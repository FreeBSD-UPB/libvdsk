/*-
  Copyright (c) 2014 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: user/marcel/libvdsk/libvdsk/vmdk.c 286996 2015-08-21 15:20:01Z marcel $");

#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vdsk_int.h"

#define VMDK4_MAGIC			0x4b444d56
#define BUFLEN_PROBE			512
#define VERSION_LEN			12
#define VMDK_COMPRESSION_DEFLATE	1
#define VMDK4_GD_AT_END			0xffffffffffffffffULL
#define L2_CACHE_SIZE			16
#define SECTOR_BITS			9
#define SECTOR_SIZE			(1ULL << SECTOR_BITS)
#define PAD_SIZE			496
#define CLUSTERS_MAX_SIZE		0x200000
#define L1_MAX_SIZE			32 * 1024 * 1024
#define VMDK_FLAG_MARKER		131072
#define VMDK_FLAG_ZERO_GRAIN		4
#define VMDK_GTE_ZEROED			0x1
#define MAX_SIZE			(1 << 20) - 1
#define VMDK_FLAG_RGD			(1 << 1)
#define L2_CACHE_SIZE			16
#define VMDK_ZEROED			-1
#define VMDK_UNALLOC			-2

#define ROUND_UP(a, b)			(((a) + (b) - 1) & -(0 ? (a) : (b)))

enum {
	MARKER_END_OF_STREAM    = 0,
	MARKER_GRAIN_TABLE      = 1,
	MARKER_GRAIN_DIRECTORY  = 2,
	MARKER_FOOTER           = 3,
};

struct vmdkhdr {
	uint32_t version;
	uint32_t flags;
	uint64_t capacity;
	uint64_t granularity;
	uint64_t desc_offset;
	uint64_t desc_size;
	/* Number of GrainTableEntries per GrainTable */
	uint32_t num_gtes_per_gt;
	uint64_t rgd_offset;
	uint64_t gd_offset;
	uint64_t number_of_sectors;
	char filler;
	char check_bytes[4];
	uint16_t compressAlgorithm;
}__attribute__((packed));

struct vmdkdsk {
	uint64_t desc_offset;
	uint8_t cid_updated;
	uint8_t cid_checked;
	uint32_t cid;
	uint32_t parent_cid;
	int num_extents;
	struct vmdkextent *extents;
	char* create_type;
#ifdef SMP
	pthread_rwlock_t lock;
#endif
};

struct vmdkextent {
	struct vdsk *file;
	uint8_t flat;
	uint8_t compressed;
	uint8_t has_marker;
	uint8_t has_zero_grain;
	uint8_t sesparse;
	uint64_t sesparse_l2_tables_offset;
	uint64_t sesparse_clusters_offset;
	int32_t entry_size;
	int version;
	int64_t sectors;
	int64_t end_sector;
	int64_t flat_start_offset;
	int64_t l1_table_offset;
	int64_t l1_backup_table_offset;
	uint32_t *l1_table;
	uint32_t *l1_backup_table;
	unsigned int l1_size;
	uint32_t l1_entry_sectors;

	unsigned int l2_size;
	void *l2_cache;
	uint32_t l2_cache_offsets[L2_CACHE_SIZE];
	uint32_t l2_cache_counts[L2_CACHE_SIZE];

	int64_t clusters_sectors;
	int64_t next_cluster_sector;
	char *type;
};

struct vmdkfooter{
	struct {
		uint64_t val;
		uint32_t size;
		uint32_t type;
		uint8_t pad[PAD_SIZE];
	} __attribute__((__packed__)) footer_marker;

	uint32_t magic_number;
	struct vmdkhdr header;
	uint8_t pad[508 - sizeof(struct vmdkhdr)];

	struct {
		uint64_t val;
		uint32_t size;
		uint32_t type;
		uint8_t pad[PAD_SIZE];
	} __attribute__((__packed__)) eos_marker;
} __attribute__((__packed__));

struct vmdkmetadata {
	unsigned int l1_index;
	unsigned int l2_index;
	unsigned int l2_offset;
	int valid;
	uint32_t *l2_cache_entry;
};

static struct vmdkdsk*
vmdk_deref(struct vdsk *vdsk)
{
	return (struct vmdkdsk*) vdsk - 1;
}

static int
vmdk_probe(struct vdsk *vdsk)
{
	uint32_t magic;
	char buffer[BUFLEN_PROBE], version[VERSION_LEN];
	int version_len = 0;
	const char *begin, *end;

	printf("Trying to %s\n", __func__);
	if (pread(vdsk->fd, &magic, sizeof(uint32_t), 0) != sizeof(uint32_t)) {
		printf("Can't read magic number\n");
		errno = EBADF;
		goto out;
	}

	magic = be32toh(magic);
	if (magic == VMDK4_MAGIC) {
		errno = 0;
		goto out;
	}
	else {
		pread(vdsk->fd, buffer, BUFLEN_PROBE, 0);
		begin = (const char*)buffer;
		end = begin + BUFLEN_PROBE;
		while (begin < end) {
			if (*begin == 'v') {
				version[version_len] = *begin;
				begin++;
				version_len++;
				while (*begin != '\n') {
					version[version_len] = *begin;
					begin++;
					version_len++;
				}
				if (*begin == '\n')
					version[version_len] = *begin;
				if (strcmp(version, "version=1\n") == 0 ||
				    strcmp(version, "version=2\n") == 0 ||
				    strcmp(version, "version=3\n") == 0 ||
				    strcmp(version, "version=1\r\n") == 0 ||
				    strcmp(version, "version=2\r\n") == 0 ||
				    strcmp(version, "version=3\r\n") == 0) {
					printf("VMDK version unsupported\n");
					errno = EFTYPE;
					goto out;
				}
			begin++;
			}
			begin++;
		}
	}

	errno = -1;

out:
	return errno;
}

static int vmdk_add_extent(struct vmdkdsk *vmdk, struct vdsk *vdsk, int flat,
		    int64_t sectors,
		    int64_t l1_offset, int64_t l1_backup_offset,
		    uint32_t l1_size, int l2_size, uint64_t cluster_sectors,
		    struct vmdkextent **new_extent)
{
	printf("Adding an extent\n");
	struct vmdkextent *extent = malloc(sizeof(struct vmdkextent));
	struct stat st;
	int64_t no_of_sectors;

	printf("Check extent allocation\n");
	if (!extent) {
		printf("Not enough space\n");
		return -ENOMEM;
	}

	if (cluster_sectors > CLUSTERS_MAX_SIZE) {
		printf("Image may be corupt\n");
		return -1;
	}
	if (l1_size > L1_MAX_SIZE) {
		printf("L1 size is too big\n");
		return -1;
	}

	if (vmdk->num_extents > 1) {
		vmdk->extents = realloc(vmdk->extents, vmdk->num_extents *
					 sizeof(struct vmdkextent));
		extent = &vmdk->extents[vmdk->num_extents - 1];
		vmdk->num_extents++;
	} else
		extent = &vmdk->extents[0];

	fstat(vdsk->fd, &st);
	no_of_sectors = st.st_size;

	if (no_of_sectors < 0)
		return no_of_sectors;

	memset(extent, 0, sizeof(struct vmdkextent));
	extent->file = vdsk;
	extent->flat = flat;
	extent->sectors = sectors;
	extent->l1_table_offset = l1_offset;
	extent->l1_backup_table_offset = l1_backup_offset;
	extent->l1_size = l1_size;
	extent->l1_entry_sectors = l2_size * cluster_sectors;
	extent->l2_size = l2_size;
	if (flat == 1)
		extent->clusters_sectors = sectors;
	else
		extent->clusters_sectors = cluster_sectors;
	extent->next_cluster_sector = ROUND_UP(no_of_sectors / SECTOR_SIZE, cluster_sectors);
	extent->entry_size = sizeof(uint32_t);

	if (vmdk->num_extents > 1)
		extent->end_sector = (*(extent - 1)).end_sector +
			extent->sectors;
	else
		extent->end_sector = extent->sectors;

	if (new_extent)
		*new_extent = extent;

	//vmdk->num_extents++;

	printf("Extent added\n");
	return 0;
}

static int init_tables(struct vdsk *vdsk, struct vmdkextent *extent)
{
	printf("Init tables\n");
	int ret;
	size_t l1_size, l2_cache_size;
	ssize_t i;

	l1_size = extent->l1_size * extent->entry_size;
	extent->l1_table = malloc(l1_size);

	if (!extent->l1_table)
		return -ENOMEM;

	ret = pread(vdsk->fd, extent->l1_table, l1_size,
		    extent->l1_table_offset);

	if (ret < 0) {
		printf("Can't read l1 table\n");
		goto fail_read_l1;
	}

	for (i = 0; i < extent->l1_size; i++)
		(*((uint32_t *)extent->l1_table + i)) =
			le64toh((*((uint32_t * )extent->l1_table + i)));

	if (extent->l1_backup_table_offset) {
		printf("Init backup table\n");
		extent->l1_backup_table = malloc(l1_size);
		if (!extent->l1_backup_table)
			return -ENOMEM;

		ret = pread(vdsk->fd, extent->l1_backup_table, l1_size,
			    extent->l1_backup_table_offset);

		if (ret < 0) {
			printf("Can't read l1 backup table\n");
			goto fail_read_backup_l1;
		}

		for (i = 0; i < extent->l1_size; i++)
			extent->l1_backup_table[i] =
				le32toh(extent->l1_backup_table[i]);
	}

	l2_cache_size = extent->entry_size * L2_CACHE_SIZE * extent->l2_size;
	extent->l2_cache = malloc(l2_cache_size);

	if (!extent->l2_cache) {
		printf("Can't alloc l2 cache\n");
		goto fail_alloc_l2;
	}

	printf("Init tables successfully\n");
	return 0;

fail_read_l1:
	free(extent->l1_table);
	return -ENOMEM;

fail_read_backup_l1:
	free(extent->l1_backup_table);
	return -ENOMEM;

fail_alloc_l2:
	free(extent->l1_table);
	free(extent->l1_backup_table);
	return -ENOMEM;
}

static void vmdk_free_last_extent(struct vmdkdsk *vmdk)
{
	if (!vmdk->num_extents)
		return;

	vmdk->num_extents--;
	vmdk->extents = realloc(vmdk->extents, vmdk->num_extents *
				 sizeof(struct vmdkextent));
}

static int
vmdk_open(struct vdsk *vdsk)
{
	struct vmdkdsk *vmdk = vmdk_deref(vdsk);
	struct vmdkhdr hdr;
	struct vmdkextent *extent;
	struct vmdkfooter footer;
	uint32_t magic;
	int ret = 0;
	int64_t l1_backup_offset, l1_entry_sectors, l1_size;

	l1_backup_offset = 0;
	l1_entry_sectors = 0;
	l1_size = 0;

	printf("Trying to %s\n", __func__);

	memset(&hdr, 0, sizeof(hdr));
	ret = pread(vdsk->fd, &hdr, sizeof(hdr), sizeof(magic));
	printf("ret = %d\n", ret);

	if (ret != sizeof(hdr)) {
		printf("Can't read header\n");
		printf("%s: (%d) %s\n\r", __func__, errno, strerror(errno));
		return (EBADF);
	}

#ifdef SMP
	pthread_rwlock_init(&vmdk->lock, NULL);
#endif

	if (hdr.capacity == 0) {
		printf("Unsuported image\n");
		return (EFTYPE);
	}

	vdsk->media_size = hdr.capacity * SECTOR_SIZE;

	if (!vmdk->create_type)
		vmdk->create_type = strdup("monolithicSparse");

	if (le64toh(hdr.gd_offset) == VMDK4_GD_AT_END) {
		ret = pread(vdsk->fd, &footer, sizeof(struct vmdkfooter),
		      vdsk->media_size - 1536);
		if (ret != sizeof(struct vmdkfooter)) {
			printf("Can't read footer\n\r");
			printf("%s: (%d) %s\n\r", __func__, errno,
			       strerror(errno));
			return (EBADF);
		}
		if (le32toh(footer.magic_number) != VMDK4_MAGIC ||
		    le32toh(footer.footer_marker.size) != 0 ||
		    le32toh(footer.footer_marker.type) != MARKER_FOOTER ||
		    le64toh(footer.eos_marker.val) != 0 ||
		    le64toh(footer.eos_marker.size) != 0 ||
		    le32toh(footer.eos_marker.type != MARKER_END_OF_STREAM)) {
			printf("Invalid footer\n\r");
			printf("%s: (%d) %s\n\r", __func__, errno,
			       strerror(errno));
			return (EBADF);
		}
		hdr = footer.header;
	}

	if (le32toh(hdr.version) > 3) {
		printf("Unsuported version %d", le32toh(hdr.version));
		goto out_err;
	}

	if (le16toh(hdr.compressAlgorithm)) {
		printf("Unsuported compressed images\n");
		goto out_err;
	}

	if (le32toh(hdr.num_gtes_per_gt) > 512) {
		printf("L2 table too big\n");
		goto out_err;
	}

	l1_entry_sectors = le32toh(hdr.num_gtes_per_gt) *
		le64toh(hdr.granularity);
	if (l1_entry_sectors == 0) {
		printf("L1 entry size is invalid\n");
		goto out_err;
	}

	l1_size = (le64toh(hdr.capacity) + l1_entry_sectors - 1) /
			l1_entry_sectors;
	if (le32toh(hdr.flags) & VMDK_FLAG_RGD)
		l1_backup_offset = le64toh(hdr.rgd_offset) << 9;

	if ((uint64_t)vdsk_sector_size(vdsk) < le64toh(hdr.number_of_sectors)) {
		printf("File truncated\n");
		return -EINVAL;
	}

	vmdk->num_extents = 1;
	vmdk->extents = malloc(vmdk->num_extents * sizeof(struct vmdkextent));

	ret = 0;
	ret = vmdk_add_extent(vmdk, vdsk,
			      0, le64toh(hdr.capacity),
			      le64toh(hdr.gd_offset) << 9,
			      l1_backup_offset, l1_size,
			      le32toh(hdr.num_gtes_per_gt),
			      le64toh(hdr.granularity),
			      &extent);
	if (ret < 0) {
		printf("Extent add failed\n");
		goto out_err;
	}

	extent->has_marker = le32toh(hdr.flags) & VMDK_FLAG_MARKER;
	extent->version = le32toh(hdr.version);
	extent->has_zero_grain = le32toh(hdr.flags) & VMDK_FLAG_ZERO_GRAIN;

	ret = init_tables(vdsk, extent);

	if (ret < 0) {
		printf("Can't init tables\n");
		vmdk_free_last_extent(vmdk);
		return ret;
	}
	DPRINTF("----\r\n");
	DPRINTF("+++> filename: %s\n", vdsk->filename);
	DPRINTF("capacity: %lu\n\r", vdsk->media_size);
	DPRINTF("sectorsize: %lu\n\r", vdsk->sector_size);
	DPRINTF("grainSize = %lu\n\r", be64toh(hdr.granularity));
	DPRINTF("rgdOffset = %lu\n\r", be64toh(hdr.rgd_offset) << 9);
	DPRINTF("gdOffset = %lu\n\r", be64toh(hdr.gd_offset) << 9);
	DPRINTF("===============================================\n\r");

	return (ret);

out_err:
	ret = -1;
	printf("Exit out err\n");
	return (ret);
}

static int
vmdk_close(struct vdsk *vdsk)
{
	printf("Trying to %s\n\r", __func__);
	int i;
	struct vmdkdsk *vmdk = vmdk_deref(vdsk);

	for (i = 0; i < vmdk->num_extents; i++) {
		free(vmdk->extents[i].l1_table);
		free(vmdk->extents[i].l2_cache);
		free(vmdk->extents[i].l1_backup_table);
		free(vmdk->extents[i].type);
	}

	free(vmdk->extents);
	return 0;
}

static struct vmdkextent* find_extent(struct vmdkdsk *vmdk, int64_t sector_no,
				     struct vmdkextent *start_extent)
{
	struct vmdkextent *extent = start_extent;
	struct vmdkextent *last_extent = &vmdk->extents[vmdk->num_extents];

	if (!extent)
		extent = &vmdk->extents[0];

	while (extent <= last_extent) {
		if (sector_no < extent->end_sector)
			return extent;
		extent++;
	}
	return NULL;
}

static uint64_t find_offset_in_cluster(struct vmdkextent *extent, uint64_t offset)
{
	uint64_t extent_begin_offset, extent_relative_offset;
	uint64_t cluster_size = extent->clusters_sectors * SECTOR_SIZE;
	uint64_t offset_in_cluster;
	extent_begin_offset =
		(extent->end_sector - extent->sectors) * SECTOR_SIZE;
	extent_relative_offset = offset - extent_begin_offset;
	offset_in_cluster = extent_relative_offset % cluster_size;

	return offset_in_cluster;
}

static uint64_t get_cluster_offset(struct vmdkextent *extent,
			      uint64_t offset,
			      struct vmdkmetadata *metadata,
			      int fd)
{
	unsigned int l1_index, l2_offset, l2_index;
	int min_index, i, j;
	uint32_t min_count;
	void *l2_table;
	int64_t ret;
	int64_t cluster_sectors;
	uint64_t begin_offset;
	unsigned int l2_size_bytes;

	l2_size_bytes = extent->l2_size * extent->entry_size;

	if (extent->flat)
		return extent->flat_start_offset;

	/* compute the value where begins the grain */
	begin_offset = (extent->end_sector - extent->sectors) * SECTOR_SIZE;

	/* the relative offset from the beginning*/
	offset -= begin_offset;
	/* compute the grain table entry */
	l1_index = (offset >> 9) / extent->l1_entry_sectors;

	if (l1_index >= extent->l1_size)
		return -1;

	l2_offset = ((uint32_t *)extent->l1_table)[l1_index];
	if (!l2_offset)
		return -1;

	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (l2_offset == extent->l2_cache_offsets[i]) {
			//++extent
			if (extent->l2_cache_counts[i] == 0xffffffff) {
				for (j = 0; j < L2_CACHE_SIZE; j++)
					extent->l2_cache_counts[j] >>= 1;
			}
			l2_table = (char *)extent->l2_cache + (i * l2_size_bytes);
			goto entry_found;
		}
	}

	min_index = 0;
	min_count = 0xffffffff;
	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (extent->l2_cache_counts[i] < min_count) {
			min_count = extent->l2_cache_counts[i];
			min_index = i;
		}
	}

	l2_table = (char *)extent->l2_cache + (min_index * l2_size_bytes);

	ret = pread(fd, l2_table, l2_size_bytes, (int64_t )l2_offset * 512);

	if (ret != l2_size_bytes)
		return -1;

	extent->l2_cache_offsets[min_index] = l2_offset;
	extent->l2_cache_counts[min_index] = 1;
entry_found:
	l2_index = ((offset >> 9) / extent->clusters_sectors) % extent->l2_size;

	cluster_sectors = le32toh(((uint32_t *)l2_table)[l2_index]);
	if (!cluster_sectors) {
		if (metadata) {
			metadata->valid = 1;
			metadata->l1_index = l1_index;
			metadata->l2_index = l2_index;
			metadata->l2_offset = l2_offset;
			metadata->l2_cache_entry = ((uint32_t *) l2_table) + l2_index;
		}
	}

	return cluster_sectors << SECTOR_BITS;
}


static ssize_t
vmdk_readv(struct vdsk *vdsk, const struct iovec *iov,
    int iovcnt, off_t offset)
{
	int i;
	struct vmdkdsk *vmdk = vmdk_deref(vdsk);
	struct vmdkextent *extent = NULL;
	uint64_t offset_in_cluster, cluster_offset;
	uint64_t to_read;
	uint64_t ioc, to_set;
	ssize_t total, rem, bytes_to_read, iov_rem, read;
	char *buf;

	iov_rem = 0;
	ioc = 0;
	read = 0;
	rem = 0;
	bytes_to_read = 0;
	read = 0;
	to_read = 0;
	offset_in_cluster = 0;
	cluster_offset = 0;

#ifdef SMP
	pthread_rwlock_rdlock(&vmdk->lock);
#endif
	DPRINTF("TRYING TO: %s\n\r", __func__);
	DPRINTF("iov->iov_len: %lu\n\r", iov->iov_len);
	DPRINTF("rem: %ld\n\r", rem);
	DPRINTF("offset: %ld\n\r", offset);
	DPRINTF("iovcnt: %d\n\r", iovcnt);
	DPRINTF("----\n\r");
	DPRINTF("capacity: %lu\n\r", vdsk->media_size);
	DPRINTF("sectorsize: %d\n\r", vdsk->sector_size);

	for (i = 0; i < iovcnt; i++)
		rem += iov[i].iov_len;

	if (offset < 0) {
		printf("Exit with offset < 0 offset = %ld\n", offset);
#ifdef SMP
		pthread_rwlock_unlock(&vmdk->lock);
#endif

		return -1;
	}

	buf = malloc(rem * sizeof(char));

	while (rem > 0) {
		extent = find_extent(vmdk, offset >> SECTOR_BITS, extent);
		if (!extent) {
			printf("Extent not found\n\r");
#ifdef SMP
		pthread_rwlock_unlock(&vmdk->lock);
#endif
			return -1;
		}

		cluster_offset = get_cluster_offset(extent, offset,
					 NULL, vdsk->fd);

		offset_in_cluster = find_offset_in_cluster(extent, offset);

		bytes_to_read = extent->clusters_sectors * SECTOR_SIZE
			- offset_in_cluster;

		total = 0;

		if (bytes_to_read > rem)
			bytes_to_read = rem;

		if (cluster_offset == 0) {
			while (total < bytes_to_read) {
				if (iov_rem) {
					if (iov_rem < bytes_to_read - total)
						to_set = iov_rem;
					else
						to_set = bytes_to_read - total;
					memset((char *)iov[ioc].iov_base +
							(iov[ioc].iov_len -
							 iov_rem), 0, to_set);
					total += to_set;
					iov_rem -= to_set;
				} else {
					iov_rem = iov[ioc].iov_len;
					if (iov_rem < bytes_to_read - total)
						to_set = iov_rem;
					else
						to_set = bytes_to_read - total;

					memset(iov[ioc].iov_base, 0, to_set);
					total += to_set;
					iov_rem -= to_set;
				}

				if (!iov_rem)
					ioc++;
			}
		} else {
			while (total < bytes_to_read) {
				if (iov_rem) {
					if (iov_rem < bytes_to_read - total)
						to_read = iov_rem;
					else
						to_read = bytes_to_read - total;

					read = pread(vdsk->fd,
							(char *)iov[ioc].iov_base +
							(iov[ioc].iov_len - iov_rem),
							to_read,
							cluster_offset +
							offset_in_cluster);
				} else {
					iov_rem = iov[ioc].iov_len;
					if (iov_rem < bytes_to_read - total)
						to_read = iov_rem;
					else
						to_read = bytes_to_read - total;
						read = pread(vdsk->fd,
							iov[ioc].iov_base,
							to_read,
							cluster_offset +
							offset_in_cluster);
				}

			DPRINTF("%s: read %lx ioc %lu bytes_to_read %lx "
				"iov_len %lx total %lx iov_rem %lx\n\r",
				__func__, read, ioc, bytes_to_read,
				iov[ioc].iov_len, total, iov_rem);

				if (read == -1) {
					printf("%s: (%d) %s\r\n", __func__, errno,
				       strerror(errno));
#ifdef SMP
					pthread_rwlock_unlock(&vmdk->lock);
#endif
					return -1;
				}

				iov_rem -= read;
				cluster_offset += read;
				total += read;
				if (!iov_rem)
					ioc++;
			}
		}

		offset += bytes_to_read;
		rem -= bytes_to_read;
	}
	DPRINTF("%s: finished rem: %lx\n\r", __func__, rem);

#ifdef SMP
	pthread_rwlock_unlock(&vmdk->lock);
#endif
	return rem;
}

static uint64_t mkcluster(struct vmdkextent *extent,
		struct vmdkmetadata *mdata, int fd,
		uint64_t skip_start_bytes, uint64_t skip_end_bytes)
{
	uint32_t offset, off;
	uint64_t cluster_offset = 0, length;
	uint64_t cluster_sectors = extent->next_cluster_sector;
	uint64_t cluster_bytes = extent->clusters_sectors << SECTOR_BITS;
	uint8_t *whole_grain = NULL;
	int64_t l1_index;
	int bytes_written;

	extent->next_cluster_sector += extent->clusters_sectors;

	length = (cluster_sectors + extent->clusters_sectors) * SECTOR_SIZE;

	if (ftruncate(fd, length) < 0) {
		printf("ftruncate failed\n");
		return -1;
	}

	whole_grain = malloc(cluster_bytes * sizeof(uint8_t));

	if (!whole_grain)
		return -ENOMEM;

	if (skip_start_bytes > 0) {
		memset(whole_grain, 0, skip_start_bytes);
		bytes_written = pwrite(fd, whole_grain, cluster_offset,
				skip_start_bytes);
		if (bytes_written < 0) {
			cluster_offset = bytes_written;
			goto out;
		}
	}
	if (skip_end_bytes < cluster_bytes) {
		memset(whole_grain + skip_end_bytes, 0,
				cluster_bytes - skip_end_bytes);
		bytes_written = pwrite(fd, whole_grain + skip_end_bytes,
				cluster_offset, cluster_bytes - skip_end_bytes);
		if (bytes_written < 0) {
			cluster_offset = bytes_written;
			goto out;
		}
	}

	offset = le32toh(cluster_sectors);
	off = ((int64_t)mdata->l2_offset * SECTOR_SIZE) +
		(mdata->l2_index * sizeof(offset));
	bytes_written = pwrite(fd, &offset, sizeof(offset), off);
	if (bytes_written < 0) {
		cluster_offset = bytes_written;
		goto out;
	}

	if (extent->l1_backup_table_offset != 0) {
		l1_index = mdata->l1_index;
		mdata->l2_offset = extent->l1_backup_table[l1_index];
		off = ((int64_t)mdata->l2_offset * SECTOR_SIZE) +
			(mdata->l2_index * sizeof(offset));
		bytes_written = pwrite(fd, &offset, sizeof(offset), off);
		if (bytes_written < 0) {
			printf("Write L2 backup failed\n");
			cluster_offset = bytes_written;
			goto out;
		}
	}

	if (mdata->l2_cache_entry)
		*mdata->l2_cache_entry = offset;

	cluster_offset = cluster_sectors << SECTOR_BITS;
out:
	free(whole_grain);
	return cluster_offset;
}

static ssize_t
vmdk_writev(struct vdsk *vdsk, const struct iovec *iov,
    int iovcnt, off_t offset)
{
	struct vmdkdsk *vmdk = vmdk_deref(vdsk);
	struct vmdkextent *extent = NULL;
	struct vmdkmetadata mdata;
	int ret, i;
	int64_t offset_in_cluster;
	uint64_t cluster_offset, write_end_sector;
	uint64_t skip_start_bytes, skip_end_bytes;
	ssize_t total, rem, bytes_to_write, iov_rem, ioc, wrote, to_write;

	total = 0;
	rem = 0;
	bytes_to_write = 0;
	iov_rem = 0;
	ioc = 0;
	to_write = 0;
	wrote = 0;
	write_end_sector = 0;

#ifdef SMP
	pthread_rwlock_wrlock(&vmdk->lock);
#endif

	for (i = 0; i < iovcnt; i++)
		rem += iov[i].iov_len;

	while(rem > 0) {
		total = 0;
		extent = find_extent(vmdk, offset >> SECTOR_BITS, extent);

		if (!extent) {
			printf("Extent not found\n");
#ifdef SMP
			pthread_rwlock_unlock(&vmdk->lock);
#endif
			return -EIO;
		}

		offset_in_cluster = find_offset_in_cluster(extent, offset);
		bytes_to_write = extent->clusters_sectors * SECTOR_SIZE -
			offset_in_cluster;

		if (bytes_to_write > rem)
			bytes_to_write = rem;

		cluster_offset = get_cluster_offset(extent, offset,
				&mdata, vdsk->fd);
		if (cluster_offset < 0) {
			printf("Get cluster offset failed\n");
#ifdef SMP
			pthread_rwlock_unlock(&vmdk->lock);
#endif
			return cluster_offset;
		}

		if (cluster_offset == 0) {
			skip_start_bytes = offset_in_cluster;
			skip_end_bytes = bytes_to_write + offset_in_cluster;
			cluster_offset = mkcluster(extent, &mdata,
					vdsk->fd,
					skip_start_bytes, skip_end_bytes);
			if (cluster_offset < 0) {
				printf("Can not allocate cluster\n");
#ifdef SMP
				pthread_rwlock_unlock(&vmdk->lock);
#endif
				return cluster_offset;
			}
		}

		while (total < bytes_to_write) {
			if (iov_rem) {
				if (iov_rem < bytes_to_write - total)
					to_write = iov_rem;
				else
					to_write = bytes_to_write - total;
				ret = pwrite(vdsk->fd, (char *)iov[ioc].iov_base +
						(iov[ioc].iov_len - iov_rem),
						to_write,
						cluster_offset +
						offset_in_cluster);
				if (ret < 0) {
					printf("Write data failed %d %s\n", errno,
						strerror(errno));
#ifdef SMP
					pthread_rwlock_unlock(&vmdk->lock);
#endif
					return ret;
				}
			} else {
				iov_rem = iov[ioc].iov_len;
				if (iov_rem < bytes_to_write - total)
					to_write = iov_rem;
				else
					to_write = bytes_to_write - total;
				ret = pwrite(vdsk->fd, iov[ioc].iov_base,
						to_write,
						cluster_offset +
						offset_in_cluster);
					if (ret < 0) {
						printf("Write data failed %d %s\n",
								errno,
								strerror(errno));
#ifdef SMP
						pthread_rwlock_unlock(&vmdk->lock);
#endif
						return ret;
					}
			}
			iov_rem -= ret;
			cluster_offset += ret;
			total += ret;

			if (!iov_rem)
				ioc++;
		}
		rem -= bytes_to_write;
		offset += bytes_to_write;
	}
#ifdef SMP
	pthread_rwlock_unlock(&vmdk->lock);
#endif
	return rem;
}
static int
vmdk_trim(struct vdsk *vdsk, off_t offset __unused,
    size_t length __unused)
{
	struct vmdkdsk *vmdk = vmdk_deref(vdsk);
	int i;

	for (i = 0; i < vmdk->num_extents; i++)
		if (vdsk_is_dev(vmdk->extents[i].file))
			return -1;

	return 0;
}

static int
vmdk_flush(struct vdsk *vdsk)
{
	struct vmdkdsk *vmdk = vmdk_deref(vdsk);
	int i;
	for (i = 0; i < vmdk->num_extents; i++)
		if(vmdk->extents[i].file) {
			if (fsync(vmdk->extents[i].file->fd) == -1) {
				printf("Flush failed\n");
				return -1;
			}
		}
	return 0;
}

static struct vdsk_format vmdk_format = {
	.name = "vmdk",
	.description = "Virtual Machine Disk",
	.flags = VDSKFMT_CAN_WRITE | VDSKFMT_HAS_HEADER,
	.struct_size = sizeof(struct vmdkdsk),
	.probe = vmdk_probe,
	.open = vmdk_open,
	.close = vmdk_close,
	.readv = vmdk_readv,
	.writev = vmdk_writev,
	.trim = vmdk_trim,
	.flush = vmdk_flush,
};
FORMAT_DEFINE(vmdk_format);

