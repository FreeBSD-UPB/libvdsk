/*-
 * Copyright (c) 2014 Marcel Moolenaar
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
__FBSDID("$FreeBSD: user/marcel/libvdsk/libvdsk/vdi.c 286996 2015-08-21 15:20:01Z marcel $");

#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>

#include "vdsk_int.h"
#include "vdi.h"

#ifdef SMP
	#define lock_rdlock(lock) pthread_rwlock_rdlock(lock);
	#define lock_wrlock(lock) pthread_rwlock_wrlock(lock);
	#define lock_unlock(lock) pthread_rwlock_unlock(lock);
#else
	#define lock_rdlock(lock)
	#define lock_wrlock(lock)
	#define lock_unlock(lock)
#endif

static ssize_t
pread_all(int fd, void *buf, size_t nbytes, off_t offset)
{
	ssize_t ret = 0;
	size_t read = 0;
	
	while (read < nbytes) {
		ret = pread(fd, (char *) buf + read, nbytes - read, offset + read);
		if (ret <= 0)
			return -1;
		read += ret;
	}
	
	return read;
}

static ssize_t
pwrite_all(int fd, const void *buf, size_t nbytes, off_t offset)
{
	ssize_t ret = 0;
	size_t written = 0;
	
	while (written < nbytes) {
		ret = pwrite(fd, (const char *) buf + written, nbytes - written, offset + written);
		if (ret <= 0)
			return -1;
		written += ret;
	}
	
	return written;
}

static ssize_t
preadv_all(int fd, struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t ret = 0;
	size_t read = 0;
	int index = 0;
	
	for (;;) {
		ret = preadv(fd, iov + index, iovcnt - index, offset + read);
		DPRINTF("index %d iovcnt %d read %#lx read_total %#lx offset %#lx\r\n",
			index, iovcnt, ret, read, offset);
		if (ret <= 0)
			return -1;
		read += ret;
		while (index < iovcnt && (size_t) ret >= iov[index].iov_len) {
			ret -= iov[index].iov_len;
			index++;
		}
		if (index == iovcnt)
			return read;
		iov[index].iov_base = (char *) iov[index].iov_base + ret;
		iov[index].iov_len -= ret;
	}
}

static ssize_t
pwritev_all(int fd, struct iovec *iov, int iovcnt, off_t offset)
{
	ssize_t ret = 0;
	size_t written = 0;
	int index = 0;
	
	for (;;) {
		ret = pwritev(fd, iov + index, iovcnt - index, offset + written);
		if (ret <= 0)
			return -1;
		written += ret;
		while (index < iovcnt && (size_t) ret >= iov[index].iov_len) {
			ret -= iov[index].iov_len;
			index++;
		}
		if (index == iovcnt)
			return written;
		iov[index].iov_base = (char *) iov[index].iov_base + ret;
		iov[index].iov_len -= ret;
	}
}

static struct iovec *
clone_iov(const struct iovec *iov, int *start, size_t *start_off, size_t nbytes, int *iovcnt)
{
	struct iovec *new_iov;
	size_t count = 0;
	
	*iovcnt = 1;
	count += iov[*start].iov_len - *start_off;
	DPRINTF("CLONE: count: %#lx iovcnt: %u\r\n", count, *iovcnt);
	while (count < nbytes) {
		count += iov[*iovcnt + *start].iov_len;
		(*iovcnt)++;
		DPRINTF("CLONE: count: %#lx iovcnt: %u\r\n", count, *iovcnt);
	}
	
	
	new_iov = malloc(*iovcnt * sizeof(*new_iov));
	if (new_iov == NULL)
		return NULL;
	memcpy(new_iov, &iov[*start], *iovcnt * sizeof(*new_iov));
	
	new_iov[0].iov_base = (char *) new_iov[0].iov_base + *start_off;
	new_iov[0].iov_len -= *start_off;
	
	new_iov[*iovcnt - 1].iov_len -= (count - nbytes);
	
	/* Update starting iovec index and offset */
	*start += *iovcnt - 1;
	/* If remaining bytes are zero, go to the next iovec */
	if (count - nbytes == 0) {
		*start += 1;
		*start_off = 0;
	}
	else {
		*start_off = new_iov[*iovcnt - 1].iov_len;
	}
	
	return new_iov;
}

static struct vdidsk*
vdi_deref(struct vdsk *vdsk)
{
	return (struct vdidsk*) vdsk - 1;
}

static int
vdi_probe(struct vdsk *vdsk)
{
	struct vdi_header header;
	uint16_t version_major, version_minor;

	if (pread_all(vdsk->fd, &header, sizeof(header), 0) != sizeof(header)) {
		printf("VDI: Cannot read VDI header\n");
		return EBADF;
	}

	/* Verify VDI signature */
	if (le32toh(header.signature) != VDI_SIGNATURE) {
		printf("VDI: Disk image is not VDI compatible\n");
		return EFTYPE;
	}
	
	version_major = le16toh(header.version_major);
	version_minor = le16toh(header.version_minor);
	if (version_major != 1 || version_minor < 1) {
		printf("VDI: Image version %d.%d not supported\n", version_major, version_minor);
		return ENXIO;
	}

	return 0;
}

static int
vdi_open(struct vdsk *vdsk)
{
	struct vdidsk *vdidsk = vdi_deref(vdsk);
	struct vdi_header *header = &vdidsk->header;
	uuid_t uuid_link, uuid_parent;
	size_t nbytes;
	off_t offset;
	uint32_t i, status;
	int ret = 0;

#ifdef SMP
	pthread_rwlock_init(&vdidsk->lock, NULL);
#endif
	vdidsk->vdsk = vdsk;

	if (pread_all(vdsk->fd, header, sizeof(*header), 0) != sizeof(*header)) {
		printf("VDI: Cannot read VDI header\n");
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		return EBADF;
	}
	
	header->signature = le32toh(header->signature);
	header->version_major = le16toh(header->version_major);
	header->version_minor = le16toh(header->version_minor);
	header->header_size = le32toh(header->header_size);
	header->image_type = le32toh(header->image_type);
	header->image_flags = le32toh(header->image_flags);
	header->offset_block_array = le32toh(header->offset_block_array);
	header->offset_data = le32toh(header->offset_data);
	header->sector_size = le32toh(header->sector_size);
	header->disk_size = le64toh(header->disk_size);
	header->block_size = le32toh(header->block_size);
	header->block_extra_data = le32toh(header->block_extra_data);
	header->blocks_total = le32toh(header->blocks_total);
	header->blocks_allocated = le32toh(header->blocks_allocated);
	/* TODO: UUID conversion maybe */
	
	vdsk->media_size = header->disk_size;

	DPRINTF("----\r\n");
	DPRINTF("VDI disk version %u.%u\r\n",
		header->version_major, header->version_minor);
	DPRINTF("filename: %s\r\n", vdsk->filename);
	DPRINTF("capacity: %lu\r\n", vdsk->media_size);
	DPRINTF("sector_size: %u\r\n", header->sector_size);
	DPRINTF("image_type: %u\r\n", header->image_type);
	DPRINTF("image_flags: %x\r\n", header->image_flags);
	DPRINTF("offset_block_array: %u\r\n", header->offset_block_array);
	DPRINTF("offset_data: %u\r\n", header->offset_data);
	DPRINTF("block_size: %u\r\n", header->block_size);
	DPRINTF("block_extra_data: %u\r\n", header->block_extra_data);
	DPRINTF("blocks_total: %u\r\n", header->blocks_total);
	DPRINTF("blocks_allocated: %u\r\n", header->blocks_allocated);
	DPRINTF("----\r\n");

	uuid_link = header->uuid_link;
	uuid_parent = header->uuid_parent;

	if (header->signature != VDI_SIGNATURE) {
		printf("VDI: Disk image is not VDI compatible\r\n");
		ret = EBADF;
		goto open_err;
	}
	if (header->version_major != 1 || header->version_minor < 1) {
		printf("VDI: Image version %u.%u not supported\r\n",
			header->version_major, header->version_minor);
		ret = ENXIO;
		goto open_err;
	}
	if (header->sector_size != VDI_SECTOR_SIZE) {
		printf("VDI: Invalid sector size %u different from %u\r\n",
			header->sector_size, VDI_SECTOR_SIZE);
		ret = EBADF;
		goto open_err;
	}
	if ((header->block_size & (header->block_size - 1)) != 0 ||
			header->block_size < VDI_SECTOR_SIZE) {
		printf("VDI: Invalid block size %u not power of 2 or lower than sector size %u\r\n",
			header->block_size, header->sector_size);
		ret = EBADF;
		goto open_err;
	}
	if ((uint64_t) header->blocks_total * header->block_size != header->disk_size) {
		printf("VDI: Invalid disk size %lu different from block size * number of blocks %lu\r\n",
			header->disk_size, (uint64_t) header->blocks_total * header->block_size);
		ret = EBADF;
		goto open_err;
	}
	/* TODO: support snapshots */
	if (!uuid_is_nil(&uuid_link, &status) || !uuid_is_nil(&uuid_parent, &status)) {
		printf("VDI: Unsupported image snapshot\r\n");
		ret = ENXIO;
		goto open_err;
	}

	vdidsk->block_array = calloc(vdidsk->header.blocks_total, sizeof(uint32_t));
	if (vdidsk->block_array == NULL) {
		printf("VDI: Calloc failed for block array\r\n");
		ret = ENOMEM;
		goto open_err;
	}
	
	nbytes = vdidsk->header.blocks_total * sizeof(uint32_t);
	offset = vdidsk->header.offset_block_array;
	
	if (pread_all(vdsk->fd, (char *) vdidsk->block_array, nbytes, offset) != (ssize_t) nbytes) {
		printf("Unable to read VDI block array\r\n");
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		free(vdidsk->block_array);
		goto open_err;
	}
	for (i = 0; i < vdidsk->header.blocks_total; i++) {
		vdidsk->block_array[i] = le32toh(vdidsk->block_array[i]);
	}
	
	return ret;
	
open_err:
	DPRINTF("VDI: Exit open_err\r\n");
	return ret;
}

static int
vdi_close(struct vdsk *vdsk)
{
	struct vdidsk *vdidsk = vdi_deref(vdsk);

	free(vdidsk->block_array);

	return 0;
}

static ssize_t
vdi_readv(struct vdsk *vdsk, const struct iovec *iov, int iovcnt, off_t offset)
{
	struct vdidsk *vdidsk = vdi_deref(vdsk);
	struct iovec *block_iov;
	off_t read_off;
	ssize_t bytes_read;
	size_t rem, bytes_to_read, iov_offset;
	uint32_t block_index, block_offset, block_val;
	uint32_t offset_data, block_size;
	int i, iov_index, nr_iov;

	offset_data = vdidsk->header.offset_data;
	block_size = vdidsk->header.block_size;

	iov_index = 0;
	iov_offset = 0;
	rem = 0;

	lock_rdlock(&vdidsk->lock);
	
	DPRINTF("=================================\r\n");
	for (i = 0; i < iovcnt; i++) {
		rem += iov[i].iov_len;
		DPRINTF("IOV: %u - len: %#lx\r\n", i, iov[i].iov_len);
	}
	DPRINTF("TRYING TO %s\r\n", __func__);
	DPRINTF("iovcnt %d\r\n", iovcnt);
	DPRINTF("sum %ld\r\n", rem);
	DPRINTF("offset %ld\r\n", offset);
	DPRINTF("----\r\n");
	DPRINTF("capacity: %lu\r\n", vdsk->media_size);
	DPRINTF("sector_size: %d\r\n", vdsk->sector_size);
	DPRINTF("block_size: %u\r\n", block_size);
	DPRINTF("blocks_total: %u\r\n", vdidsk->header.blocks_total);
	DPRINTF("blocks_allocated: %u\r\n", vdidsk->header.blocks_allocated);
	DPRINTF("=================================\r\n");

	if (offset < 0) {
		errno = EINVAL;
		printf("VDI: Read with offset < 0; offset = %ld\r\n", offset);
		lock_unlock(&vdidsk->lock);	
		return -1;
	}
	
	while (rem > 0) {
		block_index = offset / block_size;
		block_offset = offset % block_size;
		bytes_to_read = MIN((size_t) block_size - block_offset, rem);
		
		block_val = vdidsk->block_array[block_index];
		
		DPRINTF("Block index: %u value : %u\r\n", block_index, block_val);
		
		if (block_val == VDI_BLOCK_FREE || block_val == VDI_BLOCK_ZERO) {
			/* Unallocated or zero block */
			size_t bytes_remaining = bytes_to_read;
			DPRINTF("Accessed %s block %u\r\n",
				block_val == VDI_BLOCK_FREE ? "unallocated" : "free", block_index);
			while (bytes_remaining > 0) {
				bytes_read = MIN(iov[iov_index].iov_len - iov_offset, bytes_remaining);
				/* Fill with zero if zero block, otherwise do nothing */
				if (block_val == VDI_BLOCK_ZERO)
					memset((char *) iov[iov_index].iov_base + iov_offset, 0, bytes_read);
				iov_offset += bytes_read;
				if (iov_offset == iov[iov_index].iov_len) {
					iov_index++;
					iov_offset = 0;
				}
				bytes_remaining -= bytes_read;
			}
		} else {
			/* Normal block */
			DPRINTF("Accessed block %u phys offset: %#lx block offset: %#x\r\n",
				block_index, (off_t) block_val * block_size + offset_data, block_offset);

			DPRINTF("%s: cloning read iovs from iov_index %u and iov_offset %#lx bytes_to_read %#lx\r\n",
					__func__, iov_index, iov_offset, bytes_to_read);

			block_iov = clone_iov(iov, &iov_index, &iov_offset, bytes_to_read, &nr_iov);
			if (block_iov == NULL) {
				printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
				lock_unlock(&vdidsk->lock);	
				return -1;
			}
			
			DPRINTF("%s: cloned %d read iovs successfully, now iov_index %u and iov_offset %#lx\r\n",
					__func__, nr_iov, iov_index, iov_offset);
			
			read_off = (off_t) block_val * block_size + offset_data + block_offset;
			bytes_read = preadv_all(vdsk->fd, block_iov, nr_iov, read_off);

			if (bytes_read == -1) {
				printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
				lock_unlock(&vdidsk->lock);	
				return -1;
			}

			DPRINTF("%s: read %#lx\r\n", __func__, bytes_read);
			
			free(block_iov);
		}
		rem -= bytes_to_read;
		offset += bytes_to_read;
	}
	
	DPRINTF("%s: finished rem: %#lx\r\n", __func__, rem);

	lock_unlock(&vdidsk->lock);	
	return rem;
}

static bool
is_zero_write(const struct iovec *iov, uint32_t *iov_index, size_t *iov_offset, size_t size)
{
	size_t curr_iov_offset = *iov_offset;
	size_t curr_iov_index = *iov_index;
	size_t bytes_to_check;
	char *buf;
	
	/* Check size bytes from these iovecs to see if it's all 0 */
	while (size > 0) {
		buf = (char *) iov[curr_iov_index].iov_base + curr_iov_offset;
		bytes_to_check = MIN(iov[curr_iov_index].iov_len - curr_iov_offset, size);
		if (buf[0] != 0 || memcmp(buf, buf + 1, bytes_to_check - 1))
			return false;
		curr_iov_offset += bytes_to_check;
		if (curr_iov_offset == iov[curr_iov_index].iov_len) {
			curr_iov_index++;
			curr_iov_offset = 0;
		}
		size -= bytes_to_check;
	}
	*iov_offset = curr_iov_offset;
	*iov_index = curr_iov_index;
	
	return true;
}


static ssize_t
vdi_writev(struct vdsk *vdsk, const struct iovec *iov, int iovcnt, off_t offset)
{
	struct vdidsk *vdidsk = vdi_deref(vdsk);
	struct iovec *block_iov;
	off_t write_off;
	ssize_t bytes_written;
	size_t rem, bytes_to_write, iov_offset, nbytes;
	uint32_t block_index, block_offset, block_val, *buf;
	uint32_t offset_data, block_size; 
	int i, iov_index, nr_iov, nr_allocated_blocks, starting_block_index;

	offset_data = vdidsk->header.offset_data;
	block_size = vdidsk->header.block_size;

	iov_index = 0;
	iov_offset = 0;
	rem = 0;
	nr_allocated_blocks = 0;
	starting_block_index = 0;

	lock_wrlock(&vdidsk->lock);
	
	DPRINTF("=================================\r\n");
	for (i = 0; i < iovcnt; i++) {
		rem += iov[i].iov_len;
		DPRINTF("IOV: %u - len: %#lx\r\n", i, iov[i].iov_len);
	}
	DPRINTF("TRYING TO %s\r\n", __func__);
	DPRINTF("iovcnt %d\r\n", iovcnt);
	DPRINTF("sum %ld\r\n", rem);
	DPRINTF("offset %ld\r\n", offset);
	DPRINTF("----\r\n");
	DPRINTF("capacity: %lu\r\n", vdsk->media_size);
	DPRINTF("sector_size: %d\r\n", vdsk->sector_size);
	DPRINTF("block_size: %u\r\n", block_size);
	DPRINTF("blocks_total: %u\r\n", vdidsk->header.blocks_total);
	DPRINTF("blocks_allocated: %u\r\n", vdidsk->header.blocks_allocated);
	DPRINTF("=================================\r\n");

	if (offset < 0) {
		errno = EINVAL;
		printf("VDI: Write with offset < 0; offset = %ld\r\n", offset);
		lock_unlock(&vdidsk->lock);
		return -1;
	}
	
	while (rem > 0) {
		block_index = offset / block_size;
		block_offset = offset % block_size;
		bytes_to_write = MIN((size_t) block_size - block_offset, rem);
		
		block_val = vdidsk->block_array[block_index];
		
		DPRINTF("Block index: %u value : %u\r\n", block_index, block_val);
		
		if (block_val == VDI_BLOCK_FREE || block_val == VDI_BLOCK_ZERO) {
			DPRINTF("Trying to write to %s block %u\r\n",
				block_val == VDI_BLOCK_FREE ? "unallocated" : "zero", block_index);
			/* If writing only zeros, just mark the block as a zero block */
			if (is_zero_write(iov, &iov_index, &iov_offset, bytes_to_write)) {
				DPRINTF("Marking block %u as zero block\r\n", block_index);
				vdidsk->block_array[block_index] = VDI_BLOCK_ZERO;
				rem -= bytes_to_write;
				offset += bytes_to_write;
				continue;
			} else {
			/* Writing non zero, so allocate a new block */
			DPRINTF("Truncating file to %lu bytes\n",
				(off_t) vdidsk->header.blocks_allocated * block_size + offset_data);

			if (ftruncate(vdsk->fd,
				(off_t) vdidsk->header.blocks_allocated * block_size + offset_data) < 0) {
				printf("%s: failed to allocate new block\r\n", __func__);
				printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
				lock_unlock(&vdidsk->lock);
				return -1;
			}
			
			block_val = vdidsk->header.blocks_allocated++;
			vdidsk->block_array[block_index] = block_val;
			if (starting_block_index == 0)
				starting_block_index = block_index;
			nr_allocated_blocks++;
			}
		}
		/* Normal block */
		DPRINTF("Accessed block %u phys offset: %#lx block offset: %#x\r\n",
				block_index, (off_t) block_val * block_size + offset_data, block_offset);

		DPRINTF("%s: cloning write iovs from iov_index %u and iov_offset %#lx bytes_to_write %#lx\r\n",
				__func__, iov_index, iov_offset, bytes_to_write);

		block_iov = clone_iov(iov, &iov_index, &iov_offset, bytes_to_write, &nr_iov);
		if (block_iov == NULL) {
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			lock_unlock(&vdidsk->lock);	
			return -1;
		}
		
		DPRINTF("%s: cloned %d write iovs successfully, now iov_index %u and iov_offset %#lx\r\n",
				__func__, nr_iov, iov_index, iov_offset);
		
		write_off = (off_t) block_val * block_size + offset_data + block_offset;
		bytes_written = pwritev_all(vdsk->fd, block_iov, nr_iov, write_off);

		if (bytes_written == -1) {
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			lock_unlock(&vdidsk->lock);	
			return -1;
		}

		DPRINTF("%s: wrote %#lx\r\n", __func__, bytes_written);
		
		free(block_iov);

		rem -= bytes_to_write;
		offset += bytes_to_write;
	}
	
	DPRINTF("%s: finished rem: %#lx\r\n", __func__, rem);

	if (nr_allocated_blocks > 0) {
		/* Update header in file and block array if we allocate any blocks */
		
		buf = malloc(nr_allocated_blocks * sizeof(*buf));
		if (buf == NULL) {
			printf("%s: could not calloc buf\r\n", __func__);
			lock_unlock(&vdidsk->lock);
			return -1;
		}
		
		buf[0] = htole32(vdidsk->header.blocks_allocated);
		nbytes = sizeof(uint32_t);
		if (pwrite_all(vdsk->fd, &buf[0], nbytes,
				offsetof(struct vdi_header, blocks_allocated)) != (ssize_t) nbytes) {
			printf("%s: could not write block_allocated in header\r\n", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			free(buf);
			lock_unlock(&vdidsk->lock);
			return -1;
		}
		
		for (i = 0; i < nr_allocated_blocks; i++)
			buf[i] = htole32(vdidsk->block_array[i + starting_block_index]);
		
		nbytes = nr_allocated_blocks * sizeof(uint32_t);
		if (pwrite_all(vdsk->fd, buf, nbytes, (size_t) vdidsk->header.offset_block_array +
				starting_block_index * sizeof(uint32_t)) != (ssize_t) nbytes) {
			printf("%s: could not write new blocks in block_array\r\n", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			free(buf);
			lock_unlock(&vdidsk->lock);
			return -1;
		}
		
		free(buf);
	}

	lock_unlock(&vdidsk->lock);

	return rem;
}

static int
vdi_trim(struct vdsk *vdsk, off_t offset __unused, size_t length __unused)
{
	int error;

	error = 0;
	if (vdsk_is_dev(vdsk)) {
		printf("%s: You should't be here\r\n", __func__);
	} else {
		DPRINTF("%s: You should be here \r\n", __func__);
	}
	return error;
}

static int
vdi_flush(struct vdsk *vdsk __unused)
{
	int error = 0;
	
	if (vdsk_is_dev(vdsk)) {
		printf("%s: You should't be here\r\n", __func__);
	} else {
		if (fsync(vdsk->fd) == -1) {
			error = errno;
			printf("%s: (%d) %s\r\n", __func__, errno,
				strerror(errno));
		}
		DPRINTF("%s: You should be here\r\n", __func__);
	}
	return error;
}

static struct vdsk_format vdi_format = {
	.name = "vdi",
	.description = "VirtualBox Disk Image, version 1.1",
	.flags = VDSKFMT_CAN_WRITE | VDSKFMT_HAS_HEADER,
	.struct_size = sizeof(struct vdidsk),
	.probe = vdi_probe,
	.open = vdi_open,
	.close = vdi_close,
	.readv = vdi_readv,
	.writev = vdi_writev,
	.trim = vdi_trim,
	.flush = vdi_flush,
};
FORMAT_DEFINE(vdi_format);

