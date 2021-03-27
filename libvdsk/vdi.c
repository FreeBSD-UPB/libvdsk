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

#include "vdsk_int.h"
#include "vdi.h"

#define VDI_SIGNATURE 0xbeda107f
#define VDI_SECTOR_SIZE 512

#define VDI_BLOCK_FREE ((uint32_t) ~0)
#define VDI_BLOCK_ZERO ((uint32_t) ~1)

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

	if (pread(vdsk->fd, &header, sizeof(header), 0) != sizeof(header)) {
		printf("Can't read VDI header\n");
		return EBADF;
	}

	/* Verify VDI signature */
	if (le32toh(header.signature) != VDI_SIGNATURE) {
		printf("Disk image is not VDI compatible\n");
		return EFTYPE;
	}
	
	version_major = le16toh(header.version_major);
	version_minor = le16toh(header.version_minor);
	if (version_major != 1 || version_minor < 1) {
		printf("VDI image version %d.%d not supported\n", version_major, version_minor);
		return ENXIO;
	}

	return 0;
}

static int
vdi_open(struct vdsk *vdsk)
{
	struct vdidsk *vdidsk = vdi_deref(vdsk);
	struct vdi_header *header = &vdidsk->header;
	int ret = 0;
	uint32_t i, status;
	uuid_t uuid_link, uuid_parent;

#ifdef SMP
	pthread_rwlock_init(&vdidsk->lock, NULL);
#endif
	vdidsk->vdsk = vdsk;

	if (pread(vdsk->fd, header, sizeof(*header), 0) != sizeof(*header)) {
		printf("Can't read VDI header\n");
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
		printf("Disk image is not VDI compatible\r\n");
		ret = EBADF;
		goto open_err;
	}
	if (header->version_major != 1 || header->version_minor < 1) {
		printf("VDI image version %u.%u not supported\r\n",
			header->version_major, header->version_minor);
		ret = ENXIO;
		goto open_err;
	}
	if (header->sector_size != VDI_SECTOR_SIZE) {
		printf("Invalid VDI sector size %u different from %u\r\n", header->sector_size, VDI_SECTOR_SIZE);
		ret = EBADF;
		goto open_err;
	}
	if ((header->block_size & (header->block_size - 1)) != 0 || header->block_size < VDI_SECTOR_SIZE) {
		printf("Invalid VDI block size %u not power of 2 or lower than sector size %u\r\n",
			header->block_size, header->sector_size);
		ret = EBADF;
		goto open_err;
	}
	if ((uint64_t) header->blocks_total * header->block_size != header->disk_size) {
		printf("Invalid VDI disk size %lu different from block size * number of blocks %lu\r\n",
			header->disk_size, (uint64_t) header->blocks_total * header->block_size);
		ret = EBADF;
		goto open_err;
	}
	if ((header->block_size & (header->block_size - 1)) != 0 || header->block_size < VDI_SECTOR_SIZE) {
		printf("Invalid VDI block size %u not power of 2 or lower than sector size %u\r\n",
			header->block_size, header->sector_size);
		ret = EBADF;
		goto open_err;
	}
	/* TODO: support snapshots */
	if (!uuid_is_nil(&uuid_link, &status) || !uuid_is_nil(&uuid_parent, &status)) {
		printf("Unsupported VDI image snapshot\r\n");
		ret = ENXIO;
		goto open_err;
	}
	
	vdidsk->offset_block_array = header->offset_block_array;
	vdidsk->offset_data = header->offset_data;
	vdidsk->block_size = header->block_size;
	vdidsk->blocks_total = header->blocks_total;
	
	vdidsk->block_array = calloc(vdidsk->blocks_total, sizeof(uint32_t));
	if (!vdidsk->block_array) {
		printf("Calloc failed for VDI block array\r\n");
		ret = ENOMEM;
		goto open_err;
	}
	if (pread(vdsk->fd, (char *) vdidsk->block_array, vdidsk->blocks_total * sizeof(uint32_t),
			vdidsk->offset_block_array) != vdidsk->blocks_total * sizeof(uint32_t)) {
		printf("Unable to read VDI block array\r\n");
		printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
		free(vdidsk->block_array);
		goto open_err;
	}
	for (i = 0; i < vdidsk->blocks_total; i++) {
		vdidsk->block_array[i] = le32toh(vdidsk->block_array[i]);
	}
	
	return ret;
	
open_err:
	DPRINTF("Exit open_err\r\n");
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
vdi_readv(struct vdsk *vdsk, const struct iovec *iov,
    int iovcnt, off_t offset)
{
	struct vdidsk *vdidsk = vdi_deref(vdsk);
	size_t rem, bytes_to_read, bytes_remaining, iov_offset;
	ssize_t bytes_read;
	uint32_t block_index, iov_index, block_offset;
	int i;

	iov_index = 0;
	iov_offset = 0;
	rem = 0;

#ifdef SMP
	pthread_rwlock_rdlock(&vdidsk->lock);
#endif
	
	for (i = 0; i < iovcnt; i++)
		rem += iov[i].iov_len;
	DPRINTF("=================================\r\n");
	DPRINTF("TRYING TO %s\r\n", __func__);
	DPRINTF("iovcnt %d\r\n", iovcnt);
	DPRINTF("sum %ld\r\n", rem);
	DPRINTF("offset %ld\r\n", offset);
	DPRINTF("----\r\n");
	DPRINTF("capacity: %lu\r\n", vdsk->media_size);
	DPRINTF("sector_size: %d\r\n", vdsk->sector_size);
	DPRINTF("block_size: %u\r\n", vdidsk->block_size);
	DPRINTF("blocks_total: %u\r\n", vdidsk->blocks_total);
	DPRINTF("blocks_allocated: %u\r\n", vdidsk->header.blocks_allocated);
	DPRINTF("=================================\r\n");

	if (offset < 0) {
		errno = EINVAL;
		printf("Exit with offset < 0; offset = %ld\r\n", offset);
		
#ifdef SMP
		pthread_rwlock_unlock(&vdidsk->lock);
#endif
		
		return -1;
	}
	
	while (rem > 0) {
		block_index = offset / vdidsk->block_size;
		block_offset = offset % vdidsk->block_size;
		bytes_to_read = MIN((size_t) vdidsk->block_size - block_offset, rem);
		
		bytes_remaining = bytes_to_read;
		
		DPRINTF("Block index: %u value : %u\r\n", block_index, vdidsk->block_array[block_index]);
		if (vdidsk->block_array[block_index] == VDI_BLOCK_FREE) {
			/* Random data, so we can emulate writing in the iovs */
			DPRINTF("Accessed unallocated block %u\r\n", block_index);
			while (bytes_remaining > 0) {
				bytes_read = MIN(iov[iov_index].iov_len - iov_offset, bytes_remaining);
				iov_offset += bytes_read;
				if (iov_offset == iov[iov_index].iov_len) {
					iov_index++;
					iov_offset = 0;
				}
				bytes_remaining -= bytes_read;
			}
		} else if (vdidsk->block_array[block_index] == VDI_BLOCK_ZERO) {
			/* Block filled with zeros */
			DPRINTF("Accessed zero block %u\r\n", block_index);
			while (bytes_remaining > 0) {
				bytes_read = MIN(iov[iov_index].iov_len - iov_offset, bytes_remaining);
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
			DPRINTF("Accessed block %u phys offset: %#x block offset: %#x\r\n",
				block_index, vdidsk->offset_data +
				vdidsk->block_array[block_index] * vdidsk->block_size,
				block_offset);
			while (bytes_remaining > 0) {
				bytes_read = pread(vdsk->fd,
								(char *) iov[iov_index].iov_base + iov_offset,
								MIN(iov[iov_index].iov_len - iov_offset, bytes_remaining),
								vdidsk->offset_data + vdidsk->block_array[block_index] *
									vdidsk->block_size + block_offset);

				DPRINTF("%s: read %#lx iov_index %u iov_len %#lx iov_offset "
					"%#lx block_index %u bytes_to_read %#lx bytes_read_so_far %#lx\r\n",
					__func__, bytes_read, iov_index, iov[iov_index].iov_len,
					iov_offset, block_index, bytes_to_read,
					bytes_to_read - bytes_remaining);
				
				if (bytes_read == -1) {
					printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
					
#ifdef SMP
					pthread_rwlock_unlock(&vdidsk->lock);
#endif
					
					return -1;
				}
				
				iov_offset += bytes_read;
				if (iov_offset == iov[iov_index].iov_len) {
					iov_index++;
					iov_offset = 0;
				}
				block_offset += bytes_read;
				bytes_remaining -= bytes_read;
			}
		}
		rem -= bytes_to_read;
		offset += bytes_to_read;
	}
	
	DPRINTF("%s: finished rem: %#lx\r\n", __func__, rem);

#ifdef SMP
	pthread_rwlock_unlock(&vdidsk->lock);
#endif

	return rem;
}

static int is_zero_write(const struct iovec *iov, uint32_t *iov_index,
	size_t *iov_offset, size_t size)
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
			return 0;
		curr_iov_offset += bytes_to_check;
		if (curr_iov_offset == iov[curr_iov_index].iov_len) {
			curr_iov_index++;
			curr_iov_offset = 0;
		}
		size -= bytes_to_check;
	}
	*iov_offset = curr_iov_offset;
	*iov_index = curr_iov_index;
	
	return 1;
}


static ssize_t
vdi_writev(struct vdsk *vdsk, const struct iovec *iov,
    int iovcnt, off_t offset)
{
	struct vdidsk *vdidsk = vdi_deref(vdsk);
	size_t rem, bytes_to_write, bytes_remaining, iov_offset;
	ssize_t bytes_written;
	uint32_t block_index, iov_index, block_offset;
	int i, nr_allocated_blocks, starting_block_index;
	uint32_t *buf;
	ssize_t size;


	iov_index = 0;
	iov_offset = 0;
	rem = 0;
	nr_allocated_blocks = 0;
	starting_block_index = 0;

#ifdef SMP
	pthread_rwlock_wrlock(&vdidsk->lock);
#endif
	
	for (i = 0; i < iovcnt; i++)
		rem += iov[i].iov_len;
	DPRINTF("=================================\r\n");
	DPRINTF("TRYING TO %s\r\n", __func__);
	DPRINTF("iovcnt %d\r\n", iovcnt);
	DPRINTF("sum %ld\r\n", rem);
	DPRINTF("offset %ld\r\n", offset);
	DPRINTF("----\r\n");
	DPRINTF("capacity: %lu\r\n", vdsk->media_size);
	DPRINTF("sector_size: %d\r\n", vdsk->sector_size);
	DPRINTF("block_size: %u\r\n", vdidsk->block_size);
	DPRINTF("blocks_total: %u\r\n", vdidsk->blocks_total);
	DPRINTF("blocks_allocated: %u\r\n", vdidsk->header.blocks_allocated);
	DPRINTF("=================================\r\n");

	if (offset < 0) {
		errno = EINVAL;
		printf("Exit with offset < 0; offset = %ld\r\n", offset);
		
#ifdef SMP
		pthread_rwlock_unlock(&vdidsk->lock);
#endif
		
		return -1;
	}
	
	while (rem > 0) {
		block_index = offset / vdidsk->block_size;
		block_offset = offset % vdidsk->block_size;
		bytes_to_write = MIN((size_t) vdidsk->block_size - block_offset, rem);
		
		bytes_remaining = bytes_to_write;
		
		if (vdidsk->block_array[block_index] == VDI_BLOCK_FREE ||
			vdidsk->block_array[block_index] == VDI_BLOCK_ZERO) {
			/* If writing only zeros, just mark the block as a zero block */
			if (is_zero_write(iov, &iov_index, &iov_offset, bytes_to_write)) {
				DPRINTF("Zero write to unallocated or free block %u\r\n", block_index);
				DPRINTF("Marking block %u as zero block\r\n", block_index);
				vdidsk->block_array[block_index] = VDI_BLOCK_ZERO;
				rem -= bytes_to_write;
				offset += bytes_to_write;
				continue;
			} else {
			/* Writing non zero, so allocate a new block */
			if (ftruncate(vdsk->fd, vdidsk->offset_data +
					vdidsk->header.blocks_allocated * vdidsk->block_size) < 0) {
				printf("%s: failed to allocate new block\r\n", __func__);
				printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
					
#ifdef SMP
				pthread_rwlock_unlock(&vdidsk->lock);
#endif
					
				return -1;
			}
			
			vdidsk->block_array[block_index] = vdidsk->header.blocks_allocated++;
			if (starting_block_index == 0)
				starting_block_index = block_index;
			nr_allocated_blocks++;
			}
		}
		/* Normal block */
		DPRINTF("Accessed block %u phys offset: %#x block offset: %#x\r\n",
			block_index, vdidsk->offset_data +
			vdidsk->block_array[block_index] * vdidsk->block_size,
			block_offset);
		while (bytes_remaining > 0) {
			bytes_written = pwrite(vdsk->fd,
							(char *) iov[iov_index].iov_base + iov_offset,
							MIN(iov[iov_index].iov_len - iov_offset, bytes_remaining),
							vdidsk->offset_data + vdidsk->block_array[block_index] *
								vdidsk->block_size + block_offset);
			
			DPRINTF("%s: wrote %#lx iov_index %u iov_len %#lx iov_offset "
				"%#lx block_index %u bytes_to_write %#lx bytes_read_so_far %#lx\r\n",
				__func__, bytes_written, iov_index, iov[iov_index].iov_len,
				iov_offset, block_index, bytes_to_write,
				bytes_to_write - bytes_remaining);
			
			if (bytes_written == -1) {
				printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
					
#ifdef SMP
				pthread_rwlock_unlock(&vdidsk->lock);
#endif
					
				return -1;
			}
			
			iov_offset += bytes_written;
			if (iov_offset == iov[iov_index].iov_len) {
				iov_index++;
				iov_offset = 0;
			}
			block_offset += bytes_written;
			bytes_remaining -= bytes_written;
		}
		rem -= bytes_to_write;
		offset += bytes_to_write;
	}
	
	DPRINTF("%s: finished rem: %#lx\r\n", __func__, rem);

	if (nr_allocated_blocks > 0) {
		/* Update header in file and block array if we allocate any blocks */
		
		buf = calloc(nr_allocated_blocks, sizeof(*buf));
		if (!buf) {
			printf("%s: could not calloc buf\r\n", __func__);
			pthread_rwlock_unlock(&vdidsk->lock);
			return -1;
		}
		
		buf[0] = htole32(vdidsk->header.blocks_allocated);
		size = sizeof(uint32_t);
		if (pwrite(vdsk->fd, &buf[0], size,
				offsetof(struct vdi_header, blocks_allocated)) != size) {
			printf("%s: could not write block_allocated in header\r\n", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			free(buf);
			pthread_rwlock_unlock(&vdidsk->lock);
			return -1;
		}
		
		for (i = 0; i < nr_allocated_blocks; i++)
			buf[i] = htole32(vdidsk->block_array[i + starting_block_index]);
		
		size = nr_allocated_blocks * sizeof(uint32_t);
		if (pwrite(vdsk->fd, buf, size, vdidsk->offset_block_array +
				starting_block_index * sizeof(uint32_t)) != size) {
			printf("%s: could not write new blocks in block_array\r\n", __func__);
			printf("%s: (%d) %s\r\n", __func__, errno, strerror(errno));
			free(buf);
			pthread_rwlock_unlock(&vdidsk->lock);
			return -1;
		}
		
		free(buf);
	}

#ifdef SMP
	pthread_rwlock_unlock(&vdidsk->lock);
#endif

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

