/*-
 * Copyright (c) 2021 Mihai Burcea
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
 *
 */

#ifndef __VDI_H__
#define	__VDI_H__

#include <uuid.h>

#define VDI_SIGNATURE 0xbeda107f
#define VDI_SECTOR_SIZE 512

#define VDI_BLOCK_FREE ((uint32_t) ~0)
#define VDI_BLOCK_ZERO ((uint32_t) ~1)

/* VDI PREHEADER AND HEADER - VERSION 1.1 */
struct vdi_header {
	/* PREHEADER */
	char		text[64]; /* Info about image type, not used anywhere */
	uint32_t	signature; /* Should be VDI_SIGNATURE */
	uint16_t	version_major; /* Image file version */
	uint16_t	version_minor;
	
	/* HEADER */
	uint32_t	header_size; /* Size of header in bytes */
	uint32_t	image_type; /* Preallocated or dynamically growing image */
	uint32_t	image_flags; /* Unused */
	char		image_comment[256]; /* For human eyes only */
	uint32_t	offset_block_array; /* Offset for the block array from the beginning of file */
	uint32_t	offset_data; /* Offset for block data from the beginning of file */
	uint32_t	cylinders; /* Unused */
	uint32_t	heads; /* Unused */
	uint32_t	sectors; /* Unused */
	uint32_t	sector_size; /* In bytes */
	uint32_t	dummy; /* Unused */
	uint64_t	disk_size; /* In bytes */
	uint32_t	block_size; /* In bytes, should be power of 2 */
	uint32_t	block_extra_data;
	uint32_t	blocks_total; /* Total blocks */
	uint32_t	blocks_allocated; /* Allocated blocks */
	uuid_t		uuid; /* UUID of image */
	uuid_t		uuid_last_modify; /* UUID of image's last modification */
	uuid_t		uuid_link;
	uuid_t		uuid_parent;
} __packed;

struct vdidsk {
	struct vdi_header header;
	struct vdsk *vdsk;
	uint32_t 	*block_array;
	
#ifdef SMP
	pthread_rwlock_t lock;
#endif
};

#endif
