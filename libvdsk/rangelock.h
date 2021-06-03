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

#ifndef __RANGELOCK_H__
#define	__RANGELOCK_H__

#include <sys/queue.h>

#include <pthread.h>
#include <stdbool.h>

struct range_lock {
	unsigned int start;
	unsigned int end;
	LIST_ENTRY(range_lock) lock_entries;
};

struct range_lock_root {
	LIST_HEAD(listhead, range_lock) rd_head, wr_head;
	pthread_mutex_t lock;
	pthread_cond_t update_cond;
};

int range_lock_root_init(struct range_lock_root *root);
int range_lock_root_destroy(struct range_lock_root *root);
int range_lock_init(struct range_lock *lock, unsigned int start, unsigned int end);
int range_lock_rdlock(struct range_lock_root *root, struct range_lock *lock);
int range_lock_wrlock(struct range_lock_root *root, struct range_lock *lock);
int range_lock_unlock(struct range_lock_root *root, struct range_lock *lock);

#endif