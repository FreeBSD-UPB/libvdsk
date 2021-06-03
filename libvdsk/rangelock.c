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

#include "rangelock.h"

int
range_lock_root_init(struct range_lock_root *root)
{
	int ret = 0;

	LIST_INIT(&root->rd_head);
	LIST_INIT(&root->wr_head);
	ret = pthread_mutex_init(&root->lock, NULL);
	if (ret != 0)
		goto err;
	ret = pthread_cond_init(&root->update_cond, NULL);
	if (ret != 0)
		goto err_destroy_mutex;

	return ret;

err_destroy_mutex:
	pthread_mutex_destroy(&root->lock);
err:
	return ret;
}

int
range_lock_root_destroy(struct range_lock_root *root)
{
	pthread_mutex_destroy(&root->lock);
	pthread_cond_destroy(&root->update_cond);

	return 0;
}

int
range_lock_init(struct range_lock *lock, unsigned int start, unsigned int end)
{
	lock->start = start;
	lock->end = end;

	return 0;
}

static inline bool
has_range_conflict(struct range_lock *l1, struct range_lock *l2)
{
	return l1->start <= l2->end && l1->end >= l2->start;
}

static bool
add_range_to_list(struct range_lock_root *root, struct range_lock *lock, bool is_write)
{
	struct range_lock *el;

	LIST_FOREACH(el, &root->wr_head, lock_entries) {
		if (has_range_conflict(el, lock))
			return false;
	}

	if (!is_write) {
		LIST_INSERT_HEAD(&root->rd_head, lock, lock_entries);
	} else {
		LIST_FOREACH(el, &root->rd_head, lock_entries) {
			if (has_range_conflict(el, lock))
				return false;
			}
		LIST_INSERT_HEAD(&root->wr_head, lock, lock_entries);
	}

	return true;
}

static int
add_lock(struct range_lock_root *root, struct range_lock *lock, bool is_write)
{
	pthread_mutex_lock(&root->lock);
	while(!add_range_to_list(root, lock, is_write))
		pthread_cond_wait(&root->update_cond, &root->lock);
	pthread_mutex_unlock(&root->lock);

	return 0;
}

int
range_lock_rdlock(struct range_lock_root *root, struct range_lock *lock)
{
	return add_lock(root, lock, false);
}

int
range_lock_wrlock(struct range_lock_root *root, struct range_lock *lock)
{
	return add_lock(root, lock, true);
}

int range_lock_unlock(struct range_lock_root *root, struct range_lock *lock)
{
	pthread_mutex_lock(&root->lock);
	LIST_REMOVE(lock, lock_entries);
	pthread_mutex_unlock(&root->lock);

	pthread_cond_broadcast(&root->update_cond);

	return 0;
}
