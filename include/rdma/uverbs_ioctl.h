/*
 * Copyright (c) 2016, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _UVERBS_IOCTL_
#define _UVERBS_IOCTL_

#include <linux/kernel.h>
#include <rdma/ib_verbs.h>

struct uverbs_obj_type;

struct uverbs_obj_type_ops {
	/*
	 * Get an ib_uobject that corresponds to the given id from ucontext,
	 * These functions could create or destroy objects if required.
	 * The action will be finalized only when commit or abort fops are
	 * called.
	 */
	struct ib_uobject *(*alloc_begin)(const struct uverbs_obj_type *type,
					  struct ib_ucontext *ucontext);
	struct ib_uobject *(*lookup_get)(const struct uverbs_obj_type *type,
					 struct ib_ucontext *ucontext, int id,
					 bool write);
	void (*alloc_commit)(struct ib_uobject *uobj);
	void (*alloc_abort)(struct ib_uobject *uobj);
	void (*lookup_put)(struct ib_uobject *uobj, bool write);
	void (*destroy_commit)(struct ib_uobject *uobj);
	void (*hot_unplug)(struct ib_uobject *uobj);
};

struct uverbs_obj_type {
	const struct uverbs_obj_type_ops * const ops;
	unsigned int destroy_order;
};

struct uverbs_obj_idr_type {
	struct uverbs_obj_type  type;
	size_t			obj_size;
	void (*hot_unplug)(struct ib_uobject *uobj);
};

struct uverbs_type {
	const struct uverbs_obj_type   *alloc;
};

#endif
