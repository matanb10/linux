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

struct uverbs_obj_fd_type {
	struct uverbs_obj_type  type;
	size_t			obj_size;
	void (*hot_unplug)(struct ib_uobject *uobj);
	const struct file_operations	*fops;
	const char			*name;
	int				flags;
};

struct uverbs_type {
	const struct uverbs_obj_type   *alloc;
};

extern struct uverbs_obj_type_ops uverbs_idr_ops;
extern struct uverbs_obj_type_ops uverbs_fd_ops;

#define UVERBS_BUILD_BUG_ON(cond) (sizeof(char[1 - 2 * !!(cond)]) -	\
				   sizeof(char))
#define UVERBS_TYPE_ALLOC_FD(_order, _obj_size, _hot_unplug, _fops, _name, _flags)\
	(((const struct uverbs_obj_fd_type)				\
	 {.type = {							\
		.destroy_order = _order,				\
		.ops = &uverbs_fd_ops,					\
	 },								\
	 .obj_size = (_obj_size) +					\
		UVERBS_BUILD_BUG_ON((_obj_size) < sizeof(struct ib_uobject)), \
	 .hot_unplug = _hot_unplug,					\
	 .fops = _fops,							\
	 .name = _name,							\
	 .flags = _flags,}).type)
#define UVERBS_TYPE_ALLOC_IDR_SZ(_size, _order, _hot_unplug)		\
	(((const struct uverbs_obj_idr_type)				\
	 {.type = {							\
		.destroy_order = _order,				\
		.ops = &uverbs_idr_ops,					\
	 },								\
	 .hot_unplug = _hot_unplug,					\
	 .obj_size = (_size) +						\
		UVERBS_BUILD_BUG_ON((_size) < sizeof(struct		\
						     ib_uobject)),}).type)
#define UVERBS_TYPE_ALLOC_IDR(_order, _hot_unplug)			\
	 UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uobject), _order,	\
				  _hot_unplug)
#endif
