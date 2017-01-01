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

/*
 * =======================================
 *	Verbs action specifications
 * =======================================
 */

#define UVERBS_ID_RESERVED_MASK 0xF000
#define UVERBS_ID_RESERVED_SHIFT 12

enum uverbs_attr_type {
	UVERBS_ATTR_TYPE_NA,
	UVERBS_ATTR_TYPE_PTR_IN,
	UVERBS_ATTR_TYPE_PTR_OUT,
	UVERBS_ATTR_TYPE_IDR,
	UVERBS_ATTR_TYPE_FD,
	UVERBS_ATTR_TYPE_FLAG,
};

enum uverbs_idr_access {
	UVERBS_ACCESS_READ,
	UVERBS_ACCESS_WRITE,
	UVERBS_ACCESS_NEW,
	UVERBS_ACCESS_DESTROY
};

enum uverbs_attr_spec_flags {
	UVERBS_ATTR_SPEC_F_MANDATORY	= 1U << 0,
	UVERBS_ATTR_SPEC_F_MIN_SZ	= 1U << 1,
};

struct uverbs_attr_spec {
	enum uverbs_attr_type		type;
	u8				flags;
	union {
		u16				len;
		struct {
			u16			obj_type;
			u8			access;
		} obj;
		struct {
			/* flags are always 64bits */
			u64			mask;
		} flag;
	};
};

struct uverbs_attr_spec_group {
	struct uverbs_attr_spec		*attrs;
	size_t				num_attrs;
	/* populate at runtime */
	unsigned long			*mandatory_attrs_bitmask;
};

struct uverbs_attr_array;
struct ib_uverbs_file;

enum uverbs_action_flags {
	UVERBS_ACTION_FLAG_CREATE_ROOT = 1 << 0,
};

struct uverbs_action {
	const struct uverbs_attr_spec_group		**attr_groups;
	size_t						num_groups;
	u32 flags;
	int (*handler)(struct ib_device *ib_dev, struct ib_uverbs_file *ufile,
		       struct uverbs_attr_array *ctx, size_t num);
	u16 num_child_attrs;
};

struct uverbs_type_alloc_action;
typedef void (*free_type)(const struct uverbs_type_alloc_action *uobject_type,
			  struct ib_uobject *uobject);

struct uverbs_type_alloc_action {
	enum uverbs_attr_type		type;
	int				order;
	size_t				obj_size;
	free_type			free_fn;
	struct {
		const struct file_operations	*fops;
		const char			*name;
		int				flags;
	} fd;
};

struct uverbs_action_group {
	size_t					num_actions;
	const struct uverbs_action		**actions;
};

struct uverbs_type {
	size_t					num_groups;
	const struct uverbs_action_group	**action_groups;
	const struct uverbs_type_alloc_action	*alloc;
};

struct uverbs_type_group {
	size_t					num_types;
	const struct uverbs_type		**types;
};

struct uverbs_root {
	const struct uverbs_type_group		**type_groups;
	size_t					num_groups;
};

#define UVERBS_BUILD_BUG_ON(cond) (sizeof(char[1 - 2 * !!(cond)]) -	\
				   sizeof(char))
#define UVERBS_TYPE_ALLOC_FD(_order, _obj_size, _free_fn, _fops, _name, _flags)\
	((const struct uverbs_type_alloc_action)			\
	 {.type = UVERBS_ATTR_TYPE_FD,					\
	 .order = _order,						\
	 .obj_size = _obj_size +					\
		UVERBS_BUILD_BUG_ON(_obj_size < sizeof(struct ib_uobject)), \
	 .free_fn = _free_fn,						\
	 .fd = {.fops = _fops,						\
		.name = _name,						\
		.flags = _flags} })
#define UVERBS_TYPE_ALLOC_IDR_SZ(_size, _order, _free_fn)		\
	((const struct uverbs_type_alloc_action)			\
	 {.type = UVERBS_ATTR_TYPE_IDR,					\
	 .order = _order,						\
	 .free_fn = _free_fn,						\
	 .obj_size = _size +						\
		UVERBS_BUILD_BUG_ON(_size < sizeof(struct ib_uobject)),})
#define UVERBS_TYPE_ALLOC_IDR(_order, _free_fn)				\
	 UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uobject), _order, _free_fn)
#define DECLARE_UVERBS_TYPE(name, _alloc)				\
	const struct uverbs_type name = {				\
		.alloc = _alloc,					\
	}
#define _UVERBS_TYPE_SZ(...)						\
	(sizeof((const struct uverbs_type *[]){__VA_ARGS__}) /	\
	 sizeof(const struct uverbs_type *))
#define ADD_UVERBS_TYPE(type_idx, type_ptr)				\
	[type_idx] = ((const struct uverbs_type * const)&type_ptr)
#define UVERBS_TYPES(...)  ((const struct uverbs_type_group)		\
	{.num_types = _UVERBS_TYPE_SZ(__VA_ARGS__),			\
	 .types = (const struct uverbs_type *[]){__VA_ARGS__} })
#define DECLARE_UVERBS_TYPES(name, ...)				\
	const struct uverbs_type_group name = UVERBS_TYPES(__VA_ARGS__)

#define _UVERBS_TYPES_SZ(...)						\
	(sizeof((const struct uverbs_type_group *[]){__VA_ARGS__}) /	\
	 sizeof(const struct uverbs_type_group *))

#define UVERBS_TYPES_GROUP(...)						\
	((const struct uverbs_root){				\
		.type_groups = (const struct uverbs_type_group *[]){__VA_ARGS__},\
		.num_groups = _UVERBS_TYPES_SZ(__VA_ARGS__)})
#define DECLARE_UVERBS_TYPES_GROUP(name, ...)		\
	const struct uverbs_root name = UVERBS_TYPES_GROUP(__VA_ARGS__)

/* =================================================
 *              Parsing infrastructure
 * =================================================
 */

struct uverbs_ptr_attr {
	void	* __user ptr;
	u16		len;
};

struct uverbs_fd_attr {
	int		fd;
};

struct uverbs_uobj_attr {
	/*  idr handle */
	u32	idr;
};

struct uverbs_flag_attr {
	u64	flags;
};

struct uverbs_obj_attr {
	/* pointer to the kernel descriptor -> type, access, etc */
	struct ib_uverbs_attr __user	*uattr;
	const struct uverbs_type_alloc_action	*type;
	struct ib_uobject		*uobject;
	union {
		struct uverbs_fd_attr		fd;
		struct uverbs_uobj_attr		uobj;
	};
};

struct uverbs_attr {
	union {
		struct uverbs_ptr_attr	ptr_attr;
		struct uverbs_obj_attr	obj_attr;
		struct uverbs_flag_attr flag_attr;
	};
};

/* output of one validator */
struct uverbs_attr_array {
	unsigned long *valid_bitmap;
	size_t num_attrs;
	/* arrays of attrubytes, index is the id i.e SEND_CQ */
	struct uverbs_attr *attrs;
};

static inline bool uverbs_is_valid(const struct uverbs_attr_array *attr_array,
				   unsigned int idx)
{
	return test_bit(idx, attr_array->valid_bitmap);
}

#endif
