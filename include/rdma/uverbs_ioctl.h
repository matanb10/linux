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
#include <linux/uaccess.h>
#include <rdma/rdma_user_ioctl.h>

struct uverbs_object_type;
struct uverbs_uobject_type;

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

#define UA_FLAGS(_flags)  .flags = _flags
#define UVERBS_ATTR(_id, _len, _type, ...)				\
	[_id] = {.len = _len, .type = _type, ##__VA_ARGS__}
#define UVERBS_ATTR_PTR_IN_SZ(_id, _len, ...)				\
	UVERBS_ATTR(_id, _len, UVERBS_ATTR_TYPE_PTR_IN, ##__VA_ARGS__)
#define UVERBS_ATTR_PTR_IN(_id, _type, ...)				\
	UVERBS_ATTR_PTR_IN_SZ(_id, sizeof(_type), ##__VA_ARGS__)
#define UVERBS_ATTR_PTR_OUT_SZ(_id, _len, ...)				\
	UVERBS_ATTR(_id, _len, UVERBS_ATTR_TYPE_PTR_OUT, ##__VA_ARGS__)
#define UVERBS_ATTR_PTR_OUT(_id, _type, ...)				\
	UVERBS_ATTR_PTR_OUT_SZ(_id, sizeof(_type), ##__VA_ARGS__)
#define UVERBS_ATTR_IDR(_id, _idr_type, _access, ...)			\
	[_id] = {.type = UVERBS_ATTR_TYPE_IDR,				\
		 .obj = {.obj_type = _idr_type,				\
			 .access = _access				\
		 }, ##__VA_ARGS__ }
#define UVERBS_ATTR_FD(_id, _fd_type, _access, ...)			\
	[_id] = {.type = UVERBS_ATTR_TYPE_FD,				\
		 .obj = {.obj_type = _fd_type,				\
			 .access = _access + BUILD_BUG_ON_ZERO(		\
				_access != UVERBS_ACCESS_NEW &&		\
				_access != UVERBS_ACCESS_READ)		\
		 }, ##__VA_ARGS__ }
#define UVERBS_ATTR_FLAG(_id, _mask, ...)				\
	[_id] = {.type = UVERBS_ATTR_TYPE_FLAG,				\
		 .flag = {.mask = _mask}, ##__VA_ARGS__ }
#define _UVERBS_ATTR_SPEC_SZ(...)					\
	(sizeof((const struct uverbs_attr_spec[]){__VA_ARGS__}) /	\
	 sizeof(const struct uverbs_attr_spec))
#define UVERBS_ATTR_SPEC(...)					\
	((const struct uverbs_attr_spec_group)				\
	 {.attrs = (struct uverbs_attr_spec[]){__VA_ARGS__},		\
	  .num_attrs = _UVERBS_ATTR_SPEC_SZ(__VA_ARGS__)})
#define DECLARE_UVERBS_ATTR_SPEC(name, ...)			\
	const struct uverbs_attr_spec_group name =			\
		UVERBS_ATTR_SPEC(__VA_ARGS__)
#define _UVERBS_ATTR_ACTION_SPEC_SZ(...)				  \
	(sizeof((const struct uverbs_attr_spec_group *[]){__VA_ARGS__}) / \
	 sizeof(const struct uverbs_attr_spec_group *))
#define _UVERBS_ACTION(_handler, _flags, ...)				\
	((const struct uverbs_action) {					\
		.flags = _flags,					\
		.handler = _handler,					\
		.num_groups =	_UVERBS_ATTR_ACTION_SPEC_SZ(__VA_ARGS__),	\
		.attr_groups = (const struct uverbs_attr_spec_group *[]){__VA_ARGS__} })
#define UVERBS_ACTION(_handler, ...)			\
	_UVERBS_ACTION(_handler, 0, __VA_ARGS__)
#define UVERBS_CTX_ACTION(_handler, ...)			\
	_UVERBS_ACTION(_handler, UVERBS_ACTION_FLAG_CREATE_ROOT, __VA_ARGS__)
#define _UVERBS_ACTIONS_SZ(...)					\
	(sizeof((const struct uverbs_action *[]){__VA_ARGS__}) /	\
	 sizeof(const struct uverbs_action *))
#define ADD_UVERBS_ACTION(action_idx, _handler,  ...)		\
	[action_idx] = &UVERBS_ACTION(_handler, __VA_ARGS__)
#define DECLARE_UVERBS_ACTION(name, _handler, ...)		\
	const struct uverbs_action name =				\
		UVERBS_ACTION(_handler, __VA_ARGS__)
#define ADD_UVERBS_CTX_ACTION(action_idx, _handler,  ...)	\
	[action_idx] = &UVERBS_CTX_ACTION(_handler, __VA_ARGS__)
#define DECLARE_UVERBS_CTX_ACTION(name, _handler, ...)	\
	const struct uverbs_action name =				\
		UVERBS_CTX_ACTION(_handler, __VA_ARGS__)
#define ADD_UVERBS_ACTION_PTR(idx, ptr)					\
	[idx] = ptr
#define UVERBS_ACTIONS(...)						\
	((const struct uverbs_action_group)			\
	  {.num_actions = _UVERBS_ACTIONS_SZ(__VA_ARGS__),		\
	   .actions = (const struct uverbs_action *[]){__VA_ARGS__} })
#define DECLARE_UVERBS_ACTIONS(name, ...)				\
	const struct  uverbs_type_actions_group name =			\
		UVERBS_ACTIONS(__VA_ARGS__)
#define _UVERBS_ACTIONS_GROUP_SZ(...)					\
	(sizeof((const struct uverbs_action_group*[]){__VA_ARGS__}) / \
	 sizeof(const struct uverbs_action_group *))
#define UVERBS_BUILD_BUG_ON(cond) (sizeof(char[1 - 2 * !!(cond)]) -	\
				   sizeof(char))
#define UVERBS_TYPE_ALLOC_FD(_order, _obj_size, _free_fn, _fops, _name, _flags)\
	((const struct uverbs_type_alloc_action)			\
	 {.type = UVERBS_ATTR_TYPE_FD,					\
	 .order = _order,						\
	 .obj_size = (_obj_size) +					\
		UVERBS_BUILD_BUG_ON((_obj_size) < sizeof(struct ib_uobject)), \
	 .free_fn = _free_fn,						\
	 .fd = {.fops = _fops,						\
		.name = _name,						\
		.flags = _flags} })
#define UVERBS_TYPE_ALLOC_IDR_SZ(_size, _order, _free_fn)		\
	((const struct uverbs_type_alloc_action)			\
	 {.type = UVERBS_ATTR_TYPE_IDR,					\
	 .order = _order,						\
	 .free_fn = _free_fn,						\
	 .obj_size = (_size) +						\
		UVERBS_BUILD_BUG_ON((_size) < sizeof(struct ib_uobject)),})
#define UVERBS_TYPE_ALLOC_IDR(_order, _free_fn)				\
	 UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uobject), _order, _free_fn)
#define DECLARE_UVERBS_TYPE(name, _alloc, ...)				\
	const struct uverbs_type name = {				\
		.alloc = _alloc,					\
		.num_groups = _UVERBS_ACTIONS_GROUP_SZ(__VA_ARGS__),	\
		.action_groups = (const struct uverbs_action_group *[]){__VA_ARGS__} \
	}
#define _UVERBS_TYPE_SZ(...)						\
	(sizeof((const struct uverbs_type *[]){__VA_ARGS__}) /	\
	 sizeof(const struct uverbs_type *))
#define ADD_UVERBS_TYPE_ACTIONS(type_idx, ...)				\
	[type_idx] = &UVERBS_ACTIONS(__VA_ARGS__)
#define ADD_UVERBS_TYPE(type_idx, type_ptr)				\
	[type_idx] = ((const struct uverbs_type * const)&(type_ptr))
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

/* TODO: Add debug version for these macros/inline func */
static inline int uverbs_copy_to(struct uverbs_attr_array *attr_array,
				 size_t idx, const void *from)
{
	if (!uverbs_is_valid(attr_array, idx))
		return -ENOENT;

	return copy_to_user(attr_array->attrs[idx].ptr_attr.ptr, from,
			    attr_array->attrs[idx].ptr_attr.len) ? -EFAULT : 0;
}

#define uverbs_copy_from(to, attr_array, idx)				\
	(uverbs_is_valid((attr_array), idx) ?				\
	 (sizeof(*to) <= sizeof(((struct ib_uverbs_attr *)0)->data) ?\
	  (memcpy(to, &(attr_array)->attrs[idx].ptr_attr.ptr,		\
		 (attr_array)->attrs[idx].ptr_attr.len), 0) :		\
	  (copy_from_user((to), (attr_array)->attrs[idx].ptr_attr.ptr,	\
			 (attr_array)->attrs[idx].ptr_attr.len) ?	\
	   -EFAULT : 0)) : -ENOENT)
#define uverbs_get_attr(to, attr_array, idx)				\
	(uverbs_is_valid((attr_array), idx) ?				\
	 (sizeof(to) <= sizeof(((struct ib_uverbs_attr *)0)->data) ? \
	  (sizeof(to) == sizeof((&(to))[0]) ?				\
	   ((to) = *(typeof(to) *)&(attr_array)->attrs[idx].ptr_attr.ptr, 0) :\
	   (memcpy(&(to), &(attr_array)->attrs[idx].ptr_attr.ptr,	\
		 (attr_array)->attrs[idx].ptr_attr.len), 0)) :		\
	  (copy_from_user(&(to), (attr_array)->attrs[idx].ptr_attr.ptr,	\
			 (attr_array)->attrs[idx].ptr_attr.len) ?	\
	   -EFAULT : 0)) : -ENOENT)

/* =================================================
 *              Types infrastructure
 * =================================================
 */

struct uverbs_root_spec {
	const struct uverbs_type_group	*types;
	u8				group_id;
};

struct uverbs_root *uverbs_alloc_spec_tree(unsigned int num_trees,
					   const struct uverbs_root_spec *trees);
void uverbs_specs_free(struct uverbs_root *root);

#endif
