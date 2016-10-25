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

struct uverbs_object_type;
struct ib_ucontext;
struct ib_uobject;
struct ib_device;
struct uverbs_uobject_type;

/*
 * =======================================
 *	Verbs action specifications
 * =======================================
 */

enum uverbs_attr_type {
	UVERBS_ATTR_TYPE_PTR_IN,
	UVERBS_ATTR_TYPE_PTR_OUT,
	UVERBS_ATTR_TYPE_IDR,
	UVERBS_ATTR_TYPE_FD,
};

enum uverbs_idr_access {
	UVERBS_IDR_ACCESS_READ,
	UVERBS_IDR_ACCESS_WRITE,
	UVERBS_IDR_ACCESS_NEW,
	UVERBS_IDR_ACCESS_DESTROY
};

struct uverbs_attr_spec {
	u16				len;
	enum uverbs_attr_type		type;
	struct {
		u16			obj_type;
		u8			access;
	} obj;
};

struct uverbs_attr_group_spec {
	struct uverbs_attr_spec		*attrs;
	size_t				num_attrs;
};

struct uverbs_action_spec {
	const struct uverbs_attr_group_spec		**attr_groups;
	/* if > 0 -> validator, otherwise, error */
	int (*dist)(__u16 *attr_id, void *priv);
	void						*priv;
	size_t						num_groups;
};

struct uverbs_attr_array;
struct ib_uverbs_file;

struct uverbs_action {
	struct uverbs_action_spec spec;
	void *priv;
	int (*handler)(struct ib_device *ib_dev, struct ib_uverbs_file *ufile,
		       struct uverbs_attr_array *ctx, size_t num, void *priv);
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

struct uverbs_type_actions_group {
	size_t					num_actions;
	const struct uverbs_action		**actions;
};

struct uverbs_type {
	size_t					num_groups;
	const struct uverbs_type_actions_group	**action_groups;
	const struct uverbs_type_alloc_action	*alloc;
	int (*dist)(__u16 *action_id, void *priv);
	void					*priv;
};

struct uverbs_types {
	size_t					num_types;
	const struct uverbs_type		**types;
};

struct uverbs_types_group {
	const struct uverbs_types		**type_groups;
	size_t					num_groups;
	int (*dist)(__u16 *type_id, void *priv);
	void					*priv;
};

/* =================================================
 *              Parsing infrastructure
 * =================================================
 */

struct uverbs_ptr_attr {
	void	* __user ptr;
	__u16		len;
};

struct uverbs_fd_attr {
	int		fd;
};

struct uverbs_uobj_attr {
	/*  idr handle */
	__u32	idr;
};

struct uverbs_obj_attr {
	/* pointer to the kernel descriptor -> type, access, etc */
	const struct uverbs_attr_spec *val;
	struct ib_uverbs_attr __user	*uattr;
	const struct uverbs_type_alloc_action	*type;
	struct ib_uobject		*uobject;
	union {
		struct uverbs_fd_attr		fd;
		struct uverbs_uobj_attr		uobj;
	};
};

struct uverbs_attr {
	bool valid;
	union {
		struct uverbs_ptr_attr	cmd_attr;
		struct uverbs_obj_attr	obj_attr;
	};
};

/* output of one validator */
struct uverbs_attr_array {
	size_t num_attrs;
	/* arrays of attrubytes, index is the id i.e SEND_CQ */
	struct uverbs_attr *attrs;
};

/* =================================================
 *              Types infrastructure
 * =================================================
 */

int ib_uverbs_uobject_type_add(struct list_head	*head,
			       void (*free)(struct uverbs_uobject_type *type,
					    struct ib_uobject *uobject,
					    struct ib_ucontext *ucontext),
			       uint16_t	obj_type);
void ib_uverbs_uobject_types_remove(struct ib_device *ib_dev);

#endif
