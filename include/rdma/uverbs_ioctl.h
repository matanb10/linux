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

#include <rdma/uverbs_types.h>

/*
 * =======================================
 *	Verbs action specifications
 * =======================================
 */

enum uverbs_attr_type {
	UVERBS_ATTR_TYPE_NA,
	UVERBS_ATTR_TYPE_IDR,
	UVERBS_ATTR_TYPE_FD,
};

enum uverbs_idr_access {
	UVERBS_ACCESS_READ,
	UVERBS_ACCESS_WRITE,
	UVERBS_ACCESS_NEW,
	UVERBS_ACCESS_DESTROY
};

struct uverbs_attr_spec {
	enum uverbs_attr_type		type;
	union {
		u16				len;
		struct {
			u16			obj_type;
			u8			access;
		} obj;
	};
};

struct uverbs_attr_spec_group {
	struct uverbs_attr_spec		*attrs;
	size_t				num_attrs;
};

struct uverbs_action {
	const struct uverbs_attr_spec_group		**attr_groups;
	size_t						num_groups;
};

/* =================================================
 *              Parsing infrastructure
 * =================================================
 */

struct uverbs_fd_attr {
	int		fd;
};

struct uverbs_uobj_attr {
	/*  idr handle */
	u32	idr;
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
		struct uverbs_obj_attr	obj_attr;
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

