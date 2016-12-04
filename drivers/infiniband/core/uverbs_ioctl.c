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

#include <rdma/rdma_user_ioctl.h>
#include <rdma/uverbs_ioctl.h>
#include "rdma_core.h"
#include "uverbs.h"

static int uverbs_validate_attr(struct ib_device *ibdev,
				struct ib_ucontext *ucontext,
				const struct ib_uverbs_attr *uattr,
				u16 attr_id,
				const struct uverbs_attr_spec_group *attr_spec_group,
				struct uverbs_attr_array *attr_array,
				struct ib_uverbs_attr __user *uattr_ptr,
				bool w_legacy)
{
	const struct uverbs_attr_spec *spec;
	struct uverbs_attr *e;
	const struct uverbs_type *type;
	struct uverbs_obj_attr *o_attr;
	struct uverbs_attr *elements = attr_array->attrs;

	if (uattr->reserved)
		return -EINVAL;

	if (attr_id >= attr_spec_group->num_attrs) {
		if (uattr->flags & UVERBS_ATTR_F_MANDATORY)
			return -EINVAL;
		else
			return 0;
	}

	spec = &attr_spec_group->attrs[attr_id];
	e = &elements[attr_id];

	switch (spec->type) {
	case UVERBS_ATTR_TYPE_PTR_IN:
	case UVERBS_ATTR_TYPE_PTR_OUT:
		if (uattr->len < spec->len ||
		    (!(spec->flags & UVERBS_ATTR_SPEC_F_MIN_SZ) &&
		     uattr->len > spec->len))
			return -EINVAL;

		e->cmd_attr.ptr = (void * __user)uattr->ptr_idr;
		e->cmd_attr.len = uattr->len;
		break;

	case UVERBS_ATTR_TYPE_FLAG:
		e->flag_attr.flags = uattr->ptr_idr;
		if (uattr->flags & UVERBS_ATTR_F_MANDATORY &&
		    e->flag_attr.flags & ~spec->flag.mask)
			return -EINVAL;
		break;

	case UVERBS_ATTR_TYPE_IDR:
	case UVERBS_ATTR_TYPE_FD:
		if (uattr->len != 0 || (uattr->ptr_idr >> 32) || (!ucontext))
			return -EINVAL;

		o_attr = &e->obj_attr;
		type = uverbs_get_type(ibdev, spec->obj.obj_type);
		if (!type)
			return -EINVAL;
		o_attr->type = type->alloc;
		o_attr->uattr = uattr_ptr;

		if (spec->type == UVERBS_ATTR_TYPE_IDR) {
			o_attr->uobj.idr = (uint32_t)uattr->ptr_idr;
			o_attr->uobject = uverbs_get_type_from_idr(o_attr->type,
								   ucontext,
								   spec->obj.access,
								   o_attr->uobj.idr);
		} else {
			o_attr->fd.fd = (int)uattr->ptr_idr;
			o_attr->uobject = uverbs_get_type_from_fd(o_attr->type,
								  ucontext,
								  spec->obj.access,
								  o_attr->fd.fd);
		}

		if (IS_ERR(o_attr->uobject))
			return -EINVAL;

		if (spec->obj.access == UVERBS_IDR_ACCESS_NEW) {
			u64 idr = o_attr->uobject->id;

			if (!w_legacy &&
			    put_user(idr, &o_attr->uattr->ptr_idr)) {
				uverbs_rollback_object(o_attr->uobject,
						       UVERBS_IDR_ACCESS_NEW);
				return -EFAULT;
			} else {
				o_attr->uattr->ptr_idr = idr;
			}
		}

		break;
	default:
		return -EOPNOTSUPP;
	};

	set_bit(attr_id, attr_array->valid_bitmap);
	return 0;
}

static int uverbs_validate(struct ib_device *ibdev,
			   struct ib_ucontext *ucontext,
			   const struct ib_uverbs_attr *uattrs,
			   size_t num_attrs,
			   const struct uverbs_action *action,
			   struct uverbs_attr_array *attr_array,
			   struct ib_uverbs_attr __user *uattr_ptr,
			   bool w_legacy)
{
	size_t i;
	int ret;
	int n_val = 0;

	for (i = 0; i < num_attrs; i++) {
		const struct ib_uverbs_attr *uattr = &uattrs[i];
		u16 attr_id = uattr->attr_id;
		const struct uverbs_attr_spec_group *attr_spec_group;

		ret = uverbs_group_idx(&attr_id, action->num_groups);
		if (ret < 0) {
			if (uattr->flags & UVERBS_ATTR_F_MANDATORY)
				return ret;

			ret = 0;
			continue;
		}

		if (ret >= n_val)
			n_val = ret + 1;

		attr_spec_group = action->attr_groups[ret];
		ret = uverbs_validate_attr(ibdev, ucontext, uattr, attr_id,
					   attr_spec_group, &attr_array[ret],
					   uattr_ptr++, w_legacy);
		if (ret) {
			uverbs_commit_objects(attr_array, n_val,
					      action, false);
			return ret;
		}
	}

	return ret ? ret : n_val;
}

static int uverbs_handle_action(struct ib_uverbs_attr __user *uattr_ptr,
				const struct ib_uverbs_attr *uattrs,
				size_t num_attrs,
				struct ib_device *ibdev,
				struct ib_uverbs_file *ufile,
				const struct uverbs_action *handler,
				struct uverbs_attr_array *attr_array,
				bool w_legacy)
{
	int ret;
	int n_val;
	unsigned int i;

	n_val = uverbs_validate(ibdev, ufile->ucontext, uattrs, num_attrs,
				handler, attr_array, uattr_ptr,
				w_legacy);
	if (n_val <= 0)
		return n_val;

	for (i = 0; i < n_val; i++) {
		const struct uverbs_attr_spec_group *attr_spec_group =
			handler->attr_groups[i];

		if (!bitmap_subset(attr_spec_group->mandatory_attrs_bitmask,
				   attr_array[i].valid_bitmap,
				   attr_spec_group->num_attrs)) {
			ret = -EINVAL;
			goto cleanup;
		}
	}

	ret = handler->handler(ibdev, ufile, attr_array, n_val);
cleanup:
	uverbs_commit_objects(attr_array, n_val, handler, !ret);

	return ret;
}

#define UVERBS_OPTIMIZE_USING_STACK
#ifdef UVERBS_OPTIMIZE_USING_STACK
#define UVERBS_MAX_STACK_USAGE		512
#endif
long ib_uverbs_cmd_verbs(struct ib_device *ib_dev,
			 struct ib_uverbs_file *file,
			 struct ib_uverbs_ioctl_hdr *hdr,
			 void __user *buf,
			 bool w_legacy)
{
	const struct uverbs_type *type;
	const struct uverbs_action *action;
	long err = 0;
	unsigned int i;
	struct {
		struct ib_uverbs_attr		*uattrs;
		struct uverbs_attr_array	*uverbs_attr_array;
	} *ctx = NULL;
	struct uverbs_attr *curr_attr;
	unsigned long *curr_bitmap;
	size_t ctx_size;
#ifdef UVERBS_OPTIMIZE_USING_STACK
	uintptr_t data[UVERBS_MAX_STACK_USAGE / sizeof(uintptr_t)];
#endif

	if (ib_dev->driver_id != hdr->driver_id)
		return -EINVAL;

	type = uverbs_get_type(ib_dev, hdr->object_type);
	if (!type)
		return -EOPNOTSUPP;

	action = uverbs_get_action(type, hdr->action);
	if (!action)
		return -EOPNOTSUPP;

	if ((action->flags & UVERBS_ACTION_FLAG_CREATE_ROOT) ^ !file->ucontext)
		return -EINVAL;

	ctx_size = sizeof(*ctx->uattrs) * hdr->num_attrs +
		   sizeof(*ctx->uverbs_attr_array->attrs) * action->num_child_attrs +
		   sizeof(struct uverbs_attr_array) * action->num_groups +
		   sizeof(*ctx->uverbs_attr_array->valid_bitmap) *
			(action->num_child_attrs / BITS_PER_LONG +
			 action->num_groups) +
		   sizeof(*ctx);

#ifdef UVERBS_OPTIMIZE_USING_STACK
	if (ctx_size <= UVERBS_MAX_STACK_USAGE) {
		memset(data, 0, ctx_size);
		ctx = (void *)data;
	}
	if (!ctx)
#endif
	ctx = kzalloc(ctx_size, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->uverbs_attr_array = (void *)ctx + sizeof(*ctx);
	ctx->uattrs = (void *)(ctx->uverbs_attr_array +
			       action->num_groups);
	curr_attr = (void *)(ctx->uattrs + hdr->num_attrs);
	curr_bitmap = (void *)(curr_attr + action->num_child_attrs);

	for (i = 0; i < action->num_groups; i++) {
		unsigned int curr_num_attrs = action->attr_groups[i]->num_attrs;

		ctx->uverbs_attr_array[i].attrs = curr_attr;
		curr_attr += curr_num_attrs;
		ctx->uverbs_attr_array[i].num_attrs = curr_num_attrs;
		ctx->uverbs_attr_array[i].valid_bitmap = curr_bitmap;
		curr_bitmap += BITS_TO_LONGS(curr_num_attrs);
	}

	if (w_legacy) {
		memcpy(ctx->uattrs, buf,
		       sizeof(*ctx->uattrs) * hdr->num_attrs);
	} else {
		err = copy_from_user(ctx->uattrs, buf,
				     sizeof(*ctx->uattrs) * hdr->num_attrs);
		if (err) {
			err = -EFAULT;
			goto out;
		}
	}

	err = uverbs_handle_action(buf, ctx->uattrs, hdr->num_attrs, ib_dev,
				   file, action, ctx->uverbs_attr_array,
				   w_legacy);
out:
#ifdef UVERBS_OPTIMIZE_USING_STACK
	if (ctx_size > UVERBS_MAX_STACK_USAGE)
#endif
	kfree(ctx);
	return err;
}

#define IB_UVERBS_MAX_CMD_SZ 4096

long ib_uverbs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ib_uverbs_file *file = filp->private_data;
	struct ib_uverbs_ioctl_hdr __user *user_hdr =
		(struct ib_uverbs_ioctl_hdr __user *)arg;
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_device *ib_dev;
	int srcu_key;
	long err;

	srcu_key = srcu_read_lock(&file->device->disassociate_srcu);
	ib_dev = srcu_dereference(file->device->ib_dev,
				  &file->device->disassociate_srcu);
	if (!ib_dev) {
		err = -EIO;
		goto out;
	}

	if (cmd == RDMA_DIRECT_IOCTL) {
		/* TODO? */
		err = -ENOSYS;
		goto out;
	} else {
		if (cmd != RDMA_VERBS_IOCTL) {
			err = -ENOIOCTLCMD;
			goto out;
		}

		err = copy_from_user(&hdr, user_hdr, sizeof(hdr));

		if (err || hdr.length > IB_UVERBS_MAX_CMD_SZ ||
		    hdr.length <= sizeof(hdr) ||
		    hdr.length != sizeof(hdr) + hdr.num_attrs * sizeof(struct ib_uverbs_attr)) {
			err = -EINVAL;
			goto out;
		}

		/* currently there are no flags supported */
		if (hdr.flags) {
			err = -EOPNOTSUPP;
			goto out;
		}

		err = ib_uverbs_cmd_verbs(ib_dev, file, &hdr,
					  (__user void *)arg + sizeof(hdr),
					  false);
	}
out:
	srcu_read_unlock(&file->device->disassociate_srcu, srcu_key);

	return err;
}
