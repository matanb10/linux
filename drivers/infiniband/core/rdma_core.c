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

#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <rdma/ib_verbs.h>
#include "uverbs.h"
#include "rdma_core.h"
#include <rdma/uverbs_ioctl.h>

int uverbs_group_idx(u16 *id, unsigned int ngroups)
{
	int ret = (*id & UVERBS_ID_RESERVED_MASK) >> UVERBS_ID_RESERVED_SHIFT;

	if (ret >= ngroups)
		return -EINVAL;

	*id &= ~UVERBS_ID_RESERVED_MASK;
	return ret;
}

const struct uverbs_type *uverbs_get_type(const struct ib_device *ibdev,
					  uint16_t type)
{
	const struct uverbs_root *groups = ibdev->specs_root;
	const struct uverbs_type_group *types;
	int ret = uverbs_group_idx(&type, groups->num_groups);

	if (ret < 0)
		return NULL;

	types = groups->type_groups[ret];

	if (type >= types->num_types)
		return NULL;

	return types->types[type];
}

const struct uverbs_action *uverbs_get_action(const struct uverbs_type *type,
					      uint16_t action)
{
	const struct uverbs_action_group *action_group;
	int ret = uverbs_group_idx(&action, type->num_groups);

	if (ret < 0)
		return NULL;

	action_group = type->action_groups[ret];
	if (action >= action_group->num_actions)
		return NULL;

	return action_group->actions[action];
}

static int uverbs_lock_object(struct ib_uobject *uobj,
			      enum uverbs_idr_access access)
{
	if (access == UVERBS_IDR_ACCESS_READ)
		return down_read_trylock(&uobj->usecnt) == 1 ? 0 : -EBUSY;

	/* lock is either WRITE or DESTROY - should be exclusive */
	return down_write_trylock(&uobj->usecnt) == 1 ? 0 : -EBUSY;
}

static struct ib_uobject *get_uobj(int id, struct ib_ucontext *context)
{
	struct ib_uobject *uobj;

	rcu_read_lock();
	uobj = idr_find(&context->device->idr, id);
	if (uobj) {
		if (uobj->context != context)
			uobj = NULL;
	}
	rcu_read_unlock();

	return uobj;
}

struct ib_ucontext_lock {
	struct kref  ref;
	/* locking the uobjects_list */
	struct mutex lock;
};

static void init_uobjects_list_lock(struct ib_ucontext_lock *lock)
{
	mutex_init(&lock->lock);
	kref_init(&lock->ref);
}

static void release_uobjects_list_lock(struct kref *ref)
{
	struct ib_ucontext_lock *lock = container_of(ref,
						     struct ib_ucontext_lock,
						     ref);

	kfree(lock);
}

static void init_uobj(struct ib_uobject *uobj, u64 user_handle,
		      struct ib_ucontext *context)
{
	init_rwsem(&uobj->usecnt);
	uobj->user_handle = user_handle;
	uobj->context     = context;
}

static int add_uobj(struct ib_uobject *uobj)
{
	int ret;

	idr_preload(GFP_KERNEL);
	spin_lock(&uobj->context->device->idr_lock);

	/* The uobject will be replaced with the actual one when we commit */
	ret = idr_alloc(&uobj->context->device->idr, NULL, 0, 0, GFP_NOWAIT);
	if (ret >= 0)
		uobj->id = ret;

	spin_unlock(&uobj->context->device->idr_lock);
	idr_preload_end();

	return ret < 0 ? ret : 0;
}

static void remove_uobj(struct ib_uobject *uobj)
{
	spin_lock(&uobj->context->device->idr_lock);
	idr_remove(&uobj->context->device->idr, uobj->id);
	spin_unlock(&uobj->context->device->idr_lock);
}

static void put_uobj(struct ib_uobject *uobj)
{
	kfree_rcu(uobj, rcu);
}

static struct ib_uobject *get_uobject_from_context(struct ib_ucontext *ucontext,
						   const struct uverbs_type_alloc_action *type,
						   u32 idr,
						   enum uverbs_idr_access access)
{
	struct ib_uobject *uobj;
	int ret;

	rcu_read_lock();
	uobj = get_uobj(idr, ucontext);
	if (!uobj)
		goto free;

	if (uobj->type != type) {
		uobj = NULL;
		goto free;
	}

	ret = uverbs_lock_object(uobj, access);
	if (ret)
		uobj = ERR_PTR(ret);
free:
	rcu_read_unlock();
	return uobj;

	return NULL;
}

static int ib_uverbs_uobject_add(struct ib_uobject *uobject,
				 const struct uverbs_type_alloc_action *uobject_type)
{
	uobject->type = uobject_type;
	return add_uobj(uobject);
}

struct ib_uobject *uverbs_get_type_from_idr(const struct uverbs_type_alloc_action *type,
					    struct ib_ucontext *ucontext,
					    enum uverbs_idr_access access,
					    uint32_t idr)
{
	struct ib_uobject *uobj;
	int ret;

	if (access == UVERBS_IDR_ACCESS_NEW) {
		uobj = kmalloc(type->obj_size, GFP_KERNEL);
		if (!uobj)
			return ERR_PTR(-ENOMEM);

		init_uobj(uobj, 0, ucontext);

		/* lock idr */
		ret = ib_uverbs_uobject_add(uobj, type);
		if (ret) {
			kfree(uobj);
			return ERR_PTR(ret);
		}

	} else {
		uobj = get_uobject_from_context(ucontext, type, idr,
						access);

		if (!uobj)
			return ERR_PTR(-ENOENT);
	}

	return uobj;
}

struct ib_uobject *uverbs_get_type_from_fd(const struct uverbs_type_alloc_action *type,
					   struct ib_ucontext *ucontext,
					   enum uverbs_idr_access access,
					   int fd)
{
	if (access == UVERBS_IDR_ACCESS_NEW) {
		int _fd;
		struct ib_uobject *uobj = NULL;
		struct file *filp;

		_fd = get_unused_fd_flags(O_CLOEXEC);
		if (_fd < 0 || WARN_ON(type->obj_size < sizeof(struct ib_uobject)))
			return ERR_PTR(_fd);

		uobj = kmalloc(type->obj_size, GFP_KERNEL);
		init_uobj(uobj, 0, ucontext);

		if (!uobj)
			return ERR_PTR(-ENOMEM);

		filp = anon_inode_getfile(type->fd.name, type->fd.fops,
					  uobj + 1, type->fd.flags);
		if (IS_ERR(filp)) {
			put_unused_fd(_fd);
			kfree(uobj);
			return (void *)filp;
		}

		uobj->type = type;
		uobj->id = _fd;
		uobj->object = filp;

		return uobj;
	} else if (access == UVERBS_IDR_ACCESS_READ) {
		struct file *f = fget(fd);
		struct ib_uobject *uobject;

		if (!f)
			return ERR_PTR(-EBADF);

		uobject = f->private_data - sizeof(struct ib_uobject);
		if (f->f_op != type->fd.fops ||
		    !uobject->context) {
			fput(f);
			return ERR_PTR(-EBADF);
		}

		/*
		 * No need to protect it with a ref count, as fget increases
		 * f_count.
		 */
		return uobject;
	} else {
		return ERR_PTR(-EOPNOTSUPP);
	}
}

static void ib_uverbs_uobject_enable(struct ib_uobject *uobject)
{
	mutex_lock(&uobject->context->uobjects_lock->lock);
	list_add(&uobject->list, &uobject->context->uobjects);
	mutex_unlock(&uobject->context->uobjects_lock->lock);
	spin_lock(&uobject->context->device->idr_lock);
	idr_replace(&uobject->context->device->idr, uobject, uobject->id);
	spin_unlock(&uobject->context->device->idr_lock);
}

static void ib_uverbs_uobject_remove(struct ib_uobject *uobject, bool lock)
{
	/*
	 * Calling remove requires exclusive access, so it's not possible
	 * another thread will use our object.
	 */
	remove_uobj(uobject);
	if (lock)
		mutex_lock(&uobject->context->uobjects_lock->lock);
	list_del(&uobject->list);
	if (lock)
		mutex_unlock(&uobject->context->uobjects_lock->lock);
	put_uobj(uobject);
}

static void uverbs_commit_idr(struct ib_uobject *uobj,
			      enum uverbs_idr_access access,
			      bool success)
{
	switch (access) {
	case UVERBS_IDR_ACCESS_READ:
		up_read(&uobj->usecnt);
		break;
	case UVERBS_IDR_ACCESS_NEW:
		if (success) {
			ib_uverbs_uobject_enable(uobj);
		} else {
			remove_uobj(uobj);
			put_uobj(uobj);
		}
		break;
	case UVERBS_IDR_ACCESS_WRITE:
		up_write(&uobj->usecnt);
		break;
	case UVERBS_IDR_ACCESS_DESTROY:
		if (success)
			ib_uverbs_uobject_remove(uobj, true);
		else
			up_write(&uobj->usecnt);
		break;
	}
}

static void uverbs_commit_fd(struct ib_uobject *uobj,
			     enum uverbs_idr_access access,
			     bool success)
{
	struct file *filp = uobj->object;

	if (access == UVERBS_IDR_ACCESS_NEW) {
		if (success) {
			kref_get(&uobj->context->ufile->ref);
			uobj->uobjects_lock = uobj->context->uobjects_lock;
			kref_get(&uobj->uobjects_lock->ref);
			ib_uverbs_uobject_enable(uobj);
			fd_install(uobj->id, uobj->object);
		} else {
			fput(uobj->object);
			put_unused_fd(uobj->id);
			kfree(uobj);
		}
	} else {
		fput(filp);
	}
}

static void _uverbs_commit_object(struct ib_uobject *uobj,
				  enum uverbs_idr_access access,
				  bool success)
{
	if (uobj->type->type == UVERBS_ATTR_TYPE_IDR)
		uverbs_commit_idr(uobj, access, success);
	else if (uobj->type->type == UVERBS_ATTR_TYPE_FD)
		uverbs_commit_fd(uobj, access, success);
	else
		WARN_ON(true);
}

void uverbs_commit_object(struct ib_uobject *uobj,
			  enum uverbs_idr_access access)
{
	return _uverbs_commit_object(uobj, access, true);
}

void uverbs_rollback_object(struct ib_uobject *uobj,
			    enum uverbs_idr_access access)
{
	return _uverbs_commit_object(uobj, access, false);
}

static void ib_uverbs_remove_fd(struct ib_uobject *uobject)
{
	/*
	 * user should release the uobject in the release
	 * callback.
	 */
	if (uobject->context) {
		list_del(&uobject->list);
		uobject->type->free_fn(uobject->type, uobject);
		kref_put(&uobject->context->ufile->ref, ib_uverbs_release_file);
		uobject->context = NULL;
	}
}

void ib_uverbs_close_fd(struct file *f)
{
	struct ib_uobject *uobject = f->private_data - sizeof(struct ib_uobject);

	mutex_lock(&uobject->uobjects_lock->lock);
	if (uobject->context) {
		list_del(&uobject->list);
		kref_put(&uobject->context->ufile->ref, ib_uverbs_release_file);
		uobject->context = NULL;
	}
	mutex_unlock(&uobject->uobjects_lock->lock);
	kref_put(&uobject->uobjects_lock->ref, release_uobjects_list_lock);
}

void ib_uverbs_cleanup_fd(void *private_data)
{
	struct ib_uboject *uobject = private_data - sizeof(struct ib_uobject);

	kfree(uobject);
}

void uverbs_commit_objects(struct uverbs_attr_array *attr_array,
			   size_t num,
			   const struct uverbs_action *action,
			   bool success)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		struct uverbs_attr_array *attr_spec_array = &attr_array[i];
		const struct uverbs_attr_spec_group *attr_spec_group =
			action->attr_groups[i];
		unsigned int j;

		for (j = 0; j < attr_spec_array->num_attrs; j++) {
			struct uverbs_attr *attr = &attr_spec_array->attrs[j];
			struct uverbs_attr_spec *spec = &attr_spec_group->attrs[j];

			if (!uverbs_is_valid(attr_spec_array, j))
				continue;

			if (spec->type == UVERBS_ATTR_TYPE_IDR ||
			    spec->type == UVERBS_ATTR_TYPE_FD)
				/*
				 * refcounts should be handled at the object
				 * level and not at the uobject level.
				 */
				_uverbs_commit_object(attr->obj_attr.uobject,
						      spec->obj.access, success);
		}
	}
}

static unsigned int get_type_orders(const struct uverbs_root *root)
{
	unsigned int i;
	unsigned int max = 0;

	for (i = 0; i < root->num_groups; i++) {
		unsigned int j;
		const struct uverbs_type_group *types = root->type_groups[i];

		for (j = 0; j < types->num_types; j++) {
			if (!types->types[j] || !types->types[j]->alloc)
				continue;
			if (types->types[j]->alloc->order > max)
				max = types->types[j]->alloc->order;
		}
	}

	return max;
}

void ib_uverbs_uobject_type_cleanup_ucontext(struct ib_ucontext *ucontext,
					     const struct uverbs_root *root)
{
	unsigned int num_orders = get_type_orders(root);
	unsigned int i;

	for (i = 0; i <= num_orders; i++) {
		struct ib_uobject *obj, *next_obj;

		/*
		 * No need to take lock here, as cleanup should be called
		 * after all commands finished executing. Newly executed
		 * commands should fail.
		 */
		mutex_lock(&ucontext->uobjects_lock->lock);
		list_for_each_entry_safe(obj, next_obj, &ucontext->uobjects,
					 list)
			if (obj->type->order == i) {
				if (obj->type->type == UVERBS_ATTR_TYPE_IDR)
					ib_uverbs_uobject_remove(obj, false);
				else
					ib_uverbs_remove_fd(obj);
			}
		mutex_unlock(&ucontext->uobjects_lock->lock);
	}
	kref_put(&ucontext->uobjects_lock->ref, release_uobjects_list_lock);
}

int ib_uverbs_uobject_type_initialize_ucontext(struct ib_ucontext *ucontext)
{
	ucontext->uobjects_lock = kmalloc(sizeof(*ucontext->uobjects_lock),
					  GFP_KERNEL);
	if (!ucontext->uobjects_lock)
		return -ENOMEM;

	init_uobjects_list_lock(ucontext->uobjects_lock);
	INIT_LIST_HEAD(&ucontext->uobjects);

	return 0;
}

void ib_uverbs_uobject_type_release_ucontext(struct ib_ucontext *ucontext)
{
	kfree(ucontext->uobjects_lock);
}

