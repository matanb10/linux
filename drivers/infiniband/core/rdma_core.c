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
#include <rdma/uverbs_types.h>
#include "uverbs.h"
#include "rdma_core.h"

void uverbs_uobject_get(struct ib_uobject *uobject)
{
	kref_get(&uobject->ref);
}

static void uverbs_uobject_put_ref(struct kref *ref)
{
	struct ib_uobject *uobj =
		container_of(ref, struct ib_uobject, ref);

	if (uobj->type->type_class->needs_rcu)
		kfree_rcu(uobj, rcu);
	else
		kfree(uobj);
}

void uverbs_uobject_put(struct ib_uobject *uobject)
{
	kref_put(&uobject->ref, uverbs_uobject_put_ref);
}

static int uverbs_try_lock_object(struct ib_uobject *uobj, bool write)
{
	if (!write)
		return __atomic_add_unless(&uobj->usecnt, 1, -1) == -1 ?
			-EBUSY : 0;

	/* lock is either WRITE or DESTROY - should be exclusive */
	return atomic_cmpxchg(&uobj->usecnt, 0, -1) == 0 ? 0 : -EBUSY;
}

static struct ib_uobject *alloc_uobj(struct ib_ucontext *context,
				     const struct uverbs_obj_type *type)
{
	struct ib_uobject *uobj = kmalloc(type->obj_size, GFP_KERNEL);

	if (!uobj)
		return ERR_PTR(-ENOMEM);
	/*
	 * user_handle should be filled by the handler,
	 * The object is added to the list in the commit stage.
	 */
	uobj->context     = context;
	uobj->type	  = type;
	atomic_set(&uobj->usecnt, 0);
	kref_init(&uobj->ref);

	return uobj;
}

static int idr_add_uobj(struct ib_uobject *uobj)
{
	int ret;

	idr_preload(GFP_KERNEL);
	spin_lock(&uobj->context->ufile->idr_lock);

	/*
	 * We start with allocating an idr pointing to NULL. This represents an
	 * object which isn't initialized yet. We'll replace it later on with
	 * the real object once we commit.
	 */
	ret = idr_alloc(&uobj->context->ufile->idr, NULL, 0,
			min_t(unsigned long, U32_MAX - 1, INT_MAX), GFP_NOWAIT);
	if (ret >= 0)
		uobj->id = ret;

	spin_unlock(&uobj->context->ufile->idr_lock);
	idr_preload_end();

	return ret < 0 ? ret : 0;
}

/* The caller must uverbs_uobject_put() uobj */
static void uverbs_idr_remove_uobj(struct ib_uobject *uobj)
{
	spin_lock(&uobj->context->ufile->idr_lock);
	idr_remove(&uobj->context->ufile->idr, uobj->id);
	spin_unlock(&uobj->context->ufile->idr_lock);
}

/* Returns the ib_uobject or an error. The caller should check for IS_ERR. */
static struct ib_uobject *lookup_get_idr_uobject(const struct uverbs_obj_type *type,
						 struct ib_ucontext *ucontext,
						 int id, bool write)
{
	struct ib_uobject *uobj;
	int ret;

	rcu_read_lock();
	/* object won't be released as we're protected in rcu */
	uobj = idr_find(&ucontext->ufile->idr, id);
	if (!uobj) {
		uobj = ERR_PTR(-ENOENT);
		goto free;
	}

	if (uobj->type != type) {
		uobj = ERR_PTR(-EINVAL);
		goto free;
	}

	ret = uverbs_try_lock_object(uobj, write);
	if (ret)
		uobj = ERR_PTR(ret);
free:
	rcu_read_unlock();
	return uobj;
}

static struct ib_uobject *alloc_begin_idr_uobject(const struct uverbs_obj_type *type,
						  struct ib_ucontext *ucontext)
{
	int ret;
	struct ib_uobject *uobj;

	uobj = alloc_uobj(ucontext, type);
	if (IS_ERR(uobj))
		return uobj;

	ret = idr_add_uobj(uobj);
	if (ret) {
		uverbs_uobject_put(uobj);
		return ERR_PTR(ret);
	}

	return uobj;
}

static void uverbs_uobject_add(struct ib_uobject *uobject)
{
	mutex_lock(&uobject->context->uobjects_lock);
	list_add(&uobject->list, &uobject->context->uobjects);
	mutex_unlock(&uobject->context->uobjects_lock);
}

static void uverbs_uobject_remove(struct ib_uobject *uobject)
{
	mutex_lock(&uobject->context->uobjects_lock);
	list_del(&uobject->list);
	mutex_unlock(&uobject->context->uobjects_lock);
}

static struct ib_uobject *alloc_begin_fd_uobject(const struct uverbs_obj_type *type,
						 struct ib_ucontext *ucontext)
{
	const struct uverbs_obj_fd_type *fd_type =
		container_of(type, struct uverbs_obj_fd_type, type);
	int new_fd;
	struct ib_uobject *uobj;
	struct ib_uobject_file *uobj_file;
	struct file *filp;

	new_fd = get_unused_fd_flags(O_CLOEXEC);
	if (new_fd < 0)
		return ERR_PTR(new_fd);

	uobj = alloc_uobj(ucontext, type);
	if (IS_ERR(uobj)) {
		put_unused_fd(new_fd);
		return uobj;
	}

	uobj_file = container_of(uobj, struct ib_uobject_file, uobj);
	filp = anon_inode_getfile(fd_type->name,
				  fd_type->fops,
				  uobj_file,
				  fd_type->flags);
	if (IS_ERR(filp)) {
		put_unused_fd(new_fd);
		uverbs_uobject_put(uobj);
		return (void *)filp;
	}

	uobj_file->uobj.id = new_fd;
	uobj_file->uobj.object = filp;
	uobj_file->ufile = ucontext->ufile;
	INIT_LIST_HEAD(&uobj->list);
	kref_get(&uobj_file->ufile->ref);

	return uobj;
}

static struct ib_uobject *lookup_get_fd_uobject(const struct uverbs_obj_type *type,
						struct ib_ucontext *ucontext,
						int id, bool write)
{
	struct file *f;
	struct ib_uobject *uobject;
	const struct uverbs_obj_fd_type *fd_type =
		container_of(type, struct uverbs_obj_fd_type, type);

	if (write)
		return ERR_PTR(-EOPNOTSUPP);

	f = fget(id);
	if (!f)
		return ERR_PTR(-EBADF);

	uobject = f->private_data;
	if (f->f_op != fd_type->fops ||
	    !uobject->context) {
		fput(f);
		return ERR_PTR(-EBADF);
	}

	/*
	 * No need to protect it with a ref count, as fget increases
	 * f_count.
	 */
	return uobject;
}

static void alloc_commit_idr_uobject(struct ib_uobject *uobj)
{
	uverbs_uobject_add(uobj);
	spin_lock(&uobj->context->ufile->idr_lock);
	/*
	 * We already allocated this IDR with a NULL object, so
	 * this shouldn't fail.
	 */
	WARN_ON(idr_replace(&uobj->context->ufile->idr,
			    uobj, uobj->id));
	spin_unlock(&uobj->context->ufile->idr_lock);
}

static void alloc_abort_idr_uobject(struct ib_uobject *uobj)
{
	uverbs_idr_remove_uobj(uobj);
	/*
	 * Actually, we don't need kfree_rcu here, as the uobject wasn't
	 * exposed to any other verb. However, to simplift the code
	 * we use that anyway.
	 */
	uverbs_uobject_put(uobj);
}

static void lookup_put_idr_uobject(struct ib_uobject *uobj, bool write)
{
	if (write)
		atomic_dec(&uobj->usecnt);
	else
		atomic_set(&uobj->usecnt, 0);
}

static void lookup_put_fd_uobject(struct ib_uobject *uobj, bool write)
{
	struct file *filp = uobj->object;

	WARN_ON(write);
	/* This indirectly calls uverbs_close_fd and free the object */
	fput(filp);
}

static void alloc_commit_fd_uobject(struct ib_uobject *uobj)
{
	struct ib_uobject_file *uobj_file =
		container_of(uobj, struct ib_uobject_file, uobj);

	uverbs_uobject_add(&uobj_file->uobj);
	fd_install(uobj_file->uobj.id, uobj->object);
	/* This shouldn't be used anymore. Use the file object instead */
	uobj_file->uobj.id = 0;
}

static void alloc_abort_fd_uobject(struct ib_uobject *uobj)
{
	struct ib_uobject_file *uobj_file =
		container_of(uobj, struct ib_uobject_file, uobj);
	struct file *filp = uobj->object;
	int id = uobj_file->uobj.id;

	/* Unsuccessful NEW */
	fput(filp);
	put_unused_fd(id);
}

static void remove_commit_idr_uobject(struct ib_uobject *uobj)
{

	/* In other cases, the object is removed by the caller */
	uverbs_uobject_remove(uobj);
	uverbs_idr_remove_uobj(uobj);
	uverbs_uobject_put(uobj);
}

static void cleanup_idr_uobject(struct ib_uobject *uobj,
				enum rdma_cleanup_reason why)
{
	const struct uverbs_obj_idr_type *idr_type =
		container_of(uobj->type, struct uverbs_obj_idr_type,
			     type);

	idr_type->destroy_object(uobj);
	uverbs_idr_remove_uobj(uobj);
	uverbs_uobject_put(uobj);
}

const struct uverbs_obj_type_class uverbs_idr_class = {
	.alloc_begin = alloc_begin_idr_uobject,
	.lookup_get = lookup_get_idr_uobject,
	.alloc_commit = alloc_commit_idr_uobject,
	.alloc_abort = alloc_abort_idr_uobject,
	.lookup_put = lookup_put_idr_uobject,
	.remove_commit = remove_commit_idr_uobject,
	.cleanup = cleanup_idr_uobject,
	/*
	 * When we destroy an object, we first just lock it for WRITE and
	 * actually DESTROY it in the finalize stage. So, the problematic
	 * scenario is when we just started the finalize stage of the
	 * destruction (nothing was executed yet). Now, the other thread
	 * fetched the object for READ access, but it didn't lock it yet.
	 * The DESTROY thread continues and starts destroying the object.
	 * When the other thread continue - without the RCU, it would
	 * access freed memory. However, the rcu_read_lock delays the free
	 * until the rcu_read_lock of the READ operation quits. Since the
	 * write lock of the object is still taken by the DESTROY flow, the
	 * READ operation will get -EBUSY and it'll just bail out.
	 */
	.needs_rcu = true,
};

static void _uverbs_close_fd(struct ib_uobject_file *uobj_file)
{
	mutex_lock(&uobj_file->ufile->cleanup_mutex);
	if (uobj_file->uobj.context) {
		uverbs_uobject_remove(&uobj_file->uobj);
		uobj_file->uobj.context = NULL;
	}
	mutex_unlock(&uobj_file->ufile->cleanup_mutex);
}

void uverbs_close_fd(struct file *f)
{
	struct ib_uobject_file *uobj_file = f->private_data;

	_uverbs_close_fd(uobj_file);
	kref_put(&uobj_file->ufile->ref, ib_uverbs_release_file);
	uverbs_uobject_put(&uobj_file->uobj);
}

static void remove_commit_fd_uobject(struct ib_uobject *uobj)
{
	struct ib_uobject_file *uobj_file =
		container_of(uobj, struct ib_uobject_file, uobj);

	_uverbs_close_fd(uobj_file);
}

void uverbs_cleanup_ucontext(struct ib_ucontext *ucontext, bool device_removed)
{
	enum rdma_cleanup_reason reason = device_removed ?
		RDMA_REMOVE_DRIVER_REMOVE : RDMA_REMOVE_CLOSE;
	unsigned int cur_order = 0;

	while (!list_empty(&ucontext->uobjects)) {
		struct ib_uobject *obj, *next_obj;
		unsigned int next_order = UINT_MAX;

		/*
		 * This shouldn't run while executing other commands on this
		 * context. Thus, the only thing we should take care of is
		 * releasing a FD while traversing this list. The FD could be
		 * closed and released from the _release fop of this FD.
		 * In order to mitigate this, we add a lock.
		 * We take and release the lock per order traversal in order
		 * to let other threads (which might still use the FDs) chance
		 * to run.
		 */
		mutex_lock(&ucontext->uobjects_lock);
		list_for_each_entry_safe(obj, next_obj, &ucontext->uobjects,
					 list)
			if (obj->type->destroy_order == cur_order) {
				WARN_ON(uverbs_try_lock_object(obj, true));
				list_del(&obj->list);
				obj->type->type_class->cleanup(obj, reason);
			} else {
				next_order = min(next_order,
						 obj->type->destroy_order);
			}
		mutex_unlock(&ucontext->uobjects_lock);
		cur_order = next_order;
	}
}

void uverbs_initialize_ucontext(struct ib_ucontext *ucontext)
{
	mutex_init(&ucontext->uobjects_lock);
	INIT_LIST_HEAD(&ucontext->uobjects);
}

static void cleanup_fd_uobject(struct ib_uobject *uobj,
			       enum rdma_cleanup_reason why)
{
	const struct uverbs_obj_fd_type *fd_type =
		container_of(uobj->type, struct uverbs_obj_fd_type, type);
	struct ib_uobject_file *uobj_file =
		container_of(uobj, struct ib_uobject_file, uobj);

	fd_type->context_closed(uobj_file, why);
	uobj_file->uobj.context = NULL;
}

const struct uverbs_obj_type_class uverbs_fd_class = {
	.alloc_begin = alloc_begin_fd_uobject,
	.lookup_get = lookup_get_fd_uobject,
	.alloc_commit = alloc_commit_fd_uobject,
	.alloc_abort = alloc_abort_fd_uobject,
	.lookup_put = lookup_put_fd_uobject,
	.remove_commit = remove_commit_fd_uobject,
	.cleanup = cleanup_fd_uobject,
	.needs_rcu = false,
};

