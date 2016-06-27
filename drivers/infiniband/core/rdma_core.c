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
#include <linux/rcupdate.h>
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
	/*
	 * When a read is required, we use a positive counter. Each read
	 * request checks that the value != -1 and increment it. Write
	 * requires an exclusive access, thus we check that the counter is
	 * zero (nobody claimed this object) and we set it to -1.
	 * Releasing a read lock is done by simply decreasing the counter.
	 * As for writes, since only a single write is permitted, setting
	 * it to zero is enough for releasing it.
	 */
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
	uobj->context = context;
	uobj->type = type;
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

/*
 * It only removes it from the uobjects list, uverbs_uobject_put() is still
 * required.
 */
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

	RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
			 "ib_uverbs: lookup_get_idr_uobject is called without propper synchronization");
	/* object won't be released as we're protected in rcu */
	uobj = idr_find(&ucontext->ufile->idr, id);
	if (!uobj)
		return ERR_PTR(-ENOENT);

	if (uobj->type != type)
		return ERR_PTR(-EINVAL);

	return uobj;
}

struct ib_uobject *rdma_lookup_get_uobject(const struct uverbs_obj_type *type,
					   struct ib_ucontext *ucontext,
					   int id, bool write)
{
	struct ib_uobject *uobj;
	int ret;

	if (type->type_class->needs_rcu)
		rcu_read_lock();

	uobj = type->type_class->lookup_get(type, ucontext, id, write);
	if (IS_ERR(uobj))
		goto free;

	ret = uverbs_try_lock_object(uobj, write);
	if (ret) {
		WARN(ucontext->cleanup_reason,
		     "ib_uverbs: Trying to lookup_get while cleanup context\n");
		uobj = ERR_PTR(ret);
		goto free;
	}

	uverbs_uobject_get(uobj);
free:
	if (type->type_class->needs_rcu)
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

struct ib_uobject *rdma_alloc_begin_uobject(const struct uverbs_obj_type *type,
					    struct ib_ucontext *ucontext)
{
	return type->type_class->alloc_begin(type, ucontext);
}

static void uverbs_uobject_add(struct ib_uobject *uobject)
{
	mutex_lock(&uobject->context->uobjects_lock);
	list_add(&uobject->list, &uobject->context->uobjects);
	mutex_unlock(&uobject->context->uobjects_lock);
}

static int __must_check remove_commit_idr_uobject(struct ib_uobject *uobj,
						  enum rdma_remove_reason why)
{
	const struct uverbs_obj_idr_type *idr_type =
		container_of(uobj->type, struct uverbs_obj_idr_type,
			     type);
	int ret = idr_type->destroy_object(uobj, why);

	if (why == RDMA_REMOVE_DESTROY && ret)
		return ret;

	uverbs_idr_remove_uobj(uobj);

	return ret;
}

static void lockdep_check(struct ib_uobject *uobj, bool write)
{
#ifdef CONFIG_LOCKDEP
	if (!write)
		WARN_ON(atomic_read(&uobj->usecnt) > 0);
	else
		WARN_ON(atomic_read(&uobj->usecnt) == -1);
#endif
}

int __must_check _rdma_remove_commit_uobject(struct ib_uobject *uobj,
					     enum rdma_remove_reason why,
					     bool lock)
{
	int ret;
	struct ib_ucontext *ucontext = uobj->context;

	ret = uobj->type->type_class->remove_commit(uobj, why);
	if (ret && why == RDMA_REMOVE_DESTROY) {
		atomic_set(&uobj->usecnt, 0);
		uobj->type->type_class->lookup_put(uobj, true);
	} else {
		if (lock)
			mutex_lock(&ucontext->uobjects_lock);
		list_del(&uobj->list);
		if (lock)
			mutex_unlock(&ucontext->uobjects_lock);
		/* put the ref we took when we created the object */
		uverbs_uobject_put(uobj);
	}

	return ret;
}

/* This is called only for destroy reasons */
int __must_check rdma_remove_commit_uobject(struct ib_uobject *uobj)
{
	int ret;
	struct ib_ucontext *ucontext = uobj->context;

	/* put the ref count we took at lookup_get */
	uverbs_uobject_put(uobj);
	/* Cleanup is running. Calling this should have been impossible */
	if (!down_read_trylock(&ucontext->cleanup_rwsem)) {
		WARN(true, "ib_uverbs: Cleanup is running while removing an uobject\n");
		return 0;
	}
	lockdep_check(uobj, true);
	ret = _rdma_remove_commit_uobject(uobj, RDMA_REMOVE_DESTROY, true);

	up_read(&ucontext->cleanup_rwsem);
	return ret;
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

int rdma_alloc_commit_uobject(struct ib_uobject *uobj)
{
	/* Cleanup is running. Calling this should have been impossible */
	if (!down_read_trylock(&uobj->context->cleanup_rwsem)) {
		int ret;

		WARN(true, "ib_uverbs: Cleanup is running while allocating an uobject\n");
		ret = uobj->type->type_class->remove_commit(uobj,
							    RDMA_REMOVE_DURING_CLEANUP);
		if (ret)
			pr_warn("ib_uverbs: cleanup of idr object %d failed\n",
				uobj->id);
		return ret;
	}

	uobj->type->type_class->alloc_commit(uobj);
	up_read(&uobj->context->cleanup_rwsem);

	return 0;
}

static void alloc_abort_idr_uobject(struct ib_uobject *uobj)
{
	uverbs_idr_remove_uobj(uobj);
	/*
	 * Actually, we don't need kfree_rcu here, as the uobject wasn't
	 * exposed to any other verb. However, to simplify the code
	 * we use that anyway.
	 */
	uverbs_uobject_put(uobj);
}

void rdma_alloc_abort_uobject(struct ib_uobject *uobj)
{
	uobj->type->type_class->alloc_abort(uobj);
}

static void lookup_put_idr_uobject(struct ib_uobject *uobj, bool write)
{
}

void rdma_lookup_put_uobject(struct ib_uobject *uobj, bool write)
{
	lockdep_check(uobj, write);
	uobj->type->type_class->lookup_put(uobj, write);
	if (!write)
		atomic_dec(&uobj->usecnt);
	else
		atomic_set(&uobj->usecnt, 0);

	uverbs_uobject_put(uobj);
}

const struct uverbs_obj_type_class uverbs_idr_class = {
	.alloc_begin = alloc_begin_idr_uobject,
	.lookup_get = lookup_get_idr_uobject,
	.alloc_commit = alloc_commit_idr_uobject,
	.alloc_abort = alloc_abort_idr_uobject,
	.lookup_put = lookup_put_idr_uobject,
	.remove_commit = remove_commit_idr_uobject,
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

void uverbs_cleanup_ucontext(struct ib_ucontext *ucontext, bool device_removed)
{
	enum rdma_remove_reason reason = device_removed ?
		RDMA_REMOVE_DRIVER_REMOVE : RDMA_REMOVE_CLOSE;
	unsigned int cur_order = 0;

	ucontext->cleanup_reason = reason;
	/*
	 * Waits for all remove_commit and alloc_commit to finish. We hold this
	 * forever as the context is going to be destroyed.
	 */
	down_write(&ucontext->cleanup_rwsem);

	while (!list_empty(&ucontext->uobjects)) {
		struct ib_uobject *obj, *next_obj;
		unsigned int next_order = UINT_MAX;

		/*
		 * This shouldn't run while executing other commands on this
		 * context.
		 */
		mutex_lock(&ucontext->uobjects_lock);
		list_for_each_entry_safe(obj, next_obj, &ucontext->uobjects,
					 list)
			if (obj->type->destroy_order == cur_order) {
				int ret;

				/*
				 * if we hit this WARN_ON, that means we are
				 * racing with a lookup_get.
				 */
				WARN_ON(uverbs_try_lock_object(obj, true));
				ret = _rdma_remove_commit_uobject(obj, reason,
								  false);
				if (ret)
					pr_warn("ib_uverbs: failed to remove uobject id %d order %u\n",
						obj->id, cur_order);
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
	ucontext->cleanup_reason = 0;
	mutex_init(&ucontext->uobjects_lock);
	INIT_LIST_HEAD(&ucontext->uobjects);
	init_rwsem(&ucontext->cleanup_rwsem);
}

