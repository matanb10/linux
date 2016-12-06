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

#include <rdma/uverbs_ioctl_cmd.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/bug.h>
#include <linux/file.h>
#include "rdma_core.h"
#include "uverbs.h"

void uverbs_free_ah(const struct uverbs_type_alloc_action *uobject_type,
		    struct ib_uobject *uobject)
{
	ib_destroy_ah((struct ib_ah *)uobject->object);
}
EXPORT_SYMBOL(uverbs_free_ah);

void uverbs_free_flow(const struct uverbs_type_alloc_action *type_alloc_action,
		      struct ib_uobject *uobject)
{
	ib_destroy_flow((struct ib_flow *)uobject->object);
}
EXPORT_SYMBOL(uverbs_free_flow);

void uverbs_free_mw(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject)
{
	uverbs_dealloc_mw((struct ib_mw *)uobject->object);
}
EXPORT_SYMBOL(uverbs_free_mw);

void uverbs_free_qp(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject)
{
	struct ib_qp *qp = uobject->object;
	struct ib_uqp_object *uqp =
		container_of(uobject, struct ib_uqp_object, uevent.uobject);

	if (qp != qp->real_qp) {
		ib_close_qp(qp);
	} else {
		ib_uverbs_detach_umcast(qp, uqp);
		ib_destroy_qp(qp);
	}
	ib_uverbs_release_uevent(uobject->context->ufile, &uqp->uevent);
}
EXPORT_SYMBOL(uverbs_free_qp);

void uverbs_free_rwq_ind_tbl(const struct uverbs_type_alloc_action *type_alloc_action,
			     struct ib_uobject *uobject)
{
	struct ib_rwq_ind_table *rwq_ind_tbl = uobject->object;
	struct ib_wq **ind_tbl = rwq_ind_tbl->ind_tbl;

	ib_destroy_rwq_ind_table(rwq_ind_tbl);
	kfree(ind_tbl);
}
EXPORT_SYMBOL(uverbs_free_rwq_ind_tbl);

void uverbs_free_wq(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject)
{
	struct ib_wq *wq = uobject->object;
	struct ib_uwq_object *uwq =
		container_of(uobject, struct ib_uwq_object, uevent.uobject);

	ib_destroy_wq(wq);
	ib_uverbs_release_uevent(uobject->context->ufile, &uwq->uevent);
}
EXPORT_SYMBOL(uverbs_free_wq);

void uverbs_free_srq(const struct uverbs_type_alloc_action *type_alloc_action,
		     struct ib_uobject *uobject)
{
	struct ib_srq *srq = uobject->object;
	struct ib_uevent_object *uevent =
		container_of(uobject, struct ib_uevent_object, uobject);

	ib_destroy_srq(srq);
	ib_uverbs_release_uevent(uobject->context->ufile, uevent);
}
EXPORT_SYMBOL(uverbs_free_srq);

void uverbs_free_cq(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject)
{
	struct ib_cq *cq = uobject->object;
	struct ib_uverbs_event_file *ev_file = cq->cq_context;
	struct ib_ucq_object *ucq =
		container_of(uobject, struct ib_ucq_object, uobject);

	ib_destroy_cq(cq);
	ib_uverbs_release_ucq_refactored(uobject->context->ufile, ev_file, ucq);
}
EXPORT_SYMBOL(uverbs_free_cq);

void uverbs_free_mr(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject)
{
	ib_dereg_mr((struct ib_mr *)uobject->object);
}
EXPORT_SYMBOL(uverbs_free_mr);

void uverbs_free_xrcd(const struct uverbs_type_alloc_action *type_alloc_action,
		      struct ib_uobject *uobject)
{
	struct ib_xrcd *xrcd = uobject->object;

	mutex_lock(&uobject->context->ufile->device->xrcd_tree_mutex);
	ib_uverbs_dealloc_xrcd(uobject->context->ufile->device, xrcd);
	mutex_unlock(&uobject->context->ufile->device->xrcd_tree_mutex);
}
EXPORT_SYMBOL(uverbs_free_xrcd);

void uverbs_free_pd(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject)
{
	ib_dealloc_pd((struct ib_pd *)uobject->object);
}
EXPORT_SYMBOL(uverbs_free_pd);

void uverbs_free_event_file(const struct uverbs_type_alloc_action *type_alloc_action,
			    struct ib_uobject *uobject)
{
	struct ib_uverbs_event_file *event_file = (void *)(uobject + 1);

	spin_lock_irq(&event_file->lock);
	event_file->is_closed = 1;
	spin_unlock_irq(&event_file->lock);

	wake_up_interruptible(&event_file->poll_wait);
	kill_fasync(&event_file->async_queue, SIGIO, POLL_IN);
};
EXPORT_SYMBOL(uverbs_free_event_file);

