/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
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

#include <rdma/uverbs_std_types.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <linux/bug.h>
#include <linux/file.h>
#include "rdma_core.h"
#include "uverbs.h"
#include "core_priv.h"

static int uverbs_free_ah(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	return rdma_destroy_ah((struct ib_ah *)uobject->object);
}

static int uverbs_free_flow(struct ib_uobject *uobject,
			    enum rdma_remove_reason why)
{
	return ib_destroy_flow((struct ib_flow *)uobject->object);
}

static int uverbs_free_mw(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	return uverbs_dealloc_mw((struct ib_mw *)uobject->object);
}

static int uverbs_free_qp(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_qp *qp = uobject->object;
	struct ib_uqp_object *uqp =
		container_of(uobject, struct ib_uqp_object, uevent.uobject);
	int ret;

	if (why == RDMA_REMOVE_DESTROY) {
		if (!list_empty(&uqp->mcast_list))
			return -EBUSY;
	} else if (qp == qp->real_qp) {
		ib_uverbs_detach_umcast(qp, uqp);
	}

	ret = ib_destroy_qp(qp);
	if (ret && why == RDMA_REMOVE_DESTROY)
		return ret;

	if (uqp->uxrcd)
		atomic_dec(&uqp->uxrcd->refcnt);

	ib_uverbs_release_uevent(uobject->context->ufile, &uqp->uevent);
	return ret;
}

static int uverbs_free_rwq_ind_tbl(struct ib_uobject *uobject,
				   enum rdma_remove_reason why)
{
	struct ib_rwq_ind_table *rwq_ind_tbl = uobject->object;
	struct ib_wq **ind_tbl = rwq_ind_tbl->ind_tbl;
	int ret;

	ret = ib_destroy_rwq_ind_table(rwq_ind_tbl);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		kfree(ind_tbl);
	return ret;
}

static int uverbs_free_wq(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_wq *wq = uobject->object;
	struct ib_uwq_object *uwq =
		container_of(uobject, struct ib_uwq_object, uevent.uobject);
	int ret;

	ret = ib_destroy_wq(wq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_uevent(uobject->context->ufile, &uwq->uevent);
	return ret;
}

static int uverbs_free_srq(struct ib_uobject *uobject,
			   enum rdma_remove_reason why)
{
	struct ib_srq *srq = uobject->object;
	struct ib_uevent_object *uevent =
		container_of(uobject, struct ib_uevent_object, uobject);
	enum ib_srq_type  srq_type = srq->srq_type;
	int ret;

	ret = ib_destroy_srq(srq);

	if (ret && why == RDMA_REMOVE_DESTROY)
		return ret;

	if (srq_type == IB_SRQT_XRC) {
		struct ib_usrq_object *us =
			container_of(uevent, struct ib_usrq_object, uevent);

		atomic_dec(&us->uxrcd->refcnt);
	}

	ib_uverbs_release_uevent(uobject->context->ufile, uevent);
	return ret;
}

static int uverbs_free_cq(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_cq *cq = uobject->object;
	struct ib_uverbs_event_queue *ev_queue = cq->cq_context;
	struct ib_ucq_object *ucq =
		container_of(uobject, struct ib_ucq_object, uobject);
	int ret;

	ret = ib_destroy_cq(cq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_ucq(uobject->context->ufile, ev_queue ?
				      container_of(ev_queue,
						   struct ib_uverbs_completion_event_file,
						   ev_queue) : NULL,
				      ucq);
	return ret;
}

static int uverbs_free_mr(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	return ib_dereg_mr((struct ib_mr *)uobject->object);
}

static int uverbs_free_xrcd(struct ib_uobject *uobject,
			    enum rdma_remove_reason why)
{
	struct ib_xrcd *xrcd = uobject->object;
	struct ib_uxrcd_object *uxrcd =
		container_of(uobject, struct ib_uxrcd_object, uobject);
	int ret;

	mutex_lock(&uobject->context->ufile->device->xrcd_tree_mutex);
	if (why == RDMA_REMOVE_DESTROY && atomic_read(&uxrcd->refcnt))
		ret = -EBUSY;
	else
		ret = ib_uverbs_dealloc_xrcd(uobject->context->ufile->device,
					     xrcd, why);
	mutex_unlock(&uobject->context->ufile->device->xrcd_tree_mutex);

	return ret;
}

static int uverbs_free_pd(struct ib_uobject *uobject,
			  enum rdma_remove_reason why)
{
	struct ib_pd *pd = uobject->object;

	if (why == RDMA_REMOVE_DESTROY && atomic_read(&pd->usecnt))
		return -EBUSY;

	ib_dealloc_pd((struct ib_pd *)uobject->object);
	return 0;
}

static int uverbs_hot_unplug_completion_event_file(struct ib_uobject_file *uobj_file,
						   enum rdma_remove_reason why)
{
	struct ib_uverbs_completion_event_file *comp_event_file =
		container_of(uobj_file, struct ib_uverbs_completion_event_file,
			     uobj_file);
	struct ib_uverbs_event_queue *event_queue = &comp_event_file->ev_queue;

	spin_lock_irq(&event_queue->lock);
	event_queue->is_closed = 1;
	spin_unlock_irq(&event_queue->lock);

	if (why == RDMA_REMOVE_DRIVER_REMOVE) {
		wake_up_interruptible(&event_queue->poll_wait);
		kill_fasync(&event_queue->async_queue, SIGIO, POLL_IN);
	}
	return 0;
};

static int uverbs_empty_dealloc_handler(struct ib_device *ib_dev,
					struct ib_uverbs_file *file,
					struct uverbs_attr_array *ctx, size_t num)
{
	/*
	 * No need to check if the ib_dev->uverbs_cmd_mask supports it as if we
	 * initialized such an object, the device must have an appropriate
	 * function to destroy it.
	 */
	return 0;
}

/*
 * This spec is used in order to pass information to the hardware driver in a
 * legacy way. Every verb that could get driver specific data should get this
 * spec.
 */
static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_uhw_compat_spec,
	UVERBS_ATTR_PTR_IN_SZ(UVERBS_UHW_IN, 0, UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ)),
	UVERBS_ATTR_PTR_OUT_SZ(UVERBS_UHW_OUT, 0, UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ)));

static void create_udata(struct uverbs_attr_array *ctx, size_t num,
			 struct ib_udata *udata)
{
	/*
	 * This is for ease of conversion. The purpose is to convert all drivers
	 * to use uverbs_attr_array instead of ib_udata.
	 * Assume attr == 0 is input and attr == 1 is output.
	 */
	void __user *inbuf;
	size_t inbuf_len = 0;
	void __user *outbuf;
	size_t outbuf_len = 0;

	if (num > UVERBS_UDATA_DRIVER_DATA_GROUP) {
		struct uverbs_attr_array *driver = &ctx[UVERBS_UDATA_DRIVER_DATA_GROUP];

		if (uverbs_is_valid(driver, UVERBS_UHW_IN)) {
			inbuf = driver->attrs[UVERBS_UHW_IN].ptr_attr.ptr;
			inbuf_len = driver->attrs[UVERBS_UHW_IN].ptr_attr.len;
		}

		if (driver->num_attrs >= UVERBS_UHW_OUT &&
		    uverbs_is_valid(driver, UVERBS_UHW_OUT)) {
			outbuf = driver->attrs[UVERBS_UHW_OUT].ptr_attr.ptr;
			outbuf_len = driver->attrs[UVERBS_UHW_OUT].ptr_attr.len;
		}
	}
	INIT_UDATA_BUF_OR_NULL(udata, inbuf, outbuf, inbuf_len, outbuf_len);
}

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_create_cq_spec,
	UVERBS_ATTR_IDR(CREATE_CQ_HANDLE, UVERBS_TYPE_CQ, UVERBS_ACCESS_NEW,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(CREATE_CQ_CQE, u32,
			   UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(CREATE_CQ_USER_HANDLE, u64),
	UVERBS_ATTR_FD(CREATE_CQ_COMP_CHANNEL, UVERBS_TYPE_COMP_CHANNEL, UVERBS_ACCESS_READ),
	/*
	 * Currently, COMP_VECTOR is mandatory, but that could be lifted in the
	 * future.
	 */
	UVERBS_ATTR_PTR_IN(CREATE_CQ_COMP_VECTOR, u32,
			   UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(CREATE_CQ_FLAGS, u32),
	UVERBS_ATTR_PTR_OUT(CREATE_CQ_RESP_CQE, u32,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static int uverbs_create_cq_handler(struct ib_device *ib_dev,
				    struct ib_uverbs_file *file,
				    struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_ucontext *ucontext = file->ucontext;
	struct ib_ucq_object           *obj;
	struct ib_udata uhw;
	int ret;
	u64 user_handle = 0;
	struct ib_cq_init_attr attr = {};
	struct ib_cq                   *cq;
	struct ib_uverbs_completion_event_file    *ev_file = NULL;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_CREATE_CQ))
		return -EOPNOTSUPP;

	ret = uverbs_copy_from(&attr.comp_vector, common, CREATE_CQ_COMP_VECTOR);
	if (!ret)
		ret = uverbs_copy_from(&attr.cqe, common, CREATE_CQ_CQE);
	if (ret)
		return ret;

	/* Optional params, if they don't exist, we get -ENOENT and skip them */
	if (uverbs_copy_from(&attr.flags, common, CREATE_CQ_FLAGS) == -EFAULT ||
	    uverbs_copy_from(&user_handle, common, CREATE_CQ_USER_HANDLE) == -EFAULT)
		return -EFAULT;

	if (uverbs_is_valid(common, CREATE_CQ_COMP_CHANNEL)) {
		struct ib_uobject *ev_file_uobj =
			common->attrs[CREATE_CQ_COMP_CHANNEL].obj_attr.uobject;

		ev_file = container_of(ev_file_uobj,
				       struct ib_uverbs_completion_event_file,
				       uobj_file.uobj);
		uverbs_uobject_get(ev_file_uobj);
	}

	if (attr.comp_vector >= ucontext->ufile->device->num_comp_vectors) {
		ret = -EINVAL;
		goto err_event_file;
	}

	obj = container_of(common->attrs[CREATE_CQ_HANDLE].obj_attr.uobject,
			   typeof(*obj), uobject);
	obj->uverbs_file	   = ucontext->ufile;
	obj->comp_events_reported  = 0;
	obj->async_events_reported = 0;
	INIT_LIST_HEAD(&obj->comp_list);
	INIT_LIST_HEAD(&obj->async_list);

	/* Temporary, only until drivers get the new uverbs_attr_array */
	create_udata(ctx, num, &uhw);

	cq = ib_dev->create_cq(ib_dev, &attr, ucontext, &uhw);
	if (IS_ERR(cq)) {
		ret = PTR_ERR(cq);
		goto err_event_file;
	}

	cq->device        = ib_dev;
	cq->uobject       = &obj->uobject;
	cq->comp_handler  = ib_uverbs_comp_handler;
	cq->event_handler = ib_uverbs_cq_event_handler;
	cq->cq_context    = &ev_file->ev_queue;
	obj->uobject.object = cq;
	obj->uobject.user_handle = user_handle;
	atomic_set(&cq->usecnt, 0);

	ret = uverbs_copy_to(common, CREATE_CQ_RESP_CQE, &cq->cqe);
	if (ret)
		goto err_cq;

	return 0;
err_cq:
	ib_destroy_cq(cq);

err_event_file:
	if (ev_file)
		uverbs_uobject_put(&ev_file->uobj_file.uobj);
	return ret;
};

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_destroy_cq_spec,
	UVERBS_ATTR_IDR(DESTROY_CQ_HANDLE, UVERBS_TYPE_CQ,
			UVERBS_ACCESS_DESTROY,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_OUT(DESTROY_CQ_RESP, struct ib_uverbs_destroy_cq_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static int uverbs_destroy_cq_handler(struct ib_device *ib_dev,
				     struct ib_uverbs_file *file,
				     struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uverbs_destroy_cq_resp resp;
	struct ib_uobject *uobj =
		common->attrs[DESTROY_CQ_HANDLE].obj_attr.uobject;
	struct ib_ucq_object *obj = container_of(uobj, struct ib_ucq_object,
						 uobject);
	int ret;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_DESTROY_CQ))
		return -EOPNOTSUPP;

	ret = rdma_explicit_destroy(uobj);
	if (ret)
		return ret;

	resp.comp_events_reported  = obj->comp_events_reported;
	resp.async_events_reported = obj->async_events_reported;

	return uverbs_copy_to(common, DESTROY_CQ_RESP, &resp);
}

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_get_context_spec,
	UVERBS_ATTR_PTR_OUT(GET_CONTEXT_RESP,
			    struct ib_uverbs_get_context_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static int uverbs_get_context(struct ib_device *ib_dev,
			      struct ib_uverbs_file *file,
			      struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_udata uhw;
	struct ib_uverbs_get_context_resp resp;
	struct ib_ucontext		 *ucontext;
	struct file			 *filp;
	struct ib_rdmacg_object		 cg_obj;
	int ret;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_GET_CONTEXT))
		return -EOPNOTSUPP;

	/* Temporary, only until drivers get the new uverbs_attr_array */
	create_udata(ctx, num, &uhw);

	mutex_lock(&file->mutex);

	if (file->ucontext) {
		ret = -EINVAL;
		goto err;
	}

	ret = ib_rdmacg_try_charge(&cg_obj, ib_dev, RDMACG_RESOURCE_HCA_HANDLE);
	if (ret)
		goto err;

	ucontext = ib_dev->alloc_ucontext(ib_dev, &uhw);
	if (IS_ERR(ucontext)) {
		ret = PTR_ERR(ucontext);
		goto err_alloc;
	}

	ucontext->device = ib_dev;
	ucontext->cg_obj = cg_obj;
	/* ufile is required when some objects are released */
	ucontext->ufile = file;
	uverbs_initialize_ucontext(ucontext);

	rcu_read_lock();
	ucontext->tgid = get_task_pid(current->group_leader, PIDTYPE_PID);
	rcu_read_unlock();
	ucontext->closing = 0;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	ucontext->umem_tree = RB_ROOT;
	init_rwsem(&ucontext->umem_rwsem);
	ucontext->odp_mrs_count = 0;
	INIT_LIST_HEAD(&ucontext->no_private_counters);

	if (!(ib_dev->attrs.device_cap_flags & IB_DEVICE_ON_DEMAND_PAGING))
		ucontext->invalidate_range = NULL;

#endif

	resp.num_comp_vectors = file->device->num_comp_vectors;

	ret = get_unused_fd_flags(O_CLOEXEC);
	if (ret < 0)
		goto err_free;
	resp.async_fd = ret;

	filp = ib_uverbs_alloc_async_event_file(file, ib_dev);
	if (IS_ERR(filp)) {
		ret = PTR_ERR(filp);
		goto err_fd;
	}

	ret = uverbs_copy_to(common, GET_CONTEXT_RESP, &resp);
	if (ret)
		goto err_file;

	file->ucontext = ucontext;
	ucontext->ufile = file;

	fd_install(resp.async_fd, filp);

	mutex_unlock(&file->mutex);

	return 0;

err_file:
	ib_uverbs_free_async_event_file(file);
	fput(filp);
err_fd:
	put_unused_fd(resp.async_fd);
err_alloc:
	ib_rdmacg_uncharge(&cg_obj, ib_dev, RDMACG_RESOURCE_HCA_HANDLE);
err_free:
	put_pid(ucontext->tgid);
	ib_dev->dealloc_ucontext(ucontext);
err:
	mutex_unlock(&file->mutex);
	return ret;
}

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_query_device_spec,
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_RESP, struct ib_uverbs_query_device_resp),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_ODP, struct ib_uverbs_odp_caps),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_TIMESTAMP_MASK, u64),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_HCA_CORE_CLOCK, u64),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_CAP_FLAGS, u64),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_RSS, struct ib_uverbs_rss_caps),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_WQ_TYPE, u32),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_RAW_PACKET, u32));

static int uverbs_query_device_handler(struct ib_device *ib_dev,
				       struct ib_uverbs_file *file,
				       struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_device_attr attr = {};
	struct ib_udata uhw;
	int err;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_QUERY_DEVICE))
		return -EOPNOTSUPP;

	/* Temporary, only until drivers get the new uverbs_attr_array */
	create_udata(ctx, num, &uhw);

	err = ib_dev->query_device(ib_dev, &attr, &uhw);
	if (err)
		return err;

	if (uverbs_is_valid(common, QUERY_DEVICE_RESP)) {
		struct ib_uverbs_query_device_resp resp = {};

		uverbs_copy_query_dev_fields(ib_dev, &resp, &attr);
		if (uverbs_copy_to(common, QUERY_DEVICE_RESP, &resp))
			return -EFAULT;
	}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	if (uverbs_is_valid(common, QUERY_DEVICE_ODP)) {
		struct ib_uverbs_odp_caps odp_caps;

		odp_caps.general_caps = attr.odp_caps.general_caps;
		odp_caps.per_transport_caps.rc_odp_caps =
			attr.odp_caps.per_transport_caps.rc_odp_caps;
		odp_caps.per_transport_caps.uc_odp_caps =
			attr.odp_caps.per_transport_caps.uc_odp_caps;
		odp_caps.per_transport_caps.ud_odp_caps =
			attr.odp_caps.per_transport_caps.ud_odp_caps;

		if (uverbs_copy_to(common, QUERY_DEVICE_ODP, &odp_caps))
			return -EFAULT;
	}
#endif
	if (uverbs_copy_to(common, QUERY_DEVICE_TIMESTAMP_MASK,
			   &attr.timestamp_mask) == -EFAULT)
		return -EFAULT;

	if (uverbs_copy_to(common, QUERY_DEVICE_HCA_CORE_CLOCK,
			   &attr.hca_core_clock) == -EFAULT)
		return -EFAULT;

	if (uverbs_copy_to(common, QUERY_DEVICE_CAP_FLAGS,
			   &attr.device_cap_flags) == -EFAULT)
		return -EFAULT;

	if (uverbs_is_valid(common, QUERY_DEVICE_RSS)) {
		struct ib_uverbs_rss_caps rss_caps;

		rss_caps.supported_qpts = attr.rss_caps.supported_qpts;
		rss_caps.max_rwq_indirection_tables =
			attr.rss_caps.max_rwq_indirection_tables;
		rss_caps.max_rwq_indirection_table_size =
			attr.rss_caps.max_rwq_indirection_table_size;

		if (uverbs_copy_to(common, QUERY_DEVICE_RSS, &rss_caps))
			return -EFAULT;
	}

	if (uverbs_copy_to(common, QUERY_DEVICE_WQ_TYPE,
			   &attr.max_wq_type_rq) == -EFAULT)
		return -EFAULT;

	if (uverbs_copy_to(common, QUERY_DEVICE_RAW_PACKET,
			   &attr.raw_packet_caps) == -EFAULT)
		return -EFAULT;

	return 0;
}

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_query_port_spec,
	UVERBS_ATTR_PTR_IN(QUERY_PORT_PORT_NUM, __u8),
	UVERBS_ATTR_PTR_OUT(QUERY_PORT_RESP, struct ib_uverbs_query_port_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static int uverbs_query_port_handler(struct ib_device *ib_dev,
				     struct ib_uverbs_file *file,
				     struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uverbs_query_port_resp resp = {};
	struct ib_port_attr              attr;
	u8				 port_num;
	int				 ret;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_QUERY_PORT))
		return -EOPNOTSUPP;

	ret = uverbs_copy_from(&port_num, common, QUERY_PORT_PORT_NUM);
	if (ret)
		return ret;

	ret = ib_query_port(ib_dev, port_num, &attr);
	if (ret)
		return ret;

	resp.state	     = attr.state;
	resp.max_mtu	     = attr.max_mtu;
	resp.active_mtu      = attr.active_mtu;
	resp.gid_tbl_len     = attr.gid_tbl_len;
	resp.port_cap_flags  = attr.port_cap_flags;
	resp.max_msg_sz      = attr.max_msg_sz;
	resp.bad_pkey_cntr   = attr.bad_pkey_cntr;
	resp.qkey_viol_cntr  = attr.qkey_viol_cntr;
	resp.pkey_tbl_len    = attr.pkey_tbl_len;
	resp.lid	     = attr.lid;
	resp.sm_lid	     = attr.sm_lid;
	resp.lmc	     = attr.lmc;
	resp.max_vl_num      = attr.max_vl_num;
	resp.sm_sl	     = attr.sm_sl;
	resp.subnet_timeout  = attr.subnet_timeout;
	resp.init_type_reply = attr.init_type_reply;
	resp.active_width    = attr.active_width;
	resp.active_speed    = attr.active_speed;
	resp.phys_state      = attr.phys_state;
	resp.link_layer      = rdma_port_get_link_layer(ib_dev, port_num);

	return uverbs_copy_to(common, QUERY_PORT_RESP, &resp);
}

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_alloc_pd_spec,
	UVERBS_ATTR_IDR(ALLOC_PD_HANDLE, UVERBS_TYPE_PD,
			UVERBS_ACCESS_NEW,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static int uverbs_alloc_pd_handler(struct ib_device *ib_dev,
				   struct ib_uverbs_file *file,
				   struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_ucontext *ucontext = file->ucontext;
	struct ib_udata uhw;
	struct ib_uobject *uobject;
	struct ib_pd *pd;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL << IB_USER_VERBS_CMD_ALLOC_PD))
		return -EOPNOTSUPP;

	/* Temporary, only until drivers get the new uverbs_attr_array */
	create_udata(ctx, num, &uhw);

	pd = ib_dev->alloc_pd(ib_dev, ucontext, &uhw);
	if (IS_ERR(pd))
		return PTR_ERR(pd);

	uobject = common->attrs[ALLOC_PD_HANDLE].obj_attr.uobject;
	pd->device  = ib_dev;
	pd->uobject = uobject;
	pd->__internal_mr = NULL;
	uobject->object = pd;
	atomic_set(&pd->usecnt, 0);

	return 0;
}

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_dealloc_pd_spec,
	UVERBS_ATTR_IDR(DEALLOC_PD_HANDLE, UVERBS_TYPE_PD,
			UVERBS_ACCESS_DESTROY,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static DECLARE_UVERBS_ATTR_SPEC(
	uverbs_create_comp_channel_spec,
	UVERBS_ATTR_FD(CREATE_COMP_CHANNEL_FD, UVERBS_TYPE_COMP_CHANNEL,
		       UVERBS_ACCESS_NEW,
		       UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

static int uverbs_create_comp_channel_handler(struct ib_device *ib_dev,
					      struct ib_uverbs_file *file,
					      struct uverbs_attr_array *ctx,
					      size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uverbs_completion_event_file *ev_file;
	struct ib_uobject *uobj =
		common->attrs[CREATE_COMP_CHANNEL_FD].obj_attr.uobject;

	if (!(ib_dev->uverbs_cmd_mask & 1ULL <<
	      IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL))
		return -EOPNOTSUPP;

	kref_get(&uobj->ref);
	ev_file = container_of(uobj,
			       struct ib_uverbs_completion_event_file,
			       uobj_file.uobj);
	ib_uverbs_init_event_queue(&ev_file->ev_queue);

	return 0;
}

DECLARE_UVERBS_TYPE(uverbs_type_comp_channel,
		    &UVERBS_TYPE_ALLOC_FD(0,
					  sizeof(struct ib_uverbs_completion_event_file),
					  uverbs_hot_unplug_completion_event_file,
					  &uverbs_event_fops,
					  "[infinibandevent]", O_RDONLY),
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_COMP_CHANNEL_CREATE,
					  uverbs_create_comp_channel_handler,
					  &uverbs_create_comp_channel_spec)));

DECLARE_UVERBS_TYPE(uverbs_type_cq,
		    &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_ucq_object), 0,
					      uverbs_free_cq),
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_CQ_CREATE,
					  uverbs_create_cq_handler,
					  &uverbs_create_cq_spec,
					  &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_CQ_DESTROY,
					  uverbs_destroy_cq_handler,
					  &uverbs_destroy_cq_spec)));

DECLARE_UVERBS_TYPE(uverbs_type_qp,
		    &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uqp_object), 0,
					      uverbs_free_qp));

DECLARE_UVERBS_TYPE(uverbs_type_mw,
		    &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_mw));

DECLARE_UVERBS_TYPE(uverbs_type_mr,
		    /* 1 is used in order to free the MR after all the MWs */
		    &UVERBS_TYPE_ALLOC_IDR(1, uverbs_free_mr));

DECLARE_UVERBS_TYPE(uverbs_type_srq,
		    &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_usrq_object), 0,
					      uverbs_free_srq));

DECLARE_UVERBS_TYPE(uverbs_type_ah,
		    &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_ah));

DECLARE_UVERBS_TYPE(uverbs_type_flow,
		    &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_flow));

DECLARE_UVERBS_TYPE(uverbs_type_wq,
		    &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uwq_object), 0,
					      uverbs_free_wq));

DECLARE_UVERBS_TYPE(uverbs_type_rwq_ind_table,
		    &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_rwq_ind_tbl));

DECLARE_UVERBS_TYPE(uverbs_type_xrcd,
		    &UVERBS_TYPE_ALLOC_IDR_SZ(sizeof(struct ib_uxrcd_object), 0,
					      uverbs_free_xrcd));

DECLARE_UVERBS_TYPE(uverbs_type_pd,
		    /* 2 is used in order to free the PD after MRs */
		    &UVERBS_TYPE_ALLOC_IDR(2, uverbs_free_pd),
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_PD_ALLOC,
					  uverbs_alloc_pd_handler,
					  &uverbs_alloc_pd_spec,
					  &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_PD_DEALLOC,
					  uverbs_empty_dealloc_handler,
					  &uverbs_dealloc_pd_spec)));

DECLARE_UVERBS_TYPE(uverbs_type_device, NULL,
		    &UVERBS_ACTIONS(
			ADD_UVERBS_CTX_ACTION(UVERBS_DEVICE_ALLOC_CONTEXT,
					      uverbs_get_context,
					      &uverbs_get_context_spec,
					      &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_DEVICE_QUERY,
					  uverbs_query_device_handler,
					  &uverbs_query_device_spec,
					  &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_DEVICE_PORT_QUERY,
					  uverbs_query_port_handler,
					  &uverbs_query_port_spec)));

DECLARE_UVERBS_TYPES(uverbs_common_types,
		     ADD_UVERBS_TYPE(UVERBS_TYPE_DEVICE, uverbs_type_device),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_PD, uverbs_type_pd),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_MR, uverbs_type_mr),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_COMP_CHANNEL, uverbs_type_comp_channel),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_CQ, uverbs_type_cq),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_QP, uverbs_type_qp),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_AH, uverbs_type_ah),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_MW, uverbs_type_mw),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_SRQ, uverbs_type_srq),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_FLOW, uverbs_type_flow),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_WQ, uverbs_type_wq),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_RWQ_IND_TBL,
				     uverbs_type_rwq_ind_table),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_XRCD, uverbs_type_xrcd),
);
EXPORT_SYMBOL(uverbs_common_types);
