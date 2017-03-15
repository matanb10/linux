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

int uverbs_free_ah(struct ib_uobject *uobject,
		   enum rdma_remove_reason why)
{
	return ib_destroy_ah((struct ib_ah *)uobject->object);
}

int uverbs_free_flow(struct ib_uobject *uobject,
		     enum rdma_remove_reason why)
{
	return ib_destroy_flow((struct ib_flow *)uobject->object);
}

int uverbs_free_mw(struct ib_uobject *uobject,
		   enum rdma_remove_reason why)
{
	return uverbs_dealloc_mw((struct ib_mw *)uobject->object);
}

int uverbs_free_qp(struct ib_uobject *uobject,
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

int uverbs_free_rwq_ind_tbl(struct ib_uobject *uobject,
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

int uverbs_free_wq(struct ib_uobject *uobject,
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

int uverbs_free_srq(struct ib_uobject *uobject,
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

int uverbs_free_cq(struct ib_uobject *uobject,
		   enum rdma_remove_reason why)
{
	struct ib_cq *cq = uobject->object;
	struct ib_uverbs_event_file *ev_file = cq->cq_context;
	struct ib_ucq_object *ucq =
		container_of(uobject, struct ib_ucq_object, uobject);
	int ret;

	ret = ib_destroy_cq(cq);
	if (!ret || why != RDMA_REMOVE_DESTROY)
		ib_uverbs_release_ucq(uobject->context->ufile, ev_file ?
				      container_of(ev_file,
						   struct ib_uverbs_completion_event_file,
						   ev_file) : NULL,
				      ucq);
	return ret;
}

int uverbs_free_mr(struct ib_uobject *uobject,
		   enum rdma_remove_reason why)
{
	return ib_dereg_mr((struct ib_mr *)uobject->object);
}

int uverbs_free_xrcd(struct ib_uobject *uobject,
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

int uverbs_free_pd(struct ib_uobject *uobject,
		   enum rdma_remove_reason why)
{
	struct ib_pd *pd = uobject->object;

	if (why == RDMA_REMOVE_DESTROY && atomic_read(&pd->usecnt))
		return -EBUSY;

	ib_dealloc_pd((struct ib_pd *)uobject->object);
	return 0;
}

int uverbs_hot_unplug_completion_event_file(struct ib_uobject_file *uobj_file,
					    enum rdma_remove_reason why)
{
	struct ib_uverbs_completion_event_file *comp_event_file =
		container_of(uobj_file, struct ib_uverbs_completion_event_file,
			     uobj_file);
	struct ib_uverbs_event_file *event_file = &comp_event_file->ev_file;

	spin_lock_irq(&event_file->lock);
	event_file->is_closed = 1;
	spin_unlock_irq(&event_file->lock);

	if (why == RDMA_REMOVE_DRIVER_REMOVE) {
		wake_up_interruptible(&event_file->poll_wait);
		kill_fasync(&event_file->async_queue, SIGIO, POLL_IN);
	}
	return 0;
};

DECLARE_UVERBS_ATTR_SPEC(
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
	void * __user inbuf;
	size_t inbuf_len = 0;
	void * __user outbuf;
	size_t outbuf_len = 0;

	if (num >= UVERBS_UHW_NUM) {
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

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_get_context_spec,
	UVERBS_ATTR_PTR_OUT(GET_CONTEXT_RESP,
			    struct ib_uverbs_get_context_resp));

int uverbs_get_context(struct ib_device *ib_dev,
		       struct ib_uverbs_file *file,
		       struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_udata uhw;
	struct ib_uverbs_get_context_resp resp;
	struct ib_ucontext		 *ucontext;
	struct file			 *filp;
	int ret;

	if (!uverbs_is_valid(common, GET_CONTEXT_RESP))
		return -EINVAL;

	/* Temporary, only until drivers get the new uverbs_attr_array */
	create_udata(ctx, num, &uhw);

	mutex_lock(&file->mutex);

	if (file->ucontext) {
		ret = -EINVAL;
		goto err;
	}

	ucontext = ib_dev->alloc_ucontext(ib_dev, &uhw);
	if (IS_ERR(ucontext)) {
		ret = PTR_ERR(ucontext);
		goto err;
	}

	ucontext->device = ib_dev;
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

err_free:
	put_pid(ucontext->tgid);
	ib_dev->dealloc_ucontext(ucontext);
err:
	mutex_unlock(&file->mutex);
	return ret;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_query_device_spec,
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_RESP, struct ib_uverbs_query_device_resp),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_ODP, struct ib_uverbs_odp_caps),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_TIMESTAMP_MASK, u64),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_HCA_CORE_CLOCK, u64),
	UVERBS_ATTR_PTR_OUT(QUERY_DEVICE_CAP_FLAGS, u64));

int uverbs_query_device_handler(struct ib_device *ib_dev,
				struct ib_uverbs_file *file,
				struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_device_attr attr = {};
	struct ib_udata uhw;
	int err;

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

	return 0;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_query_port_spec,
	UVERBS_ATTR_PTR_IN(QUERY_PORT_PORT_NUM, __u8),
	UVERBS_ATTR_PTR_OUT(QUERY_PORT_RESP, struct ib_uverbs_query_port_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_query_port_handler(struct ib_device *ib_dev,
			      struct ib_uverbs_file *file,
			      struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uverbs_query_port_resp resp = {};
	struct ib_port_attr              attr;
	u8				 port_num;
	int				 ret;

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

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_alloc_pd_spec,
	UVERBS_ATTR_IDR(ALLOC_PD_HANDLE, UVERBS_TYPE_PD,
			UVERBS_ACCESS_NEW,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_alloc_pd_handler(struct ib_device *ib_dev,
			    struct ib_uverbs_file *file,
			    struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_ucontext *ucontext = file->ucontext;
	struct ib_udata uhw;
	struct ib_uobject *uobject;
	struct ib_pd *pd;

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

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_dealloc_pd_spec,
	UVERBS_ATTR_IDR(DEALLOC_PD_HANDLE, UVERBS_TYPE_PD,
			UVERBS_ACCESS_DESTROY,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_dealloc_pd_handler(struct ib_device *ib_dev,
			      struct ib_uverbs_file *file,
			      struct uverbs_attr_array *ctx, size_t num)
{
	return 0;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_reg_mr_spec,
	UVERBS_ATTR_IDR(REG_MR_HANDLE, UVERBS_TYPE_MR, UVERBS_ACCESS_NEW,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_IDR(REG_MR_PD_HANDLE, UVERBS_TYPE_PD, UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(REG_MR_CMD, struct ib_uverbs_ioctl_reg_mr,
			   UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_OUT(REG_MR_RESP, struct ib_uverbs_ioctl_reg_mr_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_reg_mr_handler(struct ib_device *ib_dev,
			  struct ib_uverbs_file *file,
			  struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uverbs_ioctl_reg_mr		cmd;
	struct ib_uverbs_ioctl_reg_mr_resp	resp;
	struct ib_udata uhw;
	struct ib_uobject *uobject;
	struct ib_pd                *pd;
	struct ib_mr                *mr;
	int                          ret;

	if (uverbs_copy_from(&cmd, common, REG_MR_CMD))
		return -EFAULT;

	if ((cmd.start & ~PAGE_MASK) != (cmd.hca_va & ~PAGE_MASK))
		return -EINVAL;

	ret = ib_check_mr_access(cmd.access_flags);
	if (ret)
		return ret;

	/* Temporary, only until drivers get the new uverbs_attr_array */
	create_udata(ctx, num, &uhw);

	uobject = common->attrs[REG_MR_HANDLE].obj_attr.uobject;
	pd = common->attrs[REG_MR_PD_HANDLE].obj_attr.uobject->object;

	if (cmd.access_flags & IB_ACCESS_ON_DEMAND) {
		if (!(pd->device->attrs.device_cap_flags &
		      IB_DEVICE_ON_DEMAND_PAGING)) {
			pr_debug("ODP support not available\n");
			return -EINVAL;
		}
	}

	mr = pd->device->reg_user_mr(pd, cmd.start, cmd.length, cmd.hca_va,
				     cmd.access_flags, &uhw);
	if (IS_ERR(mr))
		return PTR_ERR(mr);

	mr->device  = pd->device;
	mr->pd      = pd;
	mr->uobject = uobject;
	atomic_inc(&pd->usecnt);
	uobject->object = mr;

	resp.lkey      = mr->lkey;
	resp.rkey      = mr->rkey;

	if (uverbs_copy_to(common, REG_MR_RESP, &resp)) {
		ret = -EFAULT;
		goto err;
	}

	return 0;

err:
	ib_dereg_mr(mr);
	return ret;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_rereg_mr_spec,
	UVERBS_ATTR_IDR(REREG_MR_HANDLE, UVERBS_TYPE_MR, UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_IDR(REREG_MR_PD_HANDLE, UVERBS_TYPE_PD, UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(REREG_MR_CMD, struct ib_uverbs_rereg_mr,
			   UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_OUT(REG_MR_RESP, struct ib_uverbs_rereg_mr_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_rereg_mr_handler(struct ib_device *ib_dev,
			    struct ib_uverbs_file *file,
			    struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];

	struct ib_udata                 udata;
	struct ib_uverbs_rereg_mr       cmd;
	struct ib_uverbs_rereg_mr_resp  resp;
	struct ib_mr                    *mr;
	struct ib_pd                    *pd = NULL;
	struct ib_pd                    *old_pd;
	int                             ret;

	if (uverbs_copy_from(&cmd, common, REREG_MR_CMD))
		return -EFAULT;

	if (cmd.flags & ~IB_MR_REREG_SUPPORTED || !cmd.flags)
		return -EINVAL;

	if ((cmd.flags & IB_MR_REREG_TRANS) &&
	    (!cmd.start || !cmd.hca_va || 0 >= cmd.length ||
	     (cmd.start & ~PAGE_MASK) != (cmd.hca_va & ~PAGE_MASK)))
		return -EINVAL;

	INIT_UDATA(&udata, &cmd, &resp,
		   sizeof(struct ib_uverbs_rereg_mr),
		   sizeof(struct ib_uverbs_rereg_mr_resp));

	mr = common->attrs[REREG_MR_HANDLE].obj_attr.uobject->object;
	pd = common->attrs[REREG_MR_PD_HANDLE].obj_attr.uobject->object;

	if (cmd.flags & IB_MR_REREG_ACCESS) {
		ret = ib_check_mr_access(cmd.access_flags);
		if (ret)
			return -EFAULT;
	}

	old_pd = mr->pd;
	ret = mr->device->rereg_user_mr(mr, cmd.flags, cmd.start,
					cmd.length, cmd.hca_va,
					cmd.access_flags, pd, &udata);
	if (!ret) {
		if (cmd.flags & IB_MR_REREG_PD) {
			atomic_inc(&pd->usecnt);
			mr->pd = pd;
			atomic_dec(&old_pd->usecnt);
		}
	} else
		return -EFAULT;

	memset(&resp, 0, sizeof(resp));
	resp.lkey      = mr->lkey;
	resp.rkey      = mr->rkey;

	if (uverbs_copy_to(common, REREG_MR_RESP, &resp))
		return -EFAULT;

	return 0;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_dereg_mr_spec,
	UVERBS_ATTR_IDR(DEREG_MR_HANDLE, UVERBS_TYPE_MR, UVERBS_ACCESS_DESTROY,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_dereg_mr_handler(struct ib_device *ib_dev,
			    struct ib_uverbs_file *file,
			    struct uverbs_attr_array *ctx, size_t num)
{
	return 0;
};

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_create_comp_channel_spec,
	UVERBS_ATTR_FD(CREATE_COMP_CHANNEL_FD, UVERBS_TYPE_COMP_CHANNEL,
		       UVERBS_ACCESS_NEW,
		       UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_create_comp_channel_handler(struct ib_device *ib_dev,
				       struct ib_uverbs_file *file,
				       struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uverbs_completion_event_file *ev_file;
	struct ib_uobject *uobj =
		common->attrs[CREATE_COMP_CHANNEL_FD].obj_attr.uobject;

	kref_get(&uobj->ref);
	ev_file = container_of(uobj,
			       struct ib_uverbs_completion_event_file,
			       uobj_file.uobj);
	ib_uverbs_init_event_file(&ev_file->ev_file);

	return 0;
}

DECLARE_UVERBS_ATTR_SPEC(
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

int uverbs_create_cq_handler(struct ib_device *ib_dev,
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
		kref_get(&ev_file_uobj->ref);
	}

	if (attr.comp_vector >= ucontext->ufile->device->num_comp_vectors)
		return -EINVAL;

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
	if (IS_ERR(cq))
		return PTR_ERR(cq);

	cq->device        = ib_dev;
	cq->uobject       = &obj->uobject;
	cq->comp_handler  = ib_uverbs_comp_handler;
	cq->event_handler = ib_uverbs_cq_event_handler;
	cq->cq_context    = &ev_file->ev_file;
	obj->uobject.object = cq;
	obj->uobject.user_handle = user_handle;
	atomic_set(&cq->usecnt, 0);

	ret = uverbs_copy_to(common, CREATE_CQ_RESP_CQE, &cq->cqe);
	if (ret)
		goto err;

	return 0;
err:
	ib_destroy_cq(cq);
	return ret;
};

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_destroy_cq_spec,
	UVERBS_ATTR_IDR(DESTROY_CQ_HANDLE, UVERBS_TYPE_CQ,
			UVERBS_ACCESS_DESTROY,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_OUT(DESTROY_CQ_RESP, struct ib_uverbs_destroy_cq_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_destroy_cq_handler(struct ib_device *ib_dev,
			      struct ib_uverbs_file *file,
			      struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uverbs_destroy_cq_resp resp;
	struct ib_uobject *uobj =
		common->attrs[DESTROY_CQ_HANDLE].obj_attr.uobject;
	struct ib_ucq_object *obj = container_of(uobj, struct ib_ucq_object,
						 uobject);

	resp.comp_events_reported  = obj->comp_events_reported;
	resp.async_events_reported = obj->async_events_reported;

	WARN_ON(uverbs_copy_to(common, DESTROY_CQ_RESP, &resp));
	return 0;
}

static int qp_fill_attrs(struct ib_qp_init_attr *attr, struct ib_ucontext *ctx,
			 const struct ib_uverbs_ioctl_create_qp *cmd,
			 u32 create_flags)
{
	if (create_flags & ~(IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK |
			     IB_QP_CREATE_CROSS_CHANNEL |
			     IB_QP_CREATE_MANAGED_SEND |
			     IB_QP_CREATE_MANAGED_RECV |
			     IB_QP_CREATE_SCATTER_FCS))
		return -EINVAL;

	attr->create_flags = create_flags;
	attr->event_handler = ib_uverbs_qp_event_handler;
	attr->qp_context = ctx->ufile;
	attr->sq_sig_type = cmd->sq_sig_all ? IB_SIGNAL_ALL_WR :
		IB_SIGNAL_REQ_WR;
	attr->qp_type = cmd->qp_type;

	attr->cap.max_send_wr     = cmd->max_send_wr;
	attr->cap.max_recv_wr     = cmd->max_recv_wr;
	attr->cap.max_send_sge    = cmd->max_send_sge;
	attr->cap.max_recv_sge    = cmd->max_recv_sge;
	attr->cap.max_inline_data = cmd->max_inline_data;

	return 0;
}

static void qp_init_uqp(struct ib_uqp_object *obj)
{
	obj->uevent.events_reported     = 0;
	INIT_LIST_HEAD(&obj->uevent.event_list);
	INIT_LIST_HEAD(&obj->mcast_list);
}

static int qp_write_resp(const struct ib_qp_init_attr *attr,
			 const struct ib_qp *qp,
			 struct uverbs_attr_array *common)
{
	struct ib_uverbs_ioctl_create_qp_resp resp = {
		.qpn = qp->qp_num,
		.max_recv_sge    = attr->cap.max_recv_sge,
		.max_send_sge    = attr->cap.max_send_sge,
		.max_recv_wr     = attr->cap.max_recv_wr,
		.max_send_wr     = attr->cap.max_send_wr,
		.max_inline_data = attr->cap.max_inline_data};

	return uverbs_copy_to(common, CREATE_QP_RESP, &resp);
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_create_qp_spec,
	UVERBS_ATTR_IDR(CREATE_QP_HANDLE, UVERBS_TYPE_QP, UVERBS_ACCESS_NEW,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_IDR(CREATE_QP_PD_HANDLE, UVERBS_TYPE_PD, UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_IDR(CREATE_QP_SEND_CQ, UVERBS_TYPE_CQ, UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_IDR(CREATE_QP_RECV_CQ, UVERBS_TYPE_CQ, UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_IDR(CREATE_QP_SRQ, UVERBS_TYPE_SRQ, UVERBS_ACCESS_READ),
	UVERBS_ATTR_PTR_IN(CREATE_QP_USER_HANDLE, u64),
	UVERBS_ATTR_PTR_IN(CREATE_QP_CMD, struct ib_uverbs_ioctl_create_qp),
	UVERBS_ATTR_PTR_IN(CREATE_QP_CMD_FLAGS, u32),
	UVERBS_ATTR_PTR_OUT(CREATE_QP_RESP, struct ib_uverbs_ioctl_create_qp_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_create_qp_handler(struct ib_device *ib_dev,
			     struct ib_uverbs_file *file,
			     struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_ucontext *ucontext = file->ucontext;
	struct ib_uqp_object           *obj;
	struct ib_udata uhw;
	int ret;
	u64 user_handle = 0;
	u32 create_flags = 0;
	struct ib_uverbs_ioctl_create_qp cmd;
	struct ib_qp_init_attr attr = {};
	struct ib_qp                   *qp;
	struct ib_pd			*pd;

	ret = uverbs_copy_from(&cmd, common, CREATE_QP_CMD);
	if (ret)
		return ret;

	/* Optional params */
	if (uverbs_copy_from(&create_flags, common, CREATE_QP_CMD_FLAGS) == -EFAULT ||
	    uverbs_copy_from(&user_handle, common, CREATE_QP_USER_HANDLE) == -EFAULT)
		return -EFAULT;

	if (cmd.qp_type == IB_QPT_XRC_INI) {
		cmd.max_recv_wr = 0;
		cmd.max_recv_sge = 0;
	}

	ret = qp_fill_attrs(&attr, ucontext, &cmd, create_flags);
	if (ret)
		return ret;

	pd = common->attrs[CREATE_QP_PD_HANDLE].obj_attr.uobject->object;
	attr.send_cq = common->attrs[CREATE_QP_SEND_CQ].obj_attr.uobject->object;
	attr.recv_cq = common->attrs[CREATE_QP_RECV_CQ].obj_attr.uobject->object;
	if (uverbs_is_valid(common, CREATE_QP_SRQ))
		attr.srq = common->attrs[CREATE_QP_SRQ].obj_attr.uobject->object;
	obj = (struct ib_uqp_object *)common->attrs[CREATE_QP_HANDLE].obj_attr.uobject;

	obj->uxrcd = NULL;
	if (attr.srq && attr.srq->srq_type != IB_SRQT_BASIC)
		return -EINVAL;

	qp_init_uqp(obj);
	create_udata(ctx, num, &uhw);
	qp = pd->device->create_qp(pd, &attr, &uhw);
	if (IS_ERR(qp))
		return PTR_ERR(qp);
	qp->real_qp	  = qp;
	qp->device	  = pd->device;
	qp->pd		  = pd;
	qp->send_cq	  = attr.send_cq;
	qp->recv_cq	  = attr.recv_cq;
	qp->srq		  = attr.srq;
	qp->event_handler = attr.event_handler;
	qp->qp_context	  = attr.qp_context;
	qp->qp_type	  = attr.qp_type;
	atomic_set(&qp->usecnt, 0);
	atomic_inc(&pd->usecnt);
	atomic_inc(&attr.send_cq->usecnt);
	if (attr.recv_cq)
		atomic_inc(&attr.recv_cq->usecnt);
	if (attr.srq)
		atomic_inc(&attr.srq->usecnt);
	qp->uobject = &obj->uevent.uobject;
	obj->uevent.uobject.object = qp;
	obj->uevent.uobject.user_handle = user_handle;

	ret = qp_write_resp(&attr, qp, common);
	if (ret) {
		ib_destroy_qp(qp);
		return ret;
	}

	return 0;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_create_qp_xrc_tgt_spec,
	UVERBS_ATTR_IDR(CREATE_QP_XRC_TGT_HANDLE, UVERBS_TYPE_QP, UVERBS_ACCESS_NEW,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_IDR(CREATE_QP_XRC_TGT_XRCD, UVERBS_TYPE_XRCD, UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(CREATE_QP_XRC_TGT_USER_HANDLE, u64),
	UVERBS_ATTR_PTR_IN(CREATE_QP_XRC_TGT_CMD, struct ib_uverbs_ioctl_create_qp),
	UVERBS_ATTR_PTR_IN(CREATE_QP_XRC_TGT_CMD_FLAGS, u32),
	UVERBS_ATTR_PTR_OUT(CREATE_QP_XRC_TGT_RESP, struct ib_uverbs_ioctl_create_qp_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_create_qp_xrc_tgt_handler(struct ib_device *ib_dev,
				     struct ib_uverbs_file *file,
				     struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_ucontext *ucontext = file->ucontext;
	struct ib_uqp_object           *obj;
	int ret;
	u64 user_handle = 0;
	u32 create_flags = 0;
	struct ib_uverbs_ioctl_create_qp cmd;
	struct ib_qp_init_attr attr = {};
	struct ib_qp                   *qp;

	ret = uverbs_copy_from(&cmd, common, CREATE_QP_XRC_TGT_CMD);
	if (ret)
		return ret;

	/* Optional params */
	if (uverbs_copy_from(&create_flags, common, CREATE_QP_CMD_FLAGS) == -EFAULT ||
	    uverbs_copy_from(&user_handle, common, CREATE_QP_USER_HANDLE) == -EFAULT)
		return -EFAULT;

	ret = qp_fill_attrs(&attr, ucontext, &cmd, create_flags);
	if (ret)
		return ret;

	obj = (struct ib_uqp_object *)common->attrs[CREATE_QP_HANDLE].obj_attr.uobject;
	obj->uxrcd = container_of(common->attrs[CREATE_QP_XRC_TGT_XRCD].obj_attr.uobject,
				  struct ib_uxrcd_object, uobject);
	attr.xrcd = obj->uxrcd->uobject.object;

	qp_init_uqp(obj);
	qp = ib_create_qp(NULL, &attr);
	if (IS_ERR(qp))
		return PTR_ERR(qp);
	qp->uobject = &obj->uevent.uobject;
	obj->uevent.uobject.object = qp;
	obj->uevent.uobject.user_handle = user_handle;
	atomic_inc(&obj->uxrcd->refcnt);

	ret = qp_write_resp(&attr, qp, common);
	if (ret) {
		ib_destroy_qp(qp);
		return ret;
	}

	return 0;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_destroy_qp_spec,
	UVERBS_ATTR_IDR(DESTROY_QP_HANDLE, UVERBS_TYPE_QP,
			UVERBS_ACCESS_DESTROY,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_OUT(DESTROY_QP_EVENTS_REPORTED,
			    __u32,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_destroy_qp_handler(struct ib_device *ib_dev,
			      struct ib_uverbs_file *file,
			      struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_uobject *uobj =
		common->attrs[DESTROY_QP_HANDLE].obj_attr.uobject;
	struct ib_uqp_object *obj = container_of(uobj, struct ib_uqp_object,
						 uevent.uobject);

	WARN_ON(uverbs_copy_to(common, DESTROY_QP_EVENTS_REPORTED,
			       &obj->uevent.events_reported));
	return 0;
}

DECLARE_UVERBS_ATTR_SPEC(
	uverbs_modify_qp_spec,
	UVERBS_ATTR_IDR(MODIFY_QP_HANDLE, UVERBS_TYPE_QP, UVERBS_ACCESS_WRITE,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_STATE, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_CUR_STATE, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_EN_SQD_ASYNC_NOTIFY, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_ACCESS_FLAGS, u32),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_PKEY_INDEX, u16),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_PORT, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_QKEY, u32),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_AV, struct ib_uverbs_qp_dest),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_PATH_MTU, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_TIMEOUT, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_RETRY_CNT, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_RNR_RETRY, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_RQ_PSN, u32),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_MAX_RD_ATOMIC, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_ALT_PATH, struct ib_uverbs_qp_alt_path),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_MIN_RNR_TIMER, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_SQ_PSN, u32),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_MAX_DEST_RD_ATOMIC, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_PATH_MIG_STATE, u8),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_DEST_QPN, u32),
	UVERBS_ATTR_PTR_IN(MODIFY_QP_RATE_LIMIT, u32));

int uverbs_modify_qp_handler(struct ib_device *ib_dev,
			     struct ib_uverbs_file *file,
			     struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_udata            uhw;
	struct ib_qp              *qp;
	struct ib_qp_attr         *attr;
	struct ib_uverbs_qp_dest  av;
	struct ib_uverbs_qp_alt_path alt_path;
	u32 attr_mask = 0;
	int ret = 0;

	qp = common->attrs[MODIFY_QP_HANDLE].obj_attr.uobject->object;
	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return -ENOMEM;

#define MODIFY_QP_CPY(_param, _fld, _attr)				\
	({								\
		int ret = uverbs_copy_from(_fld, common, _param);	\
		if (!ret)						\
			attr_mask |= _attr;				\
		ret == -EFAULT ? ret : 0;				\
	})

	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_STATE, &attr->qp_state,
				   IB_QP_STATE);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_CUR_STATE, &attr->cur_qp_state,
				   IB_QP_CUR_STATE);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_EN_SQD_ASYNC_NOTIFY,
				   &attr->en_sqd_async_notify,
				   IB_QP_EN_SQD_ASYNC_NOTIFY);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_ACCESS_FLAGS,
				   &attr->qp_access_flags, IB_QP_ACCESS_FLAGS);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_PKEY_INDEX, &attr->pkey_index,
				   IB_QP_PKEY_INDEX);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_PORT, &attr->port_num, IB_QP_PORT);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_QKEY, &attr->qkey, IB_QP_QKEY);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_PATH_MTU, &attr->path_mtu,
				   IB_QP_PATH_MTU);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_TIMEOUT, &attr->timeout,
				   IB_QP_TIMEOUT);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_RETRY_CNT, &attr->retry_cnt,
				   IB_QP_RETRY_CNT);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_RNR_RETRY, &attr->rnr_retry,
				   IB_QP_RNR_RETRY);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_RQ_PSN, &attr->rq_psn,
				   IB_QP_RQ_PSN);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_MAX_RD_ATOMIC,
				   &attr->max_rd_atomic,
				   IB_QP_MAX_QP_RD_ATOMIC);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_MIN_RNR_TIMER,
				   &attr->min_rnr_timer, IB_QP_MIN_RNR_TIMER);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_SQ_PSN, &attr->sq_psn,
				   IB_QP_SQ_PSN);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_MAX_DEST_RD_ATOMIC,
				   &attr->max_dest_rd_atomic,
				   IB_QP_MAX_DEST_RD_ATOMIC);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_PATH_MIG_STATE,
				   &attr->path_mig_state, IB_QP_PATH_MIG_STATE);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_DEST_QPN, &attr->dest_qp_num,
				   IB_QP_DEST_QPN);
	ret = ret ?: MODIFY_QP_CPY(MODIFY_QP_RATE_LIMIT, &attr->rate_limit,
				   IB_QP_RATE_LIMIT);

	if (ret)
		goto err;

	ret = uverbs_copy_from(&av, common, MODIFY_QP_AV);
	if (!ret) {
		attr_mask |= IB_QP_AV;
		memcpy(attr->ah_attr.grh.dgid.raw, av.dgid, 16);
		attr->ah_attr.grh.flow_label        = av.flow_label;
		attr->ah_attr.grh.sgid_index        = av.sgid_index;
		attr->ah_attr.grh.hop_limit         = av.hop_limit;
		attr->ah_attr.grh.traffic_class     = av.traffic_class;
		attr->ah_attr.dlid		    = av.dlid;
		attr->ah_attr.sl		    = av.sl;
		attr->ah_attr.src_path_bits	    = av.src_path_bits;
		attr->ah_attr.static_rate	    = av.static_rate;
		attr->ah_attr.ah_flags		    = av.is_global ? IB_AH_GRH : 0;
		attr->ah_attr.port_num		    = av.port_num;
	} else if (ret == -EFAULT) {
		goto err;
	}

	ret = uverbs_copy_from(&alt_path, common, MODIFY_QP_ALT_PATH);
	if (!ret) {
		attr_mask |= IB_QP_ALT_PATH;
		memcpy(attr->alt_ah_attr.grh.dgid.raw, alt_path.dest.dgid, 16);
		attr->alt_ah_attr.grh.flow_label    = alt_path.dest.flow_label;
		attr->alt_ah_attr.grh.sgid_index    = alt_path.dest.sgid_index;
		attr->alt_ah_attr.grh.hop_limit     = alt_path.dest.hop_limit;
		attr->alt_ah_attr.grh.traffic_class = alt_path.dest.traffic_class;
		attr->alt_ah_attr.dlid		    = alt_path.dest.dlid;
		attr->alt_ah_attr.sl		    = alt_path.dest.sl;
		attr->alt_ah_attr.src_path_bits     = alt_path.dest.src_path_bits;
		attr->alt_ah_attr.static_rate       = alt_path.dest.static_rate;
		attr->alt_ah_attr.ah_flags	    = alt_path.dest.is_global ? IB_AH_GRH : 0;
		attr->alt_ah_attr.port_num	    = alt_path.dest.port_num;
		attr->alt_pkey_index		    = alt_path.pkey_index;
		attr->alt_port_num		    = alt_path.port_num;
		attr->alt_timeout		    = alt_path.timeout;
	} else if (ret == -EFAULT) {
		goto err;
	}

	create_udata(ctx, num, &uhw);

	if (qp->real_qp == qp) {
		if (attr_mask & IB_QP_AV) {
			ret = ib_resolve_eth_dmac(qp->device, &attr->ah_attr);
			if (ret)
				goto err;
		}
		ret = qp->device->modify_qp(qp, attr,
					    modify_qp_mask(qp->qp_type,
							   attr_mask),
					    &uhw);
	} else {
		ret = ib_modify_qp(qp, attr, modify_qp_mask(qp->qp_type,
							    attr_mask));
	}

	if (ret)
		goto err;

	return 0;
err:
	kfree(attr);
	return ret;
}


DECLARE_UVERBS_ATTR_SPEC(
	uverbs_query_qp_spec, 
	UVERBS_ATTR_IDR(QUERY_QP_HANDLE,
			UVERBS_TYPE_QP,
			UVERBS_ACCESS_READ,
			UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_IN(QUERY_QP_ATTR_MASK, u32), 
	UVERBS_ATTR_PTR_OUT(QUERY_QP_RESP,
			    struct ib_uverbs_query_qp_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

int uverbs_query_qp_handler(struct ib_device *ib_dev,
			      struct ib_uverbs_file *file,
			      struct uverbs_attr_array *ctx, size_t num)
{
	struct uverbs_attr_array *common = &ctx[0];
	struct ib_qp              *qp;
	u32 attr_mask = 0;
	int ret;

	struct ib_qp_attr              *attr;
	struct ib_qp_init_attr         *init_attr;
	struct ib_uverbs_query_qp_resp resp;

	printk("--->%s():%d\n", __func__, __LINE__);

	attr      = kmalloc(sizeof *attr, GFP_KERNEL);
	init_attr = kmalloc(sizeof *init_attr, GFP_KERNEL);
	if (!attr || !init_attr)
		return -ENOMEM;

	uverbs_copy_from(&attr_mask, common, QUERY_QP_ATTR_MASK); 
	qp = common->attrs[QUERY_QP_HANDLE].obj_attr.uobject->object;

	ret = ib_query_qp(qp, attr, attr_mask, init_attr); 
	memset(&resp, 0, sizeof resp);

	resp.qp_state               = attr->qp_state;
	resp.cur_qp_state           = attr->cur_qp_state;
	resp.path_mtu               = attr->path_mtu;
	resp.path_mig_state         = attr->path_mig_state;
	resp.qkey                   = attr->qkey;
	resp.rq_psn                 = attr->rq_psn;
	resp.sq_psn                 = attr->sq_psn;
	resp.dest_qp_num            = attr->dest_qp_num;
	resp.qp_access_flags        = attr->qp_access_flags;
	resp.pkey_index             = attr->pkey_index;
	resp.alt_pkey_index         = attr->alt_pkey_index;
	resp.sq_draining            = attr->sq_draining;
	resp.max_rd_atomic          = attr->max_rd_atomic;
	resp.max_dest_rd_atomic     = attr->max_dest_rd_atomic;
	resp.min_rnr_timer          = attr->min_rnr_timer;
	resp.port_num               = attr->port_num;
	resp.timeout                = attr->timeout;
	resp.retry_cnt              = attr->retry_cnt;
	resp.rnr_retry              = attr->rnr_retry;
	resp.alt_port_num           = attr->alt_port_num;
	resp.alt_timeout            = attr->alt_timeout;

	memcpy(resp.dest.dgid, attr->ah_attr.grh.dgid.raw, 16);
	resp.dest.flow_label        = attr->ah_attr.grh.flow_label;
	resp.dest.sgid_index        = attr->ah_attr.grh.sgid_index;
	resp.dest.hop_limit         = attr->ah_attr.grh.hop_limit;
	resp.dest.traffic_class     = attr->ah_attr.grh.traffic_class;
	resp.dest.dlid              = attr->ah_attr.dlid;
	resp.dest.sl                = attr->ah_attr.sl;
	resp.dest.src_path_bits     = attr->ah_attr.src_path_bits;
	resp.dest.static_rate       = attr->ah_attr.static_rate;
	resp.dest.is_global         = !!(attr->ah_attr.ah_flags & IB_AH_GRH);
	resp.dest.port_num          = attr->ah_attr.port_num;

	memcpy(resp.alt_dest.dgid, attr->alt_ah_attr.grh.dgid.raw, 16);
	resp.alt_dest.flow_label    = attr->alt_ah_attr.grh.flow_label;
	resp.alt_dest.sgid_index    = attr->alt_ah_attr.grh.sgid_index;
	resp.alt_dest.hop_limit     = attr->alt_ah_attr.grh.hop_limit;
	resp.alt_dest.traffic_class = attr->alt_ah_attr.grh.traffic_class;
	resp.alt_dest.dlid          = attr->alt_ah_attr.dlid;
	resp.alt_dest.sl            = attr->alt_ah_attr.sl;
	resp.alt_dest.src_path_bits = attr->alt_ah_attr.src_path_bits;
	resp.alt_dest.static_rate   = attr->alt_ah_attr.static_rate;
	resp.alt_dest.is_global     = !!(attr->alt_ah_attr.ah_flags & IB_AH_GRH);
	resp.alt_dest.port_num      = attr->alt_ah_attr.port_num;

	resp.max_send_wr            = init_attr->cap.max_send_wr;
	resp.max_recv_wr            = init_attr->cap.max_recv_wr;
	resp.max_send_sge           = init_attr->cap.max_send_sge;
	resp.max_recv_sge           = init_attr->cap.max_recv_sge;
	resp.max_inline_data        = init_attr->cap.max_inline_data;
	resp.sq_sig_all             = init_attr->sq_sig_type == IB_SIGNAL_ALL_WR;


	if (uverbs_copy_to(common, QUERY_QP_RESP, &resp))
		return -EFAULT; 

	return 0;
}

DECLARE_UVERBS_TYPE(uverbs_type_comp_channel,
		    &UVERBS_TYPE_ALLOC_FD(0, sizeof(struct ib_uverbs_completion_event_file),
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
					      uverbs_free_qp),
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_QP_CREATE,
					  uverbs_create_qp_handler,
					  &uverbs_create_qp_spec,
					  &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_QP_CREATE_XRC_TGT,
					  uverbs_create_qp_xrc_tgt_handler,
					  &uverbs_create_qp_xrc_tgt_spec),
			ADD_UVERBS_ACTION(UVERBS_QP_MODIFY,
					  uverbs_modify_qp_handler,
					  &uverbs_modify_qp_spec,
					  &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_QP_DESTROY,
					  uverbs_destroy_qp_handler,
					  &uverbs_destroy_qp_spec),
			ADD_UVERBS_ACTION(UVERBS_QP_QUERY,
					  uverbs_query_qp_handler,
					  &uverbs_query_qp_spec)));

DECLARE_UVERBS_TYPE(uverbs_type_mw,
		    &UVERBS_TYPE_ALLOC_IDR(0, uverbs_free_mw));

DECLARE_UVERBS_TYPE(uverbs_type_mr,
		    /* 1 is used in order to free the MR after all the MWs */
		    &UVERBS_TYPE_ALLOC_IDR(1, uverbs_free_mr),
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_MR_REG, uverbs_reg_mr_handler,
					  &uverbs_reg_mr_spec,
					  &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_MR_DEREG,
					  uverbs_dereg_mr_handler,
					  &uverbs_dereg_mr_spec),
			ADD_UVERBS_ACTION(UVERBS_MR_REREG,
					  uverbs_rereg_mr_handler,
					  &uverbs_rereg_mr_spec)));

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
					  uverbs_dealloc_pd_handler,
					  &uverbs_dealloc_pd_spec)));

DECLARE_UVERBS_TYPE(uverbs_type_device, NULL,
		    &UVERBS_ACTIONS(
			ADD_UVERBS_CTX_ACTION(UVERBS_DEVICE_ALLOC_CONTEXT,
					      uverbs_get_context,
					      &uverbs_get_context_spec,
					      &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_DEVICE_QUERY,
					  &uverbs_query_device_handler,
					  &uverbs_query_device_spec,
					  &uverbs_uhw_compat_spec),
			ADD_UVERBS_ACTION(UVERBS_DEVICE_PORT_QUERY,
					  &uverbs_query_port_handler,
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
