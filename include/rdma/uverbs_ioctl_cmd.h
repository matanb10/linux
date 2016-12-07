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

#ifndef _UVERBS_IOCTL_CMD_
#define _UVERBS_IOCTL_CMD_

#include <rdma/uverbs_ioctl.h>

#define IB_UVERBS_VENDOR_FLAG	0x8000

enum {
	UVERBS_UHW_IN,
	UVERBS_UHW_OUT,
};

int ib_uverbs_std_dist(__u16 *attr_id, void *priv);

/* common validators */

int uverbs_action_std_handle(struct ib_device *ib_dev,
			     struct ib_uverbs_file *ufile,
			     struct uverbs_attr_array *ctx, size_t num,
			     void *_priv);
int uverbs_action_std_ctx_handle(struct ib_device *ib_dev,
				 struct ib_uverbs_file *ufile,
				 struct uverbs_attr_array *ctx, size_t num,
				 void *_priv);

struct uverbs_action_std_handler {
	int (*handler)(struct ib_device *ib_dev, struct ib_ucontext *ucontext,
		       struct uverbs_attr_array *common,
		       struct uverbs_attr_array *vendor,
		       void *priv);
	void *priv;
};

struct uverbs_action_std_ctx_handler {
	int (*handler)(struct ib_device *ib_dev, struct ib_uverbs_file *ufile,
		       struct uverbs_attr_array *common,
		       struct uverbs_attr_array *vendor,
		       void *priv);
	void *priv;
};

void uverbs_free_ah(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_flow(const struct uverbs_type_alloc_action *type_alloc_action,
		      struct ib_uobject *uobject);
void uverbs_free_mw(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_qp(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_rwq_ind_tbl(const struct uverbs_type_alloc_action *type_alloc_action,
			     struct ib_uobject *uobject);
void uverbs_free_wq(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_srq(const struct uverbs_type_alloc_action *type_alloc_action,
		     struct ib_uobject *uobject);
void uverbs_free_cq(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_mr(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_xrcd(const struct uverbs_type_alloc_action *type_alloc_action,
		      struct ib_uobject *uobject);
void uverbs_free_pd(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_event_file(const struct uverbs_type_alloc_action *type_alloc_action,
			    struct ib_uobject *uobject);

enum uverbs_common_types {
	UVERBS_TYPE_DEVICE, /* Don't use IDRs here */
	UVERBS_TYPE_PD,
	UVERBS_TYPE_COMP_CHANNEL,
	UVERBS_TYPE_CQ,
	UVERBS_TYPE_QP,
	UVERBS_TYPE_SRQ,
	UVERBS_TYPE_AH,
	UVERBS_TYPE_MR,
	UVERBS_TYPE_MW,
	UVERBS_TYPE_FLOW,
	UVERBS_TYPE_XRCD,
	UVERBS_TYPE_RWQ_IND_TBL,
	UVERBS_TYPE_WQ,
	UVERBS_TYPE_LAST,
};

enum uverbs_create_qp_cmd_attr {
	CREATE_QP_HANDLE,
	CREATE_QP_PD_HANDLE,
	CREATE_QP_SEND_CQ,
	CREATE_QP_RECV_CQ,
	CREATE_QP_SRQ,
	CREATE_QP_USER_HANDLE,
	CREATE_QP_CMD,
	CREATE_QP_CMD_FLAGS,
	CREATE_QP_RESP
};

enum uverbs_create_cq_cmd_attr {
	CREATE_CQ_HANDLE,
	CREATE_CQ_CQE,
	CREATE_CQ_USER_HANDLE,
	CREATE_CQ_COMP_CHANNEL,
	CREATE_CQ_COMP_VECTOR,
	CREATE_CQ_FLAGS,
	CREATE_CQ_RESP_CQE,
};

enum uverbs_create_qp_xrc_tgt_cmd_attr {
	CREATE_QP_XRC_TGT_HANDLE,
	CREATE_QP_XRC_TGT_XRCD,
	CREATE_QP_XRC_TGT_USER_HANDLE,
	CREATE_QP_XRC_TGT_CMD,
	CREATE_QP_XRC_TGT_CMD_FLAGS,
	CREATE_QP_XRC_TGT_RESP
};

enum uverbs_modify_qp_cmd_attr {
	MODIFY_QP_HANDLE,
	MODIFY_QP_STATE,
	MODIFY_QP_CUR_STATE,
	MODIFY_QP_EN_SQD_ASYNC_NOTIFY,
	MODIFY_QP_ACCESS_FLAGS,
	MODIFY_QP_PKEY_INDEX,
	MODIFY_QP_PORT,
	MODIFY_QP_QKEY,
	MODIFY_QP_AV,
	MODIFY_QP_PATH_MTU,
	MODIFY_QP_TIMEOUT,
	MODIFY_QP_RETRY_CNT,
	MODIFY_QP_RNR_RETRY,
	MODIFY_QP_RQ_PSN,
	MODIFY_QP_MAX_RD_ATOMIC,
	MODIFY_QP_ALT_PATH,
	MODIFY_QP_MIN_RNR_TIMER,
	MODIFY_QP_SQ_PSN,
	MODIFY_QP_MAX_DEST_RD_ATOMIC,
	MODIFY_QP_PATH_MIG_STATE,
	MODIFY_QP_DEST_QPN
};

enum uverbs_create_comp_channel_cmd_attr {
	CREATE_COMP_CHANNEL_FD,
};

enum uverbs_get_context {
	GET_CONTEXT_RESP,
};

enum uverbs_query_device {
	QUERY_DEVICE_RESP,
	QUERY_DEVICE_ODP,
	QUERY_DEVICE_TIMESTAMP_MASK,
	QUERY_DEVICE_HCA_CORE_CLOCK,
	QUERY_DEVICE_CAP_FLAGS,
};

enum uverbs_alloc_pd {
	ALLOC_PD_HANDLE,
};

enum uverbs_reg_mr {
	REG_MR_HANDLE,
	REG_MR_PD_HANDLE,
	REG_MR_CMD,
	REG_MR_RESP
};

enum uverbs_dereg_mr {
	DEREG_MR_HANDLE,
};

extern const struct uverbs_attr_spec_group uverbs_uhw_compat_spec;
extern const struct uverbs_attr_spec_group uverbs_get_context_spec;
extern const struct uverbs_attr_spec_group uverbs_query_device_spec;
extern const struct uverbs_attr_spec_group uverbs_alloc_pd_spec;
extern const struct uverbs_attr_spec_group uverbs_reg_mr_spec;
extern const struct uverbs_attr_spec_group uverbs_dereg_mr_spec;

enum uverbs_actions_mr_ops {
	UVERBS_MR_REG,
	UVERBS_MR_DEREG,
};

extern const struct uverbs_action_group uverbs_actions_mr;

enum uverbs_actions_comp_channel_ops {
	UVERBS_COMP_CHANNEL_CREATE,
};

extern const struct uverbs_action_group uverbs_actions_comp_channel;

enum uverbs_actions_cq_ops {
	UVERBS_CQ_CREATE,
};

extern const struct uverbs_action_group uverbs_actions_cq;

enum uverbs_actions_qp_ops {
	UVERBS_QP_CREATE,
	UVERBS_QP_CREATE_XRC_TGT,
	UVERBS_QP_MODIFY,
};

extern const struct uverbs_action_group uverbs_actions_qp;

enum uverbs_actions_pd_ops {
	UVERBS_PD_ALLOC
};

extern const struct uverbs_action_group uverbs_actions_pd;

enum uverbs_actions_device_ops {
	UVERBS_DEVICE_ALLOC_CONTEXT,
	UVERBS_DEVICE_QUERY,
};

extern const struct uverbs_action_group uverbs_actions_device;

extern const struct uverbs_type uverbs_type_cq;
extern const struct uverbs_type uverbs_type_qp;
extern const struct uverbs_type uverbs_type_rwq_ind_table;
extern const struct uverbs_type uverbs_type_wq;
extern const struct uverbs_type uverbs_type_srq;
extern const struct uverbs_type uverbs_type_ah;
extern const struct uverbs_type uverbs_type_flow;
extern const struct uverbs_type uverbs_type_comp_channel;
extern const struct uverbs_type uverbs_type_mr;
extern const struct uverbs_type uverbs_type_mw;
extern const struct uverbs_type uverbs_type_pd;
extern const struct uverbs_type uverbs_type_xrcd;
extern const struct uverbs_type uverbs_type_device;

extern const struct uverbs_type_group uverbs_common_types;
#endif

