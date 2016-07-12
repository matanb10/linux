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

#ifndef _UVERBS_STD_TYPES__
#define _UVERBS_STD_TYPES__

#include <rdma/uverbs_types.h>

#define UVERBS_UDATA_DRIVER_DATA_GROUP	1
#define UVERBS_UDATA_DRIVER_DATA_FLAG	BIT(UVERBS_ID_RESERVED_SHIFT)

enum {
	UVERBS_UHW_IN,
	UVERBS_UHW_OUT,
	UVERBS_UHW_NUM
};

enum uverbs_common_types {
	UVERBS_TYPE_DEVICE, /* No instances of DEVICE are allowed */
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

enum uverbs_create_qp_cmd_attr_ids {
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

enum uverbs_destroy_qp_cmd_attr_ids {
	DESTROY_QP_HANDLE,
	DESTROY_QP_EVENTS_REPORTED,
};

enum uverbs_create_cq_cmd_attr_ids {
	CREATE_CQ_HANDLE,
	CREATE_CQ_CQE,
	CREATE_CQ_USER_HANDLE,
	CREATE_CQ_COMP_CHANNEL,
	CREATE_CQ_COMP_VECTOR,
	CREATE_CQ_FLAGS,
	CREATE_CQ_RESP_CQE,
};

enum uverbs_destroy_cq_cmd_attr_ids {
	DESTROY_CQ_HANDLE,
	DESTROY_CQ_RESP
};

enum uverbs_create_qp_xrc_tgt_cmd_attr_ids {
	CREATE_QP_XRC_TGT_HANDLE,
	CREATE_QP_XRC_TGT_XRCD,
	CREATE_QP_XRC_TGT_USER_HANDLE,
	CREATE_QP_XRC_TGT_CMD,
	CREATE_QP_XRC_TGT_CMD_FLAGS,
	CREATE_QP_XRC_TGT_RESP
};

enum uverbs_modify_qp_cmd_attr_ids {
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
	MODIFY_QP_DEST_QPN,
	MODIFY_QP_RATE_LIMIT,
};

enum uverbs_create_comp_channel_cmd_attr_ids {
	CREATE_COMP_CHANNEL_FD,
};

enum uverbs_get_context_cmd_attr_ids {
	GET_CONTEXT_RESP,
};

enum uverbs_query_device_cmd_attr_ids {
	QUERY_DEVICE_RESP,
	QUERY_DEVICE_ODP,
	QUERY_DEVICE_TIMESTAMP_MASK,
	QUERY_DEVICE_HCA_CORE_CLOCK,
	QUERY_DEVICE_CAP_FLAGS,
};

enum uverbs_query_port_cmd_attr_ids {
	QUERY_PORT_PORT_NUM,
	QUERY_PORT_RESP,
};

enum uverbs_alloc_pd_cmd_attr_ids {
	ALLOC_PD_HANDLE,
};

enum uverbs_dealloc_pd_cmd_attr_ids {
	DEALLOC_PD_HANDLE,
};

enum uverbs_reg_mr_cmd_attr_ids {
	REG_MR_HANDLE,
	REG_MR_PD_HANDLE,
	REG_MR_CMD,
	REG_MR_RESP
};

enum uverbs_dereg_mr_cmd_attr_ids {
	DEREG_MR_HANDLE,
};

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
	UVERBS_CQ_DESTROY,
};

extern const struct uverbs_action_group uverbs_actions_cq;

enum uverbs_actions_qp_ops {
	UVERBS_QP_CREATE,
	UVERBS_QP_CREATE_XRC_TGT,
	UVERBS_QP_MODIFY,
	UVERBS_QP_DESTROY,
};

extern const struct uverbs_action_group uverbs_actions_qp;

enum uverbs_actions_pd_ops {
	UVERBS_PD_ALLOC,
	UVERBS_PD_DEALLOC
};

extern const struct uverbs_action_group uverbs_actions_pd;

enum uverbs_actions_device_ops {
	UVERBS_DEVICE_ALLOC_CONTEXT,
	UVERBS_DEVICE_QUERY,
	UVERBS_DEVICE_PORT_QUERY,
};

extern const struct uverbs_action_group uverbs_actions_device;

extern const struct uverbs_type uverbs_type_comp_channel;
extern const struct uverbs_type uverbs_type_cq;
extern const struct uverbs_type uverbs_type_qp;
extern const struct uverbs_type uverbs_type_rwq_ind_table;
extern const struct uverbs_type uverbs_type_wq;
extern const struct uverbs_type uverbs_type_srq;
extern const struct uverbs_type uverbs_type_ah;
extern const struct uverbs_type uverbs_type_flow;
extern const struct uverbs_type uverbs_type_mr;
extern const struct uverbs_type uverbs_type_mw;
extern const struct uverbs_type uverbs_type_pd;
extern const struct uverbs_type uverbs_type_xrcd;
extern const struct uverbs_type uverbs_type_device;
extern const struct uverbs_type_group uverbs_common_types;
#endif

