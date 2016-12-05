#include <rdma/uverbs_ioctl.h>
#include <rdma/uverbs_ioctl_cmd.h>
#include <rdma/mlx5-abi.h>
#include "mlx5_ib.h"

DECLARE_UVERBS_ATTR_SPEC(
	mlx5_spec_create_qp,
	UVERBS_ATTR_PTR_IN_SZ(UVERBS_UHW_IN, 0,
			      UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ)),
	UVERBS_ATTR_PTR_OUT_SZ(UVERBS_UHW_OUT, 0,
			       UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ)));

DECLARE_UVERBS_ATTR_SPEC(
	mlx5_spec_create_cq,
	UVERBS_ATTR_PTR_IN_SZ(UVERBS_UHW_IN,
			      offsetof(struct mlx5_ib_create_cq, reserved),
			      UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY |
				       UVERBS_ATTR_SPEC_F_MIN_SZ)),
	UVERBS_ATTR_PTR_OUT(UVERBS_UHW_OUT, __u32,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

DECLARE_UVERBS_ATTR_SPEC(
	mlx5_spec_alloc_pd,
	UVERBS_ATTR_PTR_OUT(UVERBS_UHW_OUT, struct mlx5_ib_alloc_pd_resp,
			    UA_FLAGS(UVERBS_ATTR_SPEC_F_MANDATORY)));

DECLARE_UVERBS_ATTR_SPEC(
	mlx5_spec_device_query,
	UVERBS_ATTR_PTR_OUT_SZ(UVERBS_UHW_OUT, 0,
			       UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ)));
/* TODO: fix sizes */
DECLARE_UVERBS_ATTR_SPEC(
	mlx5_spec_alloc_context,
	UVERBS_ATTR_PTR_IN(UVERBS_UHW_IN, struct mlx5_ib_alloc_ucontext_req,
			   UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ |
				    UVERBS_ATTR_SPEC_F_MANDATORY)),
	UVERBS_ATTR_PTR_OUT_SZ(UVERBS_UHW_OUT, 0,
			       UA_FLAGS(UVERBS_ATTR_SPEC_F_MIN_SZ)));

DECLARE_UVERBS_TYPE(mlx5_type_qp, NULL,
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_QP_CREATE, NULL, NULL,
					  &mlx5_spec_create_qp)));

DECLARE_UVERBS_TYPE(mlx5_type_cq, NULL,
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_CQ_CREATE, NULL, NULL,
					  &mlx5_spec_create_cq)));

DECLARE_UVERBS_TYPE(mlx5_type_pd, NULL,
		    &UVERBS_ACTIONS(
			ADD_UVERBS_ACTION(UVERBS_PD_ALLOC, NULL, NULL,
					  &mlx5_spec_alloc_pd)));

DECLARE_UVERBS_TYPE(mlx5_type_device, NULL,
		    &UVERBS_ACTIONS(
			ADD_UVERBS_CTX_ACTION(UVERBS_DEVICE_ALLOC_CONTEXT,
					      NULL, NULL,
					      &mlx5_spec_alloc_context),
			ADD_UVERBS_ACTION(UVERBS_DEVICE_QUERY,
					  NULL, NULL,
					  &mlx5_spec_device_query)));

DECLARE_UVERBS_TYPES(mlx5_common_types,
		     ADD_UVERBS_TYPE(UVERBS_TYPE_DEVICE, mlx5_type_device),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_PD, mlx5_type_pd),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_CQ, mlx5_type_cq),
		     ADD_UVERBS_TYPE(UVERBS_TYPE_QP, mlx5_type_qp));
