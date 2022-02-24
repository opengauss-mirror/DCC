/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * opr_bits.c
 *    bit operation
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/variant/opr_bits.c
 *
 * -------------------------------------------------------------------------
 */
#include "opr_bits.h"

#define PREPARE_BIT_OPER \
    do{\
        OP_RESULT->v_bigint = 0;\
        OP_RESULT->type = GS_TYPE_BIGINT;\
        \
        if (var_as_bigint(OP_LEFT) != GS_SUCCESS) {\
            return GS_ERROR;\
        }\
        \
        if (var_as_bigint(OP_RIGHT) != GS_SUCCESS) {\
            return GS_ERROR;\
        }\
    } while (0)

status_t opr_exec_bitand(opr_operand_set_t *op_set)
{
    PREPARE_BIT_OPER;
    OP_RESULT->v_bigint = OP_LEFT->v_bigint & OP_RIGHT->v_bigint;
    return GS_SUCCESS;
}


status_t opr_exec_bitor(opr_operand_set_t *op_set)
{
    PREPARE_BIT_OPER;
    OP_RESULT->v_bigint = OP_LEFT->v_bigint | OP_RIGHT->v_bigint;
    return GS_SUCCESS;
}

status_t opr_exec_bitxor(opr_operand_set_t *op_set)
{
    PREPARE_BIT_OPER;
    OP_RESULT->v_bigint = OP_LEFT->v_bigint ^ OP_RIGHT->v_bigint;
    return GS_SUCCESS;
}

#define PREPARE_BIT_SHIFT \
    do{\
        OP_RESULT->v_bigint = 0;\
        OP_RESULT->type = GS_TYPE_BIGINT;\
        \
        if (var_as_bigint(OP_LEFT) != GS_SUCCESS) {\
            return GS_ERROR;\
        }\
        \
        if (var_as_bigint(OP_RIGHT) != GS_SUCCESS) {\
            return GS_ERROR;\
        }\
        \
        if (OP_RIGHT->v_bigint >= 64 || OP_RIGHT->v_bigint < 0) {\
            return GS_SUCCESS;\
        }\
    } while (0)


status_t opr_exec_lshift(opr_operand_set_t *op_set)
{
    PREPARE_BIT_SHIFT;
    OP_RESULT->v_bigint = OP_LEFT->v_bigint << OP_RIGHT->v_bigint;
    return GS_SUCCESS;
}

status_t opr_exec_rshift(opr_operand_set_t *op_set)
{
    PREPARE_BIT_SHIFT;
    OP_RESULT->v_bigint = OP_LEFT->v_bigint >> OP_RIGHT->v_bigint;
    return GS_SUCCESS;
}
