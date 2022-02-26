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
 * opr_bits.h
 *    bit operation
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/variant/opr_bits.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OPR_BITS_H__
#define __OPR_BITS_H__

#include "var_opr.h"

status_t opr_exec_bitand(opr_operand_set_t *op_set);
status_t opr_exec_bitor(opr_operand_set_t *op_set);
status_t opr_exec_bitxor(opr_operand_set_t *op_set);
status_t opr_exec_lshift(opr_operand_set_t *op_set);
status_t opr_exec_rshift(opr_operand_set_t *op_set);

#endif