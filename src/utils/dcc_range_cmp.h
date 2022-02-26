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
 * dcc_range_cmp.h
 *
 *
 * IDENTIFICATION
 *    src/utils/dcc_range_cmp.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_RANGGE_CMP_H__
#define __DCC_RANGGE_CMP_H__

#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IV_END_CHARACTER    ((uint8)0xff)

typedef struct st_iv {
    text_t begin;
    text_t end;
} iv_t;

int32 iv_byte_cmp(const text_t *iv1, const text_t *iv2);

int32 iv_cmp(const iv_t *iv1, const iv_t *iv2);

#ifdef __cplusplus
}
#endif

#endif