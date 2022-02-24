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
 * dcc_range_cmp.c
 *
 *
 * IDENTIFICATION
 *    src/utils/dcc_range_cmp.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcc_range_cmp.h"

#ifdef __cplusplus
extern "C" {
#endif

int32 iv_byte_cmp(const text_t *iv1, const text_t *iv2)
{
    return cm_compare_text(iv1, iv2);
}

int32 iv_cmp(const iv_t *iv1, const iv_t *iv2)
{
    int32 iv_b_cmp_b = iv_byte_cmp(&iv1->begin, &iv2->begin);
    int32 iv_b_cmp_e = iv_byte_cmp(&iv1->begin, &iv2->end);
    int32 iv_e_cmp_b = iv_byte_cmp(&iv1->end, &iv2->begin);
    // iv1 is left of iv2
    if (iv_b_cmp_b < 0 && iv_e_cmp_b <= 0) {
        return -1;
    }
    // iv1 is right of iv2
    if (iv_b_cmp_e >= 0) {
        return 1;
    }

    return 0;
}
#ifdef __cplusplus
}
#endif