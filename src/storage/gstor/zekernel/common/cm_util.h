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
 * cm_util.h
 *
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_util.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_UTIL_H__
#define __CM_UTIL_H__
#include "cm_defs.h"
#include "cm_text.h"
#include "cm_charset.h"
#ifdef __cplusplus
extern "C" {
#endif

#define PATTERN_LEN 100
#define DESC_LEN    100

typedef struct st_keyword_map_item {
    char keyword_pattern[PATTERN_LEN];
    char type_desc[DESC_LEN];
} keyword_map_item_t;

extern keyword_map_item_t g_key_pattern[];
void cm_text_reg_match(text_t *text, const char *pattern, int32 *pos, charset_type_t charset);
void cm_text_try_map_key2type(const text_t *text, int32 *mattched_pat_id, bool32 *mattched);
void cm_text_star_to_one(text_t *text);
#ifdef __cplusplus
}
#endif

#endif
