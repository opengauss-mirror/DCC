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
 * pcr_btree_scan.h
 *    implement of pcr btree scan
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/index/pcr_btree_scan.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PCR_BTREE_SCAN_H__
#define __PCR_BTREE_SCAN_H__

#include "pcr_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t pcrb_fetch(knl_handle_t session, knl_cursor_t *cursor);
status_t pcrb_fetch_depended(knl_session_t *session, knl_cursor_t *cursor);

int32 pcrb_cmp_column(knl_column_t *column, knl_scan_key_t *scan_key, uint32 idx_col_id,
    pcrb_key_t *key, uint16 *offset);
int32 pcrb_compare_key(index_t *index, knl_scan_key_t *scan_key, pcrb_key_t *key, bool32 cmp_rowid,
    bool32 *is_same);

void pcrb_binary_search(index_t *index, btree_page_t *page, knl_scan_key_t *scan_key, btree_path_info_t *path_info,
    bool32 cmp_rowid, bool32 *is_same);
void pcrb_get_parl_schedule(knl_session_t *session, index_t *index, knl_idx_paral_info_t paral_info,
    idx_range_info_t org_info, uint32 root_level, knl_index_paral_range_t *sub_range);
int32 pcrb_cmp_rowid(pcrb_key_t *key1, pcrb_key_t *key2);
#ifdef __cplusplus
}
#endif

#endif
