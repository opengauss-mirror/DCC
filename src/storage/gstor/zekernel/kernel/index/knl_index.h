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
 * knl_index.h
 *    implement of index
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/index/knl_index.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_INDEX_H__
#define __KNL_INDEX_H__

#include "cm_defs.h"
#include "knl_common.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "knl_page.h"
#include "knl_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GS_SHADOW_INDEX_ID     (GS_MAX_TABLE_INDEXES + 1)
#define INDEX_DESC(index)      (&((index_t *)(index))->desc)
#define GS_MAX_RECYCLE_INDEXES 64
#define INDEX_MIN_RECYCLE_SIZE SIZE_M(4)
#define INDEX_RECY_CLOCK 2

/* if garbage size is large than 20% of segment size, we need recycle pages */
#define INDEX_NEED_RECY_RATIO 0.2

#define MAX_SORT_THREADS 12
#define MIN_SORT_THREADS 2
#define INDEX_IS_UNSTABLE(index, is_splitting) (((index)->desc.primary || (index)->desc.unique) && !(is_splitting))

typedef enum en_dep_scan_mode {
    DEP_SCAN_TABLE_FULL = 0,
    DEP_SCAN_INDEX_ONLY = 1,
    DEP_SCAN_MIX = 2,
} dep_scan_mode_t;

typedef struct st_cons_dep {
    uint16 *cols;
    uint8 *col_map;
    struct st_cons_dep *next;
    volatile bool32 loaded;
    spinlock_t lock;
    knl_refactor_t refactor;
    knl_constraint_state_t cons_state;
    uint16 uid;
    uint32 oid;
    uint8 col_count;
    uint8 idx_slot;
    uint8 ix_match_cols;
    uint8 align;
    dep_scan_mode_t scan_mode;
    knl_scn_t chg_scn;
} cons_dep_t;

typedef struct st_dep_condition {
    char *data[GS_MAX_INDEX_COLUMNS];
    uint16 lens[GS_MAX_INDEX_COLUMNS];
    knl_cursor_t *child_cursor;
    cons_dep_t *dep;
} dep_condition_t;

typedef struct st_cons_dep_set {
    cons_dep_t *first;
    cons_dep_t *last;
    uint32 count;
} cons_dep_set_t;

/* index access method structure */
typedef struct st_index_accessor {
    knl_cursor_operator_t do_fetch;
    knl_cursor_operator_t do_insert;
    knl_cursor_operator_t do_delete;
} idx_accessor_t;

typedef struct st_index {
    knl_index_desc_t desc;
    cons_dep_set_t dep_set;  // which constraints depends on this table
    struct st_dc_entity *entity;
    union {
        btree_t btree;     // index entity
        void *temp_btree;  // temp index entity
    };
    struct st_part_index *part_index;  // partitioned index
    idx_accessor_t *acsor;           // index access method
} index_t;

#define IS_UNIQUE_PRIMARY_INDEX(index) ((index)->desc.primary || (index)->desc.unique)
#define IS_PART_INDEX(index)           (((index_t *)(index))->desc.parted)
#define INDEX_GET_PART(index, part_no) PART_GET_ENTITY(((index_t *)(index))->part_index, part_no)
#define GS_MAX_ROOT_LEVEL  (GS_MAX_BTREE_LEVEL - 1)
#define BTREE_NEED_CMP_ROWID(cursor, index) (!IS_UNIQUE_PRIMARY_INDEX(index) || (cursor)->index_paral)

typedef struct st_index_set {
    index_t *items[GS_MAX_TABLE_INDEXES];
    uint32 count;
    uint32 total_count;
} index_set_t;

typedef struct st_index_recycle_item {
    xid_t xid;
    knl_scn_t scn;
    knl_scn_t part_org_scn;
    uint32 table_id;
    uint32 part_no;
    uint16 uid;
    uint8 index_id;
    uint8 next;
    bool32 is_tx_active;
} index_recycle_item_t;

typedef struct st_index_recycle_ctx {
    spinlock_t lock;
    bool32 is_working;
    id_list_t idx_list;
    id_list_t free_list;
    thread_t thread;
    index_recycle_item_t items[GS_MAX_RECYCLE_INDEXES];
} index_recycle_ctx_t;

typedef struct st_index_page_item {
    uint32 next;
    bool32 is_invalid;
    char page[0];
} index_page_item_t;

typedef struct st_index_cache_ctx {
    spinlock_t lock;
    uint32 capacity;
    uint32 hwm;
    id_list_t free_items;
    id_list_t expired_items;
    index_page_item_t *items;
} index_cache_ctx_t;

typedef struct st_index_area {
    index_recycle_ctx_t recycle_ctx;
    index_cache_ctx_t cache_ctx;
} index_area_t;

typedef struct st_btree_mt_context {
    mtrl_context_t mtrl_ctx;
    mtrl_context_t mtrl_ctx_paral;
    bool32 initialized;
    uint32 seg_id;
    bool32 is_parallel;
    uint64 rows;
    char *page_buf;
} btree_mt_context_t;

typedef struct st_btree_path_t {
    rowid_t path[GS_MAX_BTREE_LEVEL];
    uint64 leaf_lsn;
    knl_part_locate_t part_loc;
    bool32 get_sibling;
    char *sibling_key;
} btree_path_info_t;

typedef struct st_idx_range_info {
    page_id_t l_page[GS_MAX_BTREE_LEVEL];
    page_id_t r_page[GS_MAX_BTREE_LEVEL];
    uint32 l_slot[GS_MAX_BTREE_LEVEL];
    uint32 r_slot[GS_MAX_BTREE_LEVEL];
    uint32 keys;
    uint32 level;
}idx_range_info_t;

typedef enum en_index_build_mode {
    REBUILD_INDEX_ONLINE = 0,
    REBUILD_INDEX = 1,
    CREATE_INDEX_ONLINE = 2,
    REBUILD_INDEX_PARALLEL = 3,
}index_build_mode_t;

extern idx_accessor_t g_btree_acsor;
extern idx_accessor_t g_pcr_btree_acsor;
extern idx_accessor_t g_temp_btree_acsor;
extern idx_accessor_t g_invalid_index_acsor;

typedef void (*idx_put_key_data_t)(char *key_buf, gs_type_t type, const char *data, uint16 len, uint16 id);
typedef status_t (*idx_batch_insert)(knl_handle_t session, knl_cursor_t *cursor);
status_t knl_make_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf);
status_t knl_make_update_key(knl_handle_t session, knl_cursor_t *cursor, index_t *index, char *key_buf,
                             knl_update_info_t *ui, uint16 *map);
void idx_decode_row(knl_session_t *session, knl_cursor_t *cursor, uint16 *offsets, uint16 *lens, uint16 *size);
status_t idx_generate_dupkey_error(index_t *index, char *key);
status_t idx_construct(btree_mt_context_t *ctx);

void idx_recycle_proc(thread_t *thread);
void idx_recycle_close(knl_session_t *session);
void idx_binary_search(index_t *index, char *curr_page, knl_scan_key_t *scan_key, btree_path_info_t *path_info,
                       bool32 cmp_rowid, bool32 *is_same);
status_t idx_get_paral_schedule(knl_session_t *session, btree_t *btree, knl_scn_t org_scn,
                                knl_idx_paral_info_t paral_info, knl_index_paral_range_t *sub_ranges);
void idx_enter_next_range(knl_session_t *session, page_id_t page_id, uint32 slot, uint32 step, uint32 *border);
#ifdef __cplusplus
}
#endif

#endif
