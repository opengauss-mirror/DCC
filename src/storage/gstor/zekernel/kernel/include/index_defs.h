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
 * index_defs.h
 *    Index defines
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/include/index_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_INDEX_DEFS_H__
#define __KNL_INDEX_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_REBUILD_PARTS   32

#define IS_ALTER_INDEX_COALESCE(def)                                                                      \
    ((def)->type == ALINDEX_TYPE_COALESCE ||                                                              \
    ((def)->type == ALINDEX_TYPE_MODIFY_PART && (def)->mod_idxpart.type == MODIFY_IDXPART_COALESCE) ||    \
    ((def)->type == ALINDEX_TYPE_MODIFY_SUBPART && (def)->mod_idxpart.type == MODIFY_IDXSUBPART_COALESCE))

typedef enum en_alter_index_type {
    ALINDEX_TYPE_REBUILD = 0,
    ALINDEX_TYPE_REBUILD_PART = 1,
    ALINDEX_TYPE_ENABLE = 2,
    ALINDEX_TYPE_DISABLE = 3,
    ALINDEX_TYPE_RENAME = 4,
    ALINDEX_TYPE_COALESCE = 5,
    ALINDEX_TYPE_MODIFY_PART = 6,
    ALINDEX_TYPE_UNUSABLE = 7,
    ALINDEX_TYPE_MODIFY_SUBPART = 8,
    ALINDEX_TYPE_REBUILD_SUBPART = 9,
    ALINDEX_TYPE_INITRANS = 10,
} alter_index_type_t;

typedef struct st_rebuild_index_def {
    text_t space;
    text_t part_name[MAX_REBUILD_PARTS]; // none part rebuild should be {NULL,0}
    bool32 is_online;
    bool32 build_stats;
    uint32 pctfree;
    bool32 keep_storage;
    uint8 cr_mode;
    uint32 parallelism;
    uint32 specified_parts; // none part rebuild should be zero
} rebuild_index_def_t;

typedef struct st_knl_alt_index_prop {
    text_t new_name;
    uint32 initrans;
} knl_alt_index_prop_t;

typedef enum en_modify_idxpart_type {
    MODIFY_IDXPART_COALESCE = 0,
    MODIFY_IDXSUBPART_COALESCE = 1,
    MODIFY_IDXPART_INITRANS = 2,
    MODIFY_IDXPART_UNUSABLE = 3,
    MODIFY_IDXSUBPART_UNUSABLE = 4,
} modify_idxpart_type_t;

typedef struct st_modify_idxpart_def {
    modify_idxpart_type_t type;
    text_t part_name;
    uint32 initrans;
} modify_idxpart_def_t;

typedef struct st_knl_alindex_def {
    text_t user;
    text_t name;
    alter_index_type_t type;
    text_t table;
    union {
        knl_alt_index_prop_t idx_def;     /* < for alter index property */
        rebuild_index_def_t rebuild;      /* < for alter index rebuild */
        modify_idxpart_def_t mod_idxpart; /* < for alter index modify partition */
    };
} knl_alindex_def_t;

status_t knl_create_index(knl_handle_t session, knl_index_def_t *def);
status_t knl_alter_index_coalesce(knl_handle_t session, knl_alindex_def_t *def);
status_t knl_alter_index(knl_handle_t session, knl_alindex_def_t *def);
status_t knl_drop_index(knl_handle_t session, knl_drop_def_t *def);
status_t knl_create_indexes(knl_handle_t handle, knl_indexes_def_t *def);
#ifdef __cplusplus
}
#endif

#endif