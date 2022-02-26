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
 * gstor_sys_def.h
 *    instance interface
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_sys_def.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_SYS_DEF_H__
#define __SRV_SYS_DEF_H__

#include "cm_defs.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_column_def {
    text_t    name;
    gs_type_t type;
    uint16    size;
    bool32    nullable;
}column_def_t;

typedef struct st_index_def {
    text_t  name;
    text_t *cols;
    uint32  col_count;
    bool32  is_unique;
}index_def_t;

typedef struct st_table_def {
    text_t name;
    column_def_t *cols;
    uint32 col_count;
    text_t  *space;
    uint32  sysid;
    uint32 index_count;
    index_def_t *index;
    table_type_t type;
}table_def_t;

#define IX_SYS_KV_01_ID         0
#define SYS_KV_KEY_COL_ID       0
#define SYS_KV_VALUE_COL_ID     1

status_t knl_open_sys_database(knl_session_t *session);
status_t knl_create_sys_database(knl_session_t *knl_session, char *home);
status_t knl_build_sys_objects(knl_handle_t handle);
status_t knl_create_user_table(knl_session_t *session, table_def_t *table);

#ifdef __cplusplus
}
#endif

#endif

