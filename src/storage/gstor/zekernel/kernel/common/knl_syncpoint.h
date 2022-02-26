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
 * knl_syncpoint.h
 *    kernel syncpoint manage
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/common/knl_syncpoint.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SYNCPOINT_H__
#define __KNL_SYNCPOINT_H__

#include "cm_defs.h"
#include "cm_spinlock.h"
#include "knl_interface.h"

#ifdef __cplusplus
extern "C"{
#endif

#ifdef DB_DEBUG_VERSION
/* sync point section */
#define GS_SESSION_MAX_SYNCPOINT      10
#define GS_CONCURRENT_MAX_SYNCPOINT   0x80
#define INVALID_SYNCPOINT_INDEX       GS_SESSION_MAX_SYNCPOINT
#define INDEX_IS_INVALID(inx)         ((inx) == INVALID_SYNCPOINT_INDEX)

typedef struct st_syncpoint_action {
    uint32 active_syncpoint;
    syncpoint_def_t syncpoint_def[GS_SESSION_MAX_SYNCPOINT];
} syncpoint_action_t;

typedef struct st_syncpoint {
    spinlock_t syncpoint_lock;
    uint32 num_signal;
    char signals[GS_CONCURRENT_MAX_SYNCPOINT * GS_NAME_BUFFER_SIZE];
} syncpoint_t;

status_t sp_add_syncpoint(knl_handle_t knl_session, syncpoint_def_t *syncpoint_def);
status_t sp_reset_syncpoint(knl_handle_t knl_session);
status_t sp_exec_syncpoint(knl_handle_t knl_session, const char *syncpoint_name);
void     sp_clear_syncpoint_action(knl_handle_t knl_session);
#endif /* DB_DEBUG_VERSION */

#ifdef __cplusplus
}
#endif

#endif
