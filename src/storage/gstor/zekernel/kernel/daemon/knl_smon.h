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
 * knl_smon.h
 *    kernel system monitor definitions,contains deadlock detect, min scn detect and undo shrink
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/daemon/knl_smon.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SMON_H__
#define __KNL_SMON_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_smon {
    thread_t thread;
    volatile bool32 undo_shrinking;
    volatile bool32 nolog_alarm;
    volatile bool32 shrink_inactive;
} smon_t;

#define SMON_ENABLE(session)        ((session)->kernel->smon_ctx.disable = GS_FALSE)
#define SMON_CHECK_DISABLE(session) ((session)->kernel->smon_ctx.disable)
#define SMON_UNDO_SHRINK_CLOCK    600
#define SMON_INDEX_RECY_CLOCK     1000
#define SMON_CHECK_SPC_USAGE_CLOCK 30
#define SMON_CHECK_XA_CLOCK        10
#define SMON_CHECK_NOLOGGING       600

void smon_proc(thread_t *thread);
void smon_close(knl_session_t *session);
status_t smon_start(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
