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
 * gstor_instance.h
 *    instance interface
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_instance.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_INST_DEF_H__
#define __KNL_INST_DEF_H__

#include "cm_defs.h"
#include "gstor_sga.h"
#include "gstor_rm.h"
#include "knl_context.h"
#include "gstor_handle.h"

#ifdef __cplusplus
    extern "C" {
#endif

typedef enum en_startup_mode {
    STARTUP_MODE_OPEN = 0,
    STARTUP_MODE_NOMOUNT = 1,
} startup_mode_t;

typedef enum en_shutdown_mode {
    SHUTDOWN_MODE_NORMAL = 0,
    SHUTDOWN_MODE_IMMEDIATE,
    SHUTDOWN_MODE_SIGNAL,
    SHUTDOWN_MODE_ABORT,
    SHUTDOWN_MODE_END,
} shutdown_mode_t;

typedef enum en_shutdown_phase {
    SHUTDOWN_PHASE_NOT_BEGIN = 0,
    SHUTDOWN_PHASE_INPROGRESS,
    SHUTDOWN_PHASE_DONE
} shutdown_phase_t;

typedef struct st_shutdown_context {
    spinlock_t lock;
    shutdown_mode_t mode;
    shutdown_phase_t phase;
    bool32 enabled;
} shutdown_context_t;

typedef struct st_instance_attr {
    uint32 stack_size;
    uint64 space_size;
}instance_attr_t;

typedef struct st_instance {
    uint32             id;
    uint32             hwm;
    sga_t              sga;
    vmp_t              vmp;
    int32              lock_fd;
    uint32             sess;
    bool32             sys_defined;
    rm_pool_t          rm_pool;
    spinlock_t         lock;
    knl_instance_t     kernel;
    instance_attr_t    attr;
    shutdown_context_t shutdown_ctx;
    bool8 mem_alloc_from_large_page;
    char home[GS_MAX_PATH_BUFFER_SIZE];
    char xpurpose_buf[GS_XPURPOSE_BUFFER_SIZE + GS_MAX_ALIGN_SIZE_4K];
} instance_t;

extern instance_t *g_instance;

#ifdef __cplusplus
}
#endif

#endif

