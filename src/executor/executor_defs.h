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
 * executor_defs.h
 *
 * IDENTIFICATION
 *    src/executor/executor_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_EXECUTOR_DEFS_H__
#define __DCC_EXECUTOR_DEFS_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "cm_error.h"
#include "cm_text.h"
#include "cm_timer.h"
#include "cm_sync.h"
#include "cm_queue.h"
#include "cm_log.h"
#include "srv_param.h"
#include "dcc_msg_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXC_STREAM_ID_DEFAULT          (1)
#define EXC_PATH_MAX_SIZE              (MAX_PARAM_VALUE_LEN + 1)
#define EXC_DCF_CFG_SIZE               SIZE_K(4)
#define EXC_DCF_TRUNCATE_SIZE          (100000)
#define EXC_DCF_APPLY_IDX_FROZEN_CNT_THOLD (10)
#define EXC_DISK_AVAIL_RATE            (0.2)
#define EXC_DCF_APPLY_INDEX_SIZE       (3000)
#define EXC_DCF_ROLE_NOT_LEADER_ERRORNO (603)
#define EXC_THREAD_SLEEP_TIME          (10)

#define EXC_DCF_START_LOOP             (1000)
#define EXC_DCF_SET_APPLY_TIMEOUT      (10000)
#define EXC_DCF_WAIT_ALL_APPLY_TIMEOUT (300000)

#define MILLISECS_PERP_SECOND    1000U
#define MICROSECS_PERP_MILLISEC  1000U

#define EXC_BIT_MOVE_TWO_BYTES         (16)
#define EXC_BIT_MOVE_FOUR_BYTES        (32)
#define EXC_BIT_MOVE_SIX_BYTES         (48)
#define EXC_KEY_MAX_SIZE               SIZE_K(4)
#define EXC_DATA_MAX_SIZE              SIZE_M(10)
#define EXC_DIGIT_MAX_SIZE             (32)
#define EXC_STG_ROW_MAX_SIZE           SIZE_M(2)

#define EXC_DCF_APPLIED_INDEX_KEY  "dcf_applied_index"
#define EXC_DCF_APPLIED_INDEX_LEN  (17)

#define EXC_SLEEP_1_FIXED          1
#define EXC_MSG_BATCH_COMMIT       1000
#define EXC_WAIT_DB_COMMIT_TIMEOUT (3000) // ms

typedef struct st_exc_msg_queue {
    spinlock_t   lock;
    biqueue_t    msg_queue;
    cm_event_t   event;
    thread_t     thread;
} exc_msg_queue_t;

typedef struct st_exc_check_thread {
    latch_t lock;
    volatile bool32 is_check_all_applied;
    uint32_t role_type;
    thread_t thread;
} exc_check_thread_t;

typedef struct st_exc_cmd_get {
    uint32 cmd;
    bool32 is_prefix;
    uint32 read_level;
    text_t key;
} exc_cmd_get_t;

static inline void exc_put_uint32(const char* buff, uint32 value, uint32* offset)
{
    CM_ASSERT(buff != NULL);
    *(uint32 *)(buff + *offset) = value;
    *offset += sizeof(uint32);
}

static inline void exc_put_uint64(const char* buff, uint64 value, uint32* offset)
{
    CM_ASSERT(buff != NULL);
    *(uint64 *)(buff + *offset) = value;
    *offset += sizeof(uint64);
}

static inline status_t exc_put_text(char* buff, uint32 buff_len, const text_t *text, uint32* offset)
{
    CM_ASSERT(buff != NULL);
    CM_ASSERT(text != NULL);
    *(uint32 *)(buff + *offset) = text->len;
    *offset += sizeof(uint32);
    if (text->len == 0) {
        return CM_SUCCESS;
    }
    MEMS_RETURN_IFERR(memcpy_s((buff + *offset), buff_len - *offset, text->str, text->len));
    *offset += CM_ALIGN4(text->len);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif
