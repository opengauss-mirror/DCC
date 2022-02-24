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
 * repl_log_replay.h
 *    implement of log replay function
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/kernel/replication/repl_log_replay.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __REPL_LOG_REPLAY_H__
#define __REPL_LOG_REPLAY_H__

#include "knl_log.h"
#include "knl_archive.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_lrpl_arch_file {
    uint32 asn;
    char file_name[GS_FILE_NAME_BUFFER_SIZE];
    int32 handle;
    log_file_head_t head;
} lrpl_arch_file_t;

typedef struct st_lrpl_context {
    thread_t thread;
    aligned_buf_t *read_buf;
    log_point_t curr_point;
    log_point_t begin_point;
    bool32 is_closing;
    bool32 is_done;
    bool32 has_gap;
    date_t begin_time;
    date_t end_time;
    arch_file_t arch_file;
    int32 log_handle[GS_MAX_LOG_FILES];
    uint32 replay_fail_cnt;
} lrpl_context_t;

status_t lrpl_init(knl_session_t *session);
void lrpl_close(knl_session_t *session);
status_t lrpl_prepare_archfile(knl_session_t *session, log_point_t *point, bool32 *reset);
bool32 lrpl_need_replay(knl_session_t *session, log_point_t *point);
bool32 lrpl_replay_blocked(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
