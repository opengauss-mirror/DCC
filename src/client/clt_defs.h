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
 * clt_defs.h
 *
 *
 * IDENTIFICATION
 *    src/client/clt_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CLT_DEFS_H__
#define __CLT_DEFS_H__

#include "cm_date.h"
#include "cm_sync.h"
#include "cm_latch.h"
#include "cm_cipher.h"
#include "util_defs.h"
#include "clt_watch_manager.h"
#include "clt_lease_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHANNEL_SIZE        (2)
#define MAX_SERVER_SIZE     (15)
#define MAX_CLI_NAME_ZIE    ((size_t)256)
#define SYNC_CHANNEL_IDX    (0)
#define ASYNC_CHANNEL_IDX   (1)

typedef enum clt_conn_status_en {
    CLT_NOT_CONNECTED = 0,
    CLT_CONNECTING,
    CLT_CONNECTED
} clt_conn_status_t;

typedef struct st_clt_lease_ctx {
    char name[MAX_LEASE_NAME_SIZE];
    uint32 ttl;
} clt_lease_ctx_t;

typedef struct st_handle {
    int32 server_cnt;
    char *server_texts[MAX_SERVER_SIZE];
    char *ca_file;
    char *crt_file;
    char *key_file;
    uchar *passwd;
    cipher_t cipher;

    spinlock_t latch;
    atomic32_t conn_idx;
    volatile bool32 sync_connected;
    void *channel[CHANNEL_SIZE];        // idx 0 sync, idx 1 async

    char clt_name[MAX_CLI_NAME_ZIE];    // for client register name

    // prefix kv buff
    uint32 eof;
    uint32 kv_cnt;
    uint32 kv_idx;
    uint32 pack_offset;
    // for sequence
    bool8  is_sequence;
    uint32 sequence_no;

    bool32 async_td_created;
    volatile uint32 session_id;         // for watch message
    volatile uint32 async_connected;
    volatile uint64 try_times;
    uint32 time_out;
    uint32 hb_interval;
    clt_watch_manager_t *watch_manager;      // watch manager
    cm_event_t async_channel_event;
    thread_t async_channel_thread;
    clt_lease_ctx_t *lease_ctx;
} clt_handle_t;

#ifdef __cplusplus
}
#endif

#endif
