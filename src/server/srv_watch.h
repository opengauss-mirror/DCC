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
 * srv_watch.h
 *    headfile of watch events proc
 *
 * IDENTIFICATION
 *    src/server/srv_watch.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_WATCH_H__
#define __SRV_WATCH_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_error.h"
#include "cm_hash.h"
#include "cm_spinlock.h"
#include "cs_packet.h"
#include "cm_list.h"
#include "dcc_interface.h"
#include "executor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DCC_MAX_SESS_WATCH_QUE_NUM 16

typedef struct st_watch_msg_node {
    uint32 sid;
    dcc_text_t   old_value; // reserved
    msg_entry_t  *entry;
    dcc_event_type_t event_type;
    uint32 is_prefix_notify;
    struct st_watch_msg_node *prev;
    struct st_watch_msg_node *next;
} watch_msg_node_t;

typedef struct st_watch_msg_queue {
    uint32 id;
    spinlock_t lock;
    biqueue_t que;
    cs_packet_t pack;
    uint32 que_len;
} watch_msg_queue_t;

typedef struct st_watch_msg_mgr {
    watch_msg_queue_t *watch_que[DCC_MAX_SESS_WATCH_QUE_NUM];
    thread_t thread;
    cm_event_t event;
    atomic_t total_msg_cnt;
} watch_mgr_t;

status_t srv_init_watch_mgr(void);
void srv_uninit_watch_mgr(void);
int srv_proc_watch_event(dcc_event_t *watch_event);
void watch_send_msg(void);

#ifdef __cplusplus
}
#endif

#endif
