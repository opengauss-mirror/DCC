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
 * net_client.h
 *    network process
 *
 * IDENTIFICATION
 *    src/network/net_client.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __NET_CLIENT_H__
#define __NET_CLIENT_H__

#include "cs_pipe.h"
#include "cm_defs.h"
#include "dcc_msg_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_net_channel {
    cs_pipe_t pipe;
    bool32 is_async;
    volatile bool8 pipe_active;
    cs_packet_t recv_pack;
    cs_packet_t send_pack;
    atomic_t send_count;
    atomic_t recv_count;
    uint32 serial_no;
    void *clt_handle;
    ssl_ctx_t *ssl_connector_fd;
} net_channel_t;

typedef status_t(*msg_proc_t)(cs_packet_t *pack, void *clt_handle);

typedef enum en_async_thread_status {
    ASYNC_THREAD_STATUS_RUNNING = 0,
    ASYNC_THREAD_STATUS_PAUSING,
    ASYNC_THREAD_STATUS_PAUSED,
} async_thread_status_t;

typedef struct st_async_thread_info {
    uint32 ref_cnt;
    int epollfd;
    async_thread_status_t status;
    thread_t thread;
    spinlock_t lock;
} async_thread_info_t;

typedef struct st_net_state {
    async_thread_info_t async_thread;
    msg_proc_t proc[DCC_CMD_CEIL];
} net_state_t;

typedef struct st_conn_option {
    int32 connect_timeout; /* ms */
    int32 socket_timeout;  /* ms */
    ssl_config_t ssl_para;
} conn_option_t;

void *cs_connect_sync_channel(const char *url, const void *clt_handle, const conn_option_t *option);
void cs_register_msg_process(uint8 cmd, msg_proc_t proc);
void *cs_connect_async_channel(const char *url, const void *clt_handle, const conn_option_t *option);
cs_packet_t *cs_get_send_pack(const void *channel);
status_t cs_remote_call(void *channel, cs_packet_t *pack, uint8 cmd);
cs_packet_t *cs_get_recv_pack(const void *channel);
status_t cs_remote_call_no_wait(void *channel, cs_packet_t *pack, uint8 cmd);
void cs_disconnect_channel(void *channel);
static inline uint32 cs_get_peer_version(const void *channel)
{
    return ((net_channel_t *)channel)->pipe.version;
}

#ifdef __cplusplus
}
#endif

#endif
