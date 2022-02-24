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
 * dcc_msg_protocol.h
 *    header file of dcc common msg protocol
 *
 * IDENTIFICATION
 *    src/utils/dcc_msg_protocol.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCC_MSG_PROTOCOL_H__
#define __DCC_MSG_PROTOCOL_H__

#include "cm_defs.h"
#include "cm_error.h"
#include "cs_packet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_protocol_type {
    PROTO_TYPE_UNKNOWN = 0,
    PROTO_TYPE_DCC_CMD = 1,
} protocol_type_t;

typedef struct st_read_request {
    uint32 is_dir;
    uint32 read_level;
    uint32 key_size;
    char *key;
} read_request_t;

typedef struct st_write_request {
    uint32 ephemeral;
    uint32 sequence;
    uint32 not_existed;
    uint64 ttl;
    uint32 val_size;
    char *val;
    uint32 expect_val_size;
    char *expect_val;
    text_t lease_name;
    uint32 key_size;
    char *key;
} write_request_t;

typedef struct st_del_request {
    uint32 is_dir;
    uint32 key_size;
    char *key;
} del_request_t;

typedef struct st_watch_request {
    uint32 session_id;
    uint32 is_dir;
    uint32 key_size;
    char *key;
} watch_request_t;

typedef struct st_connect_res {
    uint32 session_id;
    uint32 is_leader;
} connect_res_t;

typedef struct st_watch_res {
    uint32 watch_event;
    uint32 is_dir;
    uint32 key_size;
    char *key;
    uint32 now_val_size;
    char *now_val;
} watch_res_t;

typedef struct st_lease_request {
    text_t lease_name;
    uint32 ttl;
} lease_request_t;

status_t decode_read_request(cs_packet_t *packet, read_request_t *request);

status_t encode_read_request(cs_packet_t *packet, const read_request_t *request);

status_t decode_children_request(cs_packet_t *packet, read_request_t *request);

status_t encode_children_request(cs_packet_t *packet, const read_request_t *request);

status_t encode_write_request(cs_packet_t *packet, const write_request_t *request);

status_t encode_del_request(cs_packet_t *packet, const del_request_t *request);

status_t decode_watch_request(cs_packet_t *packet, watch_request_t *request);

status_t encode_watch_request(cs_packet_t *packet, const watch_request_t *request);

status_t decode_connect_res(cs_packet_t *packet, connect_res_t *response);

status_t encode_connect_res(cs_packet_t *packet, const connect_res_t *response);

status_t decode_watch_res(cs_packet_t *packet, watch_res_t *response);

status_t encode_watch_res(cs_packet_t *packet, const watch_res_t *response);

status_t encode_request(uint8 cmd, const void *request, cs_packet_t **pack);

#ifdef __cplusplus
}
#endif

#endif
