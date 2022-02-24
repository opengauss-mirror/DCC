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
 * dcc_msg_protocol.c
 *    dcc common msg protocol encode/decode
 *
 * IDENTIFICATION
 *    src/utils/dcc_msg_protocol.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcc_msg_protocol.h"
#include "dcc_msg_cmd.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t decode_read_request(cs_packet_t *packet, read_request_t *request)
{
    int32 tmp;
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &tmp));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &request->is_dir));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &request->read_level));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &request->key_size));
    CM_RETURN_IFERR(cs_get_data(packet, request->key_size, (void **) &request->key));

    return CM_SUCCESS;
}

status_t encode_read_request(cs_packet_t *packet, const read_request_t *request)
{
    CM_RETURN_IFERR(cs_put_int32(packet, DCC_CMD_GET));
    CM_RETURN_IFERR(cs_put_int32(packet, request->is_dir));
    CM_RETURN_IFERR(cs_put_int32(packet, request->read_level));
    CM_RETURN_IFERR(cs_put_int32(packet, request->key_size));
    CM_RETURN_IFERR(cs_put_data(packet, request->key, request->key_size));

    return CM_SUCCESS;
}

static status_t encode_fetch_request(cs_packet_t *packet)
{
    return cs_put_int32(packet, DCC_CMD_FETCH);
}

status_t encode_write_request(cs_packet_t *packet, const write_request_t *request)
{
    // notice cmd sequence should be the 1, 2 and key should be the last
    CM_RETURN_IFERR(cs_put_int32(packet, DCC_CMD_PUT));
    CM_RETURN_IFERR(cs_put_int32(packet, request->sequence));
    CM_RETURN_IFERR(cs_put_int32(packet, request->not_existed));
    CM_RETURN_IFERR(cs_put_int32(packet, request->val_size));
    if (request->val_size > 0) {
        CM_RETURN_IFERR(cs_put_data(packet, request->val, request->val_size));
    }
    CM_RETURN_IFERR(cs_put_int32(packet, request->expect_val_size));
    if (request->expect_val_size > 0) {
        CM_RETURN_IFERR(cs_put_data(packet, request->expect_val, request->expect_val_size));
    }
    CM_RETURN_IFERR(cs_put_int32(packet, request->lease_name.len));
    if (request->lease_name.len > 0) {
        CM_RETURN_IFERR(cs_put_data(packet, request->lease_name.str, request->lease_name.len));
    }
    CM_RETURN_IFERR(cs_put_int32(packet, request->key_size));
    CM_RETURN_IFERR(cs_put_data(packet, request->key, request->key_size));
    return CM_SUCCESS;
}

status_t encode_del_request(cs_packet_t *packet, const del_request_t *request)
{
    CM_RETURN_IFERR(cs_put_int32(packet, DCC_CMD_DELETE));
    CM_RETURN_IFERR(cs_put_int32(packet, request->is_dir));
    CM_RETURN_IFERR(cs_put_int32(packet, request->key_size));
    CM_RETURN_IFERR(cs_put_data(packet, request->key, request->key_size));
    return CM_SUCCESS;
}

status_t decode_watch_request(cs_packet_t *packet, watch_request_t *request)
{
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &request->session_id));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &request->is_dir));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &request->key_size));
    CM_RETURN_IFERR(cs_get_data(packet, request->key_size, (void **) &request->key));

    return CM_SUCCESS;
}

status_t encode_watch_request(cs_packet_t *packet, const watch_request_t *request)
{
    CM_RETURN_IFERR(cs_put_int32(packet, request->session_id));
    CM_RETURN_IFERR(cs_put_int32(packet, request->is_dir));
    CM_RETURN_IFERR(cs_put_int32(packet, request->key_size));
    CM_RETURN_IFERR(cs_put_data(packet, request->key, request->key_size));

    return CM_SUCCESS;
}

status_t decode_connect_res(cs_packet_t *packet, connect_res_t *response)
{
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &response->session_id));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &response->is_leader));
    return CM_SUCCESS;
}

status_t encode_connect_res(cs_packet_t *packet, const connect_res_t *response)
{
    CM_RETURN_IFERR(cs_put_int32(packet, response->session_id));
    CM_RETURN_IFERR(cs_put_int32(packet, response->is_leader));
    return CM_SUCCESS;
}

status_t decode_watch_res(cs_packet_t *packet, watch_res_t *response)
{
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &response->watch_event));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &response->is_dir));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &response->key_size));
    CM_RETURN_IFERR(cs_get_data(packet, response->key_size, (void **) &response->key));
    CM_RETURN_IFERR(cs_get_int32(packet, (int32 *) &response->now_val_size));
    CM_RETURN_IFERR(cs_get_data(packet, response->now_val_size, (void **) &response->now_val));

    return CM_SUCCESS;
}

status_t encode_watch_res(cs_packet_t *packet, const watch_res_t *response)
{
    CM_RETURN_IFERR(cs_put_int32(packet, response->watch_event));
    CM_RETURN_IFERR(cs_put_int32(packet, response->is_dir));
    CM_RETURN_IFERR(cs_put_int32(packet, response->key_size));
    CM_RETURN_IFERR(cs_put_data(packet, response->key, response->key_size));
    CM_RETURN_IFERR(cs_put_int32(packet, response->now_val_size));
    CM_RETURN_IFERR(cs_put_data(packet, response->now_val, response->now_val_size));

    return CM_SUCCESS;
}

static status_t encode_lease_request(cs_packet_t *packet, uint8 cmd, const lease_request_t *request)
{
    CM_RETURN_IFERR(cs_put_int32(packet, cmd));
    CM_RETURN_IFERR(cs_put_int32(packet, request->lease_name.len));
    CM_RETURN_IFERR(cs_put_data(packet, request->lease_name.str, request->lease_name.len));
    switch (cmd) {
        case DCC_CMD_LEASE_CREATE:
            CM_RETURN_IFERR(cs_put_int32(packet, request->ttl));
            break;
        case DCC_CMD_LEASE_RENEW:
        case DCC_CMD_LEASE_DESTROY:
        case DCC_CMD_LEASE_QRY:
            break;
        default:
            LOG_RUN_ERR("[CLI]unkown command");
            break;
    }
    return CM_SUCCESS;
}

status_t encode_request(uint8 cmd, const void *request, cs_packet_t **pack)
{
    switch (cmd) {
        case DCC_CMD_GET:
        case DCC_CMD_CHILDREN:
            CM_RETURN_IFERR(encode_read_request(*pack, (read_request_t *) request));
            break;
        case DCC_CMD_FETCH:
            CM_RETURN_IFERR(encode_fetch_request(*pack));
            break;
        case DCC_CMD_PUT:
            CM_RETURN_IFERR(encode_write_request(*pack, (write_request_t *) request));
            break;
        case DCC_CMD_DELETE:
            CM_RETURN_IFERR(encode_del_request(*pack, (del_request_t *) request));
            break;
        case DCC_CMD_WATCH:
            CM_RETURN_IFERR(encode_watch_request(*pack, (watch_request_t *) request));
            break;
        case DCC_CMD_UNWATCH:
            CM_RETURN_IFERR(encode_watch_request(*pack, (watch_request_t *) request));
            break;
        case DCC_CMD_CONNECT:
            break;
        case DCC_CMD_LEASE_CREATE:
        case DCC_CMD_LEASE_DESTROY:
        case DCC_CMD_LEASE_RENEW:
        case DCC_CMD_LEASE_QRY:
            CM_RETURN_IFERR(encode_lease_request(*pack, cmd, (lease_request_t *) request));
            break;
        default:
            LOG_RUN_ERR("[CLI]unkown command");
            break;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif