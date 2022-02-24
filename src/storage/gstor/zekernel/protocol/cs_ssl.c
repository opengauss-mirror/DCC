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
 * cs_ssl.c
 *    Implement of ssl management
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/protocol/cs_ssl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cs_ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

void ssl_ca_cert_expire(const ssl_ctx_t *ssl_context, int32 alert_day)
{
    return;
}

ssl_ctx_t *cs_ssl_create_acceptor_fd(ssl_config_t *config)
{
    return NULL;
}

ssl_ctx_t *cs_ssl_create_connector_fd(ssl_config_t *config)
{
    return NULL;
}

void cs_ssl_free_context(ssl_ctx_t *ctx)
{
}

status_t cs_ssl_accept_socket(ssl_link_t *link, socket_t sock, int32 timeout)
{
    return GS_ERROR;
}

status_t cs_ssl_connect_socket(ssl_link_t *link, socket_t sock, int32 timeout)
{
    return GS_ERROR;
}

void cs_ssl_disconnect(ssl_link_t *link)
{
}

status_t cs_ssl_send(ssl_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    return GS_ERROR;
}

status_t cs_ssl_send_timed(ssl_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    return GS_ERROR;
}

status_t cs_ssl_recv(ssl_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    return GS_ERROR;
}

status_t cs_ssl_recv_remain(ssl_link_t *link, char *buf, uint32 offset, uint32 remain_size,
                            uint32 wait_event, uint32 timeout)
{
    return GS_ERROR;
}

status_t cs_ssl_recv_timed(ssl_link_t *link, char *buf, uint32 size, uint32 timeout)
{
    return GS_ERROR;
}

status_t cs_ssl_wait(ssl_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    return GS_ERROR;
}

status_t cs_ssl_verify_certificate(ssl_link_t *link, ssl_verify_t vmode, const char *name, const char **errptr)
{
    return GS_ERROR;
}

const char **cs_ssl_get_default_cipher_list()
{
    return NULL;
}

const char **cs_ssl_tls13_get_default_cipher_list()
{
    return NULL;
}

status_t cs_ssl_verify_file_stat(const char *file_name)
{
    return GS_ERROR;
}

#ifdef __cplusplus
}
#endif