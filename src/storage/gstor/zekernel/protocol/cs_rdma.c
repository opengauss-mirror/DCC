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
 * cs_rdma.c
 *    Implement of rdma socket management.
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/protocol/cs_rdma.c
 *
 * -------------------------------------------------------------------------
 */

#include "cs_rdma.h"

#ifdef __cplusplus
extern "C" {
#endif

void cs_rdma_set_io_mode(socket_t sock, bool32 nonblock, bool32 nodelay)
{
    return;
}

void cs_rdma_set_buffer_size(socket_t sock, uint32 send_size, uint32 recv_size)
{
    return;
}

void cs_rdma_set_keep_alive(socket_t sock, uint32 idle, uint32 interval, uint32 count)
{
    return;
}

void cs_rdma_set_linger(socket_t sock)
{
    return;
}

status_t cs_create_rdma_socket(int ai_family, socket_t *sock)
{
    return GS_SUCCESS;
}

status_t cs_rdma_connect(const char *host, uint16 port, rdma_link_t *link)
{
    return GS_SUCCESS;
}

bool32 cs_rdma_try_connect(const char *host, uint16 port)
{
    return GS_TRUE;
}

void cs_rdma_disconnect(rdma_link_t *link)
{
    return;
}

status_t cs_rdma_send(rdma_link_t *link, const char *buf, uint32 size, int32 *send_size)
{
    return GS_SUCCESS;
}

status_t cs_rdma_send_timed(rdma_link_t *link, const char *buf, uint32 size, uint32 timeout)
{
    return GS_SUCCESS;
}

status_t cs_rdma_recv(rdma_link_t *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event)
{
    return GS_SUCCESS;
}

status_t cs_rdma_recv_timed(rdma_link_t *link, char *buf, uint32 size, uint32 timeout)
{
    return GS_SUCCESS;
}

status_t cs_rdma_wait(rdma_link_t *link, uint32 wait_for, int32 timeout, bool32 *ready)
{
    return GS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
