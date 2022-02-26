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
 * srv_lsnr.c
 *    listener interface
 *
 * IDENTIFICATION
 *    src/server/srv_lsnr.c
 *
 * -------------------------------------------------------------------------
 */
#include "srv_lsnr.h"
#include "srv_agent.h"
#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t srv_tcp_app_connect_action(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    if (srv_create_session(pipe) != CM_SUCCESS) {
        cs_tcp_disconnect(&pipe->link.tcp);
        LOG_DEBUG_ERR("[lsnr] create session fail");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t srv_start_lsnr(void)
{
    status_t status;

    g_srv_inst->lsnr.tcp_service.type = LSNR_TYPE_MES;
    status = cs_start_tcp_lsnr(&g_srv_inst->lsnr.tcp_service, srv_tcp_app_connect_action);
    if (status != CM_SUCCESS) {
        LOG_RUN_ERR("[lsnr] failed to start lsnr for LSNR_ADDR");
        return status;
    }

    return CM_SUCCESS;
}

void srv_pause_lsnr(lsnr_type_t type)
{
    if (type == LSNR_TYPE_MES || type == LSNR_TYPE_ALL) {
        cs_pause_tcp_lsnr(&g_srv_inst->lsnr.tcp_service);
    }
    return;
}

void srv_stop_lsnr(lsnr_type_t type)
{
    if (type == LSNR_TYPE_MES || type == LSNR_TYPE_ALL) {
        cs_stop_tcp_lsnr(&g_srv_inst->lsnr.tcp_service);
    }
    return;
}

#ifdef __cplusplus
}
#endif

