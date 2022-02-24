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
 * dcc_msg_cmd.h
 *    header file for dcc common msg cmd
 *
 * IDENTIFICATION
 *    src/utils/dcc_msg_cmd.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DCC_MSG_CMD_H__
#define __DCC_MSG_CMD_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DCC_CMD_UNKONOW,
    DCC_CMD_CONNECT,
    DCC_CMD_SSL,
    DCC_CMD_LOOPBACK,
    DCC_CMD_DISCONNECT,
    DCC_CMD_HEARTBEAT,
    DCC_CMD_OP_BEGIN,
    DCC_CMD_PUT = DCC_CMD_OP_BEGIN,
    DCC_CMD_GET,
    DCC_CMD_FETCH,
    DCC_CMD_CHILDREN,
    DCC_CMD_DELETE,
    DCC_CMD_WATCH,
    DCC_CMD_UNWATCH,
    DCC_CMD_LEASE_FLOOR,
    DCC_CMD_LEASE_CREATE = DCC_CMD_LEASE_FLOOR,
    DCC_CMD_LEASE_DESTROY,
    DCC_CMD_LEASE_RENEW,
    DCC_CMD_LEASE_EXPIRE,
    DCC_CMD_LEASE_SYNC,
    DCC_CMD_LEASE_QRY,
    DCC_CMD_LEASE_CEIL = DCC_CMD_LEASE_QRY,
    DCC_CMD_CEIL,
} dcc_cs_cmd_type_e;

#ifdef __cplusplus
}
#endif

#endif
