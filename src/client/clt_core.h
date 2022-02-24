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
 * clt_core.h
 *
 *
 * IDENTIFICATION
 *    src/client/clt_core.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CLT_CORE_H__
#define __CLT_CORE_H__

#include "cs_packet.h"
#include "clt_defs.h"
#include "dcc_msg_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLT_NO_TRY_CNT      ((int32)1)
#define CLT_TRY_ONCE        ((int32)2)

status_t clt_init_handle(clt_handle_t **handle, const dcc_open_option_t *open_option);

status_t clt_init_conn(clt_handle_t *handle);

void clt_deinit(clt_handle_t **handle);

void clt_register_net_proc(void);

status_t clt_process_sync_cmd(clt_handle_t *handle, uint8 cmd, void *request, int32 try_cnt);

status_t clt_wait_session_id(clt_handle_t *handle);

status_t clt_fetch_from_pack(clt_handle_t *handle, dcc_result_t *result);

status_t clt_parse_children(clt_handle_t *handle, dcc_array_t *result);

status_t clt_get_lease_info_from_pack(clt_handle_t *handle, dcc_lease_info_t *lease_info);

int clt_lease_keep_alive(clt_handle_t *handle, const dcc_string_t *lease_name);

#ifdef __cplusplus
}
#endif

#endif
