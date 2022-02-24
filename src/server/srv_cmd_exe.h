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
 * srv_cmd_exe.h
 *
 *
 * IDENTIFICATION
 *    src/server/srv_cmd_exe.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SRV_CMD_EXE_H
#define __SRV_CMD_EXE_H

#include "srv_session.h"
#include "dcc_cmd_parse.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t srv_exec_cmd_process(session_t *session, ctl_command_t *cmd, dcc_text_t *ans_buf);

#ifdef __cplusplus
}
#endif

#endif
