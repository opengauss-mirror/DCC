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
 * gstor_handle.h
 *    gstor handle
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_handle.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_HANDLE_H__
#define __KNL_HANDLE_H__

#include "cm_defs.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t knl_alloc_cursor(knl_cursor_t **cursor);

void knl_free_session(knl_session_t *knl_session);

void knl_cleanup_session(knl_session_t *knl_session);

status_t knl_alloc_session(knl_session_t **knl_session);

void knl_free_sys_sessions(void);

status_t knl_alloc_sys_sessions(void);

#ifdef __cplusplus
}
#endif

#endif
