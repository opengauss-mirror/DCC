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
 * executor_watch_group.h
 *
 *
 * IDENTIFICATION
 *    src/executor/executor_watch_group.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __EXECUTOR_WATCH_GROUP_H__
#define __EXECUTOR_WATCH_GROUP_H__

#include "interval_tree.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t exc_watch_group_init(void);
status_t exc_watch_group_insert(const text_t *key, uint32 sid, dcc_watch_proc_t proc, text_t* watch_key);
void exc_watch_group_delete(const text_t *key, uint32 sid);
status_t  exc_watch_group_proc(msg_entry_t* entry, int event_type);
void exc_watch_group_deinit(void);

#ifdef __cplusplus
}
#endif

#endif