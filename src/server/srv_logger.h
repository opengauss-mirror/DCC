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
 * srv_logger.h
 *
 *
 * IDENTIFICATION
 *    src/server/srv_logger.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef SRV_LOGGER_H
#define SRV_LOGGER_H
#include "cm_error.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t init_logger(void);
void uninit_logger(void);

#ifdef __cplusplus
}
#endif

#endif