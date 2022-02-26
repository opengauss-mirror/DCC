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
 * gstor_adpt.h
 *    gstor adapter
 *
 * IDENTIFICATION
 *    src/storage/gstor_adpt.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __V3_ADAPTER_H__
#define __V3_ADAPTER_H__

#include "cm_error.h"
#include "gstor_executor.h"

status_t load_gstor_params(char *path);

#endif