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
 * srv_config.h
 *
 *
 * IDENTIFICATION
 *    src/server/srv_config.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SRV_CONFIG_H
#define __SRV_CONFIG_H

#include "srv_param.h"

#ifdef __cplusplus
extern "C" {
#endif


#define MAX_CONFIG_FILE_SIZE SIZE_K(64)
#define SRV_MAX_CONFIG_LINE_SIZE SIZE_K(4)
#define MAX_CONFIG_ITEM_COUNT (uint32)(DCC_PARAM_CEIL - 1)
#define MAX_CONFIG_COMMENT_LEN (uint32)(SRV_MAX_CONFIG_LINE_SIZE - 1)

typedef struct st_config_item {
    uint32 param_id;
    text_t comment;
    char config_name[MAX_PARAM_NAME_LEN + 1];
    char config_value[MAX_PARAM_VALUE_LEN + 1];
    struct st_config_item *next;
} config_item_t;
typedef struct st_srv_config {
    int32 file;
    char file_name[CM_FILE_NAME_BUFFER_SIZE];
    char file_buf[MAX_CONFIG_FILE_SIZE];
    char write_buf[MAX_CONFIG_FILE_SIZE];
    uint32 text_size;
    config_item_t *item_first;
    config_item_t items[MAX_CONFIG_ITEM_COUNT + 1];
} srv_config_t;
typedef struct st_config_stream {
    srv_config_t *config;
    uint32 offset;
} srv_config_stream_t;

typedef enum READ_CONFIG_MODE_E {
    READ_INIT,
    READ_RELOAD
} READ_CONFIG_MODE;
// called when first init from config file
status_t init_config(void);
void deinit_config(void);


// called when changed parameters from session (which from client)
status_t srv_set_config(const char* config_param_name, const char* config_param_value);

#ifdef __cplusplus
}
#endif

#endif
// __SRV_CONFIG_H
