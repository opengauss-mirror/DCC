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
 * gstor_param.c
 *    gstor param
 *
 * IDENTIFICATION
 *    src/storage/gstor/gstor_param.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_defs.h"
#include "gstor_param.h"

config_item_t g_parameters[] = {
    // name (30B)          isdefault   attr       defaultvalue     value  runtime   desc    range    datatype
    // -------------       ---------   ----       ------------     -----  -------   -----   -----    --------
    { "DATA_BUFFER_SIZE",     GS_TRUE, ATTR_NONE, "128M",           NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
    { "BUF_POOL_NUM",         GS_TRUE, ATTR_NONE, "1",              NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
#ifdef DCC_LITE
    { "LOG_BUFFER_SIZE",      GS_TRUE, ATTR_NONE, "1M",            NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
    { "LOG_BUFFER_COUNT",     GS_TRUE, ATTR_NONE, "1",              NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
#else
    { "LOG_BUFFER_SIZE",      GS_TRUE, ATTR_NONE, "16M",            NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
    { "LOG_BUFFER_COUNT",     GS_TRUE, ATTR_NONE, "4",              NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
#endif
    { "PAGE_SIZE",            GS_TRUE, ATTR_NONE, "8K",             NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
    { "SPACE_SIZE",           GS_TRUE, ATTR_NONE, "128M",           NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
    { "USE_LARGE_PAGES",      GS_TRUE, ATTR_NONE, "TRUE",           NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
    { "UNDO_TABLESPACE",      GS_TRUE, ATTR_NONE, "UNDO",           NULL,  NULL,     "-",    "-",  "GS_TYPE_INTEGER" },
    { "CONTROL_FILES",        GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_FORMAT",       GS_TRUE, ATTR_NONE, "arch_%r_%s.arc", NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_1",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_2",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_3",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_4",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_5",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_6",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_7",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_8",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_9",       GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_10",      GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_1", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_2", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_3", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_4", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_5", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_6", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_7", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_8", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_9", GS_TRUE, ATTR_NONE, "ENABLE",         NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "ARCHIVE_DEST_STATE_10", GS_TRUE, ATTR_NONE, "ENABLE",        NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "_SYS_PASSWORD",        GS_TRUE, ATTR_NONE, "",               NULL,  NULL,     "-",    "-",  "GS_TYPE_VARCHAR" },
    { "LOG_LEVEL",           GS_TRUE, ATTR_NONE, "",           NULL,  NULL,     "-",    "-",     "GS_TYPE_INTEGER" },
};

void knl_param_get_config_info(config_item_t **params, uint32 *count)
{
    *params = g_parameters;
    *count = sizeof(g_parameters) / sizeof(config_item_t);
}

status_t knl_param_get_size_uint64(config_t *config, char *param_name, uint64 *param_value)
{
    char *value = cm_get_config_value(config, param_name);
    if (value == NULL || strlen(value) == 0) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }
    int64 val_int64 = 0;
    if (cm_str2size(value, &val_int64) != GS_SUCCESS || val_int64 < 0) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }
    *param_value = (uint64)val_int64;
    return GS_SUCCESS;
}

status_t knl_param_get_uint32(config_t *config, char *param_name, uint32 *param_value)
{
    char *value = cm_get_config_value(config, param_name);
    if (value == NULL || strlen(value) == 0) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }

    if (cm_str2uint32(value, param_value) != GS_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t knl_param_get_size_uint32(config_t *config, char *param_name, uint32 *param_value)
{
    char *value = cm_get_config_value(config, param_name);
    int64 val_int64 = 0;

    if (value == NULL || strlen(value) == 0) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }

    if (cm_str2size(value, &val_int64) != GS_SUCCESS || val_int64 < 0 || val_int64 > UINT_MAX) {
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, param_name);
        return GS_ERROR;
    }

    *param_value = (uint32)val_int64;
    return GS_SUCCESS;
}
