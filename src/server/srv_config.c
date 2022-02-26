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
 * srv_config.c
 *
 *
 * IDENTIFICATION
 *    src/server/srv_config.c
 *
 * -------------------------------------------------------------------------
 */


#include <cm_file.h>
#include <cm_date.h>
#include "cm_timer.h"
#include "srv_config.h"
#include "util_error.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char *g_srv_config_file = "dcc_server.ini";
spinlock_t g_srv_config_lock = 0;
srv_config_t *g_srv_config = NULL;
bool32 g_srv_config_init = CM_FALSE;
thread_t g_srv_config_mon_thread;
#define STAT_THREAD_SLEEP_TIME 100
#define DEFAULT_CHK_FILE_INTERVAL 800 // ms


static status_t open_config_stream(srv_config_t *config, srv_config_stream_t *stream)
{
    char backup_name[CM_FILE_NAME_BUFFER_SIZE] = {'\0'};
    CM_CHECK_NULL_PTR(config);
    CM_CHECK_NULL_PTR(stream);

    stream->config = config;
    stream->offset = 0;
    config->write_buf[0] = '\0';

    PRTS_RETURN_IFERR(snprintf_s(backup_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s_bak",
                                 config->file_name));

    if (cm_copy_file(config->file_name, backup_name, CM_TRUE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    PRTS_RETURN_IFERR(snprintf_s(backup_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s_tmp",
                                 config->file_name));

    if (cm_open_file(backup_name, O_CREAT | O_RDWR | O_BINARY | O_SYNC | O_TRUNC, &config->file) != CM_SUCCESS) {
        return CM_ERROR;
    }
    (void) cm_chmod_file(S_IRUSR | S_IWUSR, config->file);

    return CM_SUCCESS;
}

static status_t write_config_stream(srv_config_stream_t *stream, const char *str)
{
    uint32 len;
    CM_CHECK_NULL_PTR(stream);

    if (str == NULL) {
        return CM_SUCCESS;
    }

    len = (uint32) strlen(str);
    if (len == 0) {
        return CM_SUCCESS;
    }

    if (stream->offset + len > MAX_CONFIG_FILE_SIZE) {
        if (cm_write_file(stream->config->file, stream->config->write_buf, (int32) stream->offset) != CM_SUCCESS) {
            return CM_ERROR;
        }

        stream->offset = 0;
    }

    MEMS_RETURN_IFERR(memcpy_sp(stream->config->write_buf + stream->offset,
                                (size_t) (MAX_CONFIG_FILE_SIZE - stream->offset), str, (size_t) len));

    stream->offset += len;
    return CM_SUCCESS;
}


static status_t close_config_stream(srv_config_stream_t *stream)
{
    CM_CHECK_NULL_PTR(stream);

    if (stream->offset > 0) {
        if (cm_write_file(stream->config->file, stream->config->write_buf, (int32) stream->offset) != CM_SUCCESS) {
            return CM_ERROR;
        }

        stream->offset = 0;
    }

    cm_close_file(stream->config->file);

    // a tmp file rename formal config file
    char temp_name[CM_FILE_NAME_BUFFER_SIZE];
    PRTS_RETURN_IFERR(snprintf_s(temp_name,
                                 CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s_tmp",
                                 stream->config->file_name));

    return cm_rename_file(temp_name, stream->config->file_name);
}

static status_t srv_write_config(srv_config_t *config)
{
    CM_CHECK_NULL_PTR(config);
    srv_config_stream_t stream = {0};
    char comment[MAX_CONFIG_COMMENT_LEN + 1] = {0};
    CM_RETURN_IFERR(open_config_stream(config, &stream));
    config_item_t *item = config->item_first;
    while (item != NULL) {
        // write comment
        if (!CM_IS_EMPTY_STR(item->comment.str)) {
            CM_RETURN_IFERR(cm_text2str(&(item->comment), comment, MAX_CONFIG_COMMENT_LEN + 1));
            CM_RETURN_IFERR(write_config_stream(&stream, comment));
            CM_RETURN_IFERR(write_config_stream(&stream, "\n"));
        }
        // write param name and value
        if (CM_IS_EMPTY_STR(item->config_name) || CM_IS_EMPTY_STR(item->config_value)) {
            item = item->next;
            continue;
        }
        CM_RETURN_IFERR(write_config_stream(&stream, item->config_name));
        CM_RETURN_IFERR(write_config_stream(&stream, " = "));
        CM_RETURN_IFERR(write_config_stream(&stream, item->config_value));
        CM_RETURN_IFERR(write_config_stream(&stream, "\n"));
        item = item->next;
    }
    return close_config_stream(&stream);
}

status_t srv_set_config(const char *config_param_name, const char *config_param_value)
{
    CM_CHECK_NULL_PTR(g_srv_config);
    CM_RETURN_IFERR(srv_set_param(config_param_name, config_param_value));
    uint32 param_id;
    CM_RETURN_IFERR(get_param_id_by_name(config_param_name, &param_id));
    config_item_t *item = g_srv_config->item_first;
    // only save param already contained in config file
    while (item != NULL) {
        if (item->param_id == param_id && param_id != 0) {
            MEMS_RETURN_IFERR(strncpy_s(item->config_value, MAX_PARAM_VALUE_LEN + 1,
                                        config_param_value, strlen(config_param_value)));
            break;
        }
        item = item->next;
    }

    status_t ret = srv_write_config(g_srv_config);
    return ret;
}

static status_t config_set_comment(text_t *comment, text_t *comment_data)
{
    CM_CHECK_NULL_PTR(comment);
    CM_CHECK_NULL_PTR(comment_data);
    if (comment_data->len == 0) {
        comment->str = NULL;
        comment->len = 0;
        return CM_SUCCESS;
    } else if (comment_data->len > MAX_CONFIG_COMMENT_LEN) {
        CM_THROW_ERROR(ERR_PARAM_COMMENT_TOO_LONG, comment_data->len, comment_data->str);
        return CM_ERROR;
    }

    comment->str = comment_data->str;
    comment->len = comment_data->len;

    return CM_SUCCESS;
}

static status_t check_duplicate_config_item(srv_config_t *config, uint32 param_id)
{
    CM_CHECK_NULL_PTR(config);
    if (param_id == 0 || param_id >= DCC_PARAM_CEIL) {
        return CM_ERROR;
    }
    config_item_t *tmp = config->item_first;
    while (tmp != NULL) {
        if (tmp->param_id == param_id) {
            return CM_ERROR;
        }
        tmp = tmp->next;
    }
    return CM_SUCCESS;
}

static status_t set_config_item(
    srv_config_t *config, text_t *name, text_t *value, text_t *comment, READ_CONFIG_MODE read_mode)
{
    uint32 param_id = 0;
    status_t ret;
    char param_name[MAX_PARAM_NAME_LEN + 1] = {0};
    char param_value[MAX_PARAM_VALUE_LEN + 1] = {0};
    if (name != NULL && value != NULL) {
        CM_RETURN_IFERR(cm_text2str(name, param_name, MAX_PARAM_NAME_LEN + 1));
        CM_RETURN_IFERR(get_param_id_by_name(param_name, &param_id));
        ret = check_duplicate_config_item(config, param_id);
        if (ret != CM_SUCCESS) {
            CM_THROW_ERROR(ERR_DUPLICATE_PARAMETER, param_name);
            return CM_ERROR;
        }
        CM_RETURN_IFERR(cm_text2str(value, param_value, MAX_PARAM_VALUE_LEN + 1));
        if (read_mode == READ_INIT || (read_mode == READ_RELOAD && is_param_can_reloaded(param_id))) {
            if (param_id == DCC_PARAM_DCF_CONFIG) {
                char dcf_config_val[MAX_PARAM_ENDPOINT_LIST_SIZE] = {0};
                CM_RETURN_IFERR(cm_text2str(value, dcf_config_val, MAX_PARAM_ENDPOINT_LIST_SIZE));
                CM_RETURN_IFERR(srv_set_param(param_name, dcf_config_val));
            } else {
                CM_RETURN_IFERR(srv_set_param(param_name, param_value));
            }
        }
        CM_RETURN_IFERR(cm_text2str(value, config->items[param_id].config_value, MAX_PARAM_VALUE_LEN + 1));
        CM_RETURN_IFERR(cm_text2str(name, config->items[param_id].config_name, MAX_PARAM_NAME_LEN + 1));
    }
    CM_RETURN_IFERR(config_set_comment(&config->items[param_id].comment, comment));
    config->items[param_id].param_id = param_id;
    if (config->item_first == NULL) {
        config->item_first = &config->items[param_id];
    } else {
        config_item_t *tmp = config->item_first;
        while (tmp->next != NULL) {
            tmp = tmp->next;
        }
        tmp->next = &config->items[param_id];
    }
    return CM_SUCCESS;
}

static status_t srv_read_config_file(const char *file_name, char *buf, uint32 *buf_len)
{
    int32 file_fd;
    status_t status;
    uint32 mode = (O_CREAT | O_RDWR | O_BINARY);

    if (!cm_file_exist(file_name)) {
        CM_THROW_ERROR(ERR_FILE_NOT_EXIST, "config", file_name);
        return CM_ERROR;
    }

    if (cm_open_file(file_name, mode, &file_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int64 size = cm_file_size(file_fd);
    if (size == -1) {
        cm_close_file(file_fd);
        CM_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_END, errno);
        return CM_ERROR;
    }

    if (size > (int64) (*buf_len)) {
        cm_close_file(file_fd);
        CM_THROW_ERROR(ERR_FILE_SIZE_TOO_LARGE, file_name);
        return CM_ERROR;
    }

    if (cm_seek_file(file_fd, 0, SEEK_SET) != 0) {
        cm_close_file(file_fd);
        CM_THROW_ERROR(ERR_SEEK_FILE, 0, SEEK_SET, errno);
        return CM_ERROR;
    }

    status = cm_read_file(file_fd, buf, (int32) size, (int32 *) buf_len);
    cm_close_file(file_fd);
    return status;
}

static status_t valid_config_param_name(const text_t *name)
{
    if (name == NULL || name->len == 0) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, " ");
        return CM_ERROR;
    }
    // invisible param for user
    if (cm_text_str_equal_ins(name, "DATA_PATH")) {
        CM_THROW_ERROR(ERR_INVALID_PARAMETER_NAME, "DATA_PATH");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t srv_parse_config(srv_config_t *config, char *buf, uint32 buf_len, READ_CONFIG_MODE read_mode)
{
    uint32 line_no;
    text_t text, line, comment, name, value;
    CM_CHECK_NULL_PTR(config);

    text.len = buf_len;
    text.str = buf;
    comment.str = text.str;
    comment.len = 0;
    line_no = 0;

    while (cm_fetch_text(&text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        line_no++;
        cm_trim_text(&line);
        if (line.len >= SRV_MAX_CONFIG_LINE_SIZE) {
            CM_THROW_ERROR(ERR_LINE_SIZE_TOO_LONG, line_no);
            return CM_ERROR;
        }

        if (line.len == 0 || *line.str == '#') { /* commented line */
            continue;
        }

        comment.len = (uint32) (line.str - comment.str);
        cm_split_text(&line, '=', '\0', &name, &value);
        cm_text_upper(&name);  // case insensitive
        cm_trim_text(&name);
        CM_RETURN_IFERR(valid_config_param_name(&name));
        cm_trim_text(&value);
        cm_trim_text(&comment);
        CM_RETURN_IFERR(set_config_item(config, &name, &value, &comment, read_mode));
        comment.str = text.str;
        comment.len = 0;
    }
    // handle last comment in config file
    if (!CM_IS_EMPTY_STR(comment.str) && CM_TEXT_BEGIN(&comment) == '#') {
        comment.len = (uint32)strlen(comment.str);
        if (CM_TEXT_END(&comment) == '\n') {
            comment.len--;
        }
        CM_RETURN_IFERR(set_config_item(config, NULL, NULL, &comment, read_mode));
    }

    return CM_SUCCESS;
}

static status_t srv_read_config(const char *file_name, srv_config_t *config, READ_CONFIG_MODE read_mode)
{
    CM_CHECK_NULL_PTR(file_name);
    CM_CHECK_NULL_PTR(config);
    size_t name_len = strlen(file_name);
    errno_t errcode;
    cm_reset_error();
    errcode = strncpy_s(config->file_name, CM_FILE_NAME_BUFFER_SIZE, file_name, (size_t) name_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    config->text_size = sizeof(config->file_buf);
    MEMS_RETURN_IFERR(memset_sp(config->file_buf, sizeof(config->file_buf), 0,
        sizeof(config->file_buf)));
    if (srv_read_config_file(file_name, config->file_buf, &config->text_size) != CM_SUCCESS) {
        return CM_ERROR;
    }
    status_t ret = srv_parse_config(config, config->file_buf, config->text_size, read_mode);

    return ret;
}

static void reset_config_item_list(void)
{
    if (g_srv_config == NULL) {
        return;
    }
    if (g_srv_config->item_first != NULL) {
        config_item_t *cur = g_srv_config->item_first;
        config_item_t *tmp = cur;
        while (tmp) {
            cur = cur->next;
            tmp->next = NULL;
            tmp = cur;
        }
        g_srv_config->item_first = NULL;
    }
}

static void srv_config_mon_entry(thread_t *thread)
{
    cm_set_thread_name("srv_config_mon");
    date_t last_check_time = g_timer()->now;
    int64 file_last_size = 0;
    int64 file_last_modified_time = 0;
    struct stat file_attr;
    if (cm_file_exist(g_srv_config->file_name)) {
        stat(g_srv_config->file_name, &file_attr);
        file_last_modified_time = file_attr.st_mtime;
        file_last_size = file_attr.st_size;
    }

    while (!thread->closed) {
        cm_sleep(STAT_THREAD_SLEEP_TIME);
        date_t now = g_timer()->now;
        if (now - last_check_time < DEFAULT_CHK_FILE_INTERVAL * MICROSECS_PER_MILLISEC) {
            continue;
        }
        last_check_time = now;
        if (!cm_file_exist(g_srv_config->file_name)) {
            continue;
        }
        stat(g_srv_config->file_name, &file_attr);
        if (file_attr.st_size != file_last_size || file_attr.st_mtime > file_last_modified_time) {
            LOG_DEBUG_INF("[CFG] try to load file");
            reset_config_item_list();

            status_t ret = srv_read_config(g_srv_config->file_name, g_srv_config, READ_RELOAD);
            if (ret != CM_SUCCESS) {
                LOG_DEBUG_ERR("[CFG] reload config file error, errcode:%d, errmsg:%s",
                    cm_get_error_code(),
                    cm_get_errormsg(cm_get_error_code()));
            }
            LOG_DEBUG_INF("[CFG] config read success");
            file_last_size = file_attr.st_size;
            file_last_modified_time = file_attr.st_mtime;
        }
    }
}

static status_t srv_init_config(char *file_name)
{
    errno_t errcode;
    if (g_srv_config == NULL) {
        g_srv_config = (srv_config_t *) malloc(sizeof(srv_config_t));
        if (g_srv_config == NULL) {
            return CM_ERROR;
        }
        errcode = memset_s(g_srv_config, sizeof(srv_config_t), 0, sizeof(srv_config_t));
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }
    }
    param_value_t param_data_path;
    char real_path[CM_FILE_NAME_BUFFER_SIZE] = {0};
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DATA_PATH, &param_data_path));
    CM_RETURN_IFERR(realpath_file(param_data_path.str_val, real_path, CM_FILE_NAME_BUFFER_SIZE));

    errcode = snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE,
        CM_FILE_NAME_BUFFER_SIZE - 1, "%s/cfg/%s", real_path, g_srv_config_file);
    if (errcode == -1) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    if (!cm_file_exist(file_name)) {
        CM_THROW_ERROR(ERR_FILE_NOT_EXIST, "config", "dcc_server.ini");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t init_config(void)
{
    if (g_srv_config_init) {
        return CM_SUCCESS;
    }
    status_t ret;
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    cm_reset_error();
    init_dcc_errno_desc();
    cm_spin_lock(&g_srv_config_lock, NULL);
    ret = srv_init_config(file_name);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(g_srv_config);
        cm_spin_unlock(&g_srv_config_lock);
        return CM_ERROR;
    }
    ret = srv_read_config(file_name, g_srv_config, READ_INIT);
    cm_spin_unlock(&g_srv_config_lock);
    CM_RETURN_IFERR(ret);
    CM_RETURN_IFERR(cm_create_thread(srv_config_mon_entry, 0, NULL, &g_srv_config_mon_thread));
    g_srv_config_init = CM_TRUE;
    return CM_SUCCESS;
}

void deinit_config(void)
{
    if (g_srv_config_init) {
        cm_close_thread(&g_srv_config_mon_thread);
        CM_FREE_PTR(g_srv_config);
    }
    g_srv_config_init = CM_FALSE;
}


#ifdef __cplusplus
}
#endif
