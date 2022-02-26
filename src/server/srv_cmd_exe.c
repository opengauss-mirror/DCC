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
 * srv_cmd_exe.c
 *
 *
 * IDENTIFICATION
 *    src/server/srv_cmd_exe.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcc_interface.h"
#include "dcc_cmd_parse.h"
#include "srv_session.h"
#include "cm_error.h"

#define SRV_NEW_LINE    "\n"

static status_t srv_show_version(session_t *session, dcc_text_t *ans_buf)
{
    const char *version = srv_dcc_get_version();
    uint32 len = (uint32) strlen(version);
    MEMS_RETURN_IFERR(memcpy_sp((session)->req_buf, SRV_SESS_API_REQ_BUFF_LEN, version, len));
    MEMS_RETURN_IFERR(
        memcpy_sp(session->req_buf + len, SRV_SESS_API_REQ_BUFF_LEN - len, SRV_NEW_LINE, sizeof(SRV_NEW_LINE)));
    ans_buf->len = len + sizeof(SRV_NEW_LINE);
    return CM_SUCCESS;
}

static status_t srv_show_help(session_t *session, dcc_text_t *ans_buf)
{
    uint32 len;
    const char *help = "\nOptions:\n"
                       "   --help, -h      Shows help information\n"
                       "   --version, -v,   Shows version information\n"
                       "\nCommand:\n"
                       "   --get key       Queries the value of a specified key\n"
                       "       Command options:\n"
                       "           --prefix: Prefix matching query\n"
                       "   --put key val   Updates or insert the value of a specified key\n"
                       "   --delete key    Deletes the specified key\n"
                       "       Command options:\n"
                       "           --prefix: Prefix matching delete\n"
                       "   --cluster_info  Query dcc cluster information\n"
                       "   --leader_info   Query dcc leader information\n";
    len = (uint32) strlen(help);
    MEMS_RETURN_IFERR(memcpy_sp(session->req_buf, SRV_SESS_API_REQ_BUFF_LEN, help, len + 1));
    ans_buf->len = len + 1;
    return CM_SUCCESS;
}

static status_t srv_cmd_fix_kv(session_t *session, dcc_text_t *key, dcc_text_t *val, int *cur)
{
    if (key->len + (uint32)*cur + 1 < SRV_SESS_API_REQ_BUFF_LEN) {
        MEMS_RETURN_IFERR(memcpy_sp(session->req_buf + *cur, SRV_SESS_API_REQ_BUFF_LEN - *cur, key->value, key->len));
        (*cur) += (int)key->len;
        MEMS_RETURN_IFERR(memcpy_sp(session->req_buf + *cur, SRV_SESS_API_REQ_BUFF_LEN - *cur, SRV_NEW_LINE, 1));
        (*cur) += 1;
    }
    if (val->len + (uint32)*cur + 1 < SRV_SESS_API_REQ_BUFF_LEN) {
        MEMS_RETURN_IFERR(memcpy_sp(session->req_buf + *cur, SRV_SESS_API_REQ_BUFF_LEN - *cur, val->value, val->len));
        (*cur) += (int)val->len;
        MEMS_RETURN_IFERR(memcpy_sp(session->req_buf + *cur, SRV_SESS_API_REQ_BUFF_LEN - *cur, SRV_NEW_LINE, 1));
        (*cur) += 1;
    }

    return CM_SUCCESS;
}

static status_t srv_execute_get(session_t *session, ctl_command_t * cmd, dcc_text_t *ans_buf)
{
    dcc_text_t query_key = {.len = cmd->key_len, .value = cmd->key};
    dcc_option_t option = {0};
    option.read_op.read_level = cmd->command_option.read_level;
    option.read_op.is_prefix = cmd->command_option.prefix;
    dcc_text_t key = {0};
    dcc_text_t val = {0};
    unsigned int eof = 0;

    CM_RETURN_IFERR(srv_dcc_get((void *) session, &query_key, &option, &key, &val, &eof));
    if (option.read_op.is_prefix == 1) {
        int cur = 0;
        CM_RETURN_IFERR(srv_cmd_fix_kv(session, &key, &val, &cur));
        if (eof == 1) {
            return CM_SUCCESS;
        }
        while (srv_dcc_fetch((void *) session, &key, &val, &option, &eof) == CM_SUCCESS) {
            CM_RETURN_IFERR(srv_cmd_fix_kv(session, &key, &val, &cur));
        }
        if ((uint32)cur < SRV_SESS_API_REQ_BUFF_LEN) {
            ans_buf->value[cur] = '\0';
            ans_buf->len = (uint32)cur + 1;
        } else {
            return CM_ERROR;
        }
    } else {
        MEMS_RETURN_IFERR(memcpy_sp(session->req_buf, SRV_SESS_API_REQ_BUFF_LEN, val.value, val.len));
        MEMS_RETURN_IFERR(memcpy_sp(
            session->req_buf + val.len, SRV_SESS_API_REQ_BUFF_LEN - val.len, SRV_NEW_LINE, sizeof(SRV_NEW_LINE)));
        ans_buf->len = val.len + sizeof(SRV_NEW_LINE);
    }
    return CM_SUCCESS;
}

static status_t srv_execute_put(session_t *session, ctl_command_t * cmd, dcc_text_t *ans_buf)
{
    dcc_text_t key = {.len = cmd->key_len, .value = cmd->key};
    dcc_text_t val = {.len = cmd->val_len, .value = cmd->val};

    dcc_option_t option = {0};
    option.write_op.expect_val_size = cmd->command_option.expect_val_len;
    option.write_op.sequence = cmd->command_option.sequence;
    option.write_op.expect_value = cmd->command_option.expect_val;
    option.cmd_timeout = cmd->global_option.time_out;
    CM_RETURN_IFERR(srv_dcc_put((void *) session, &key, &val, &option));
    return CM_SUCCESS;
}

static status_t srv_execute_delete(session_t *session, ctl_command_t * cmd, dcc_text_t *ans_buf)
{
    dcc_text_t key = {.len = cmd->key_len, .value = cmd->key};

    dcc_option_t option = {0};
    option.del_op.is_prefix = cmd->command_option.prefix;
    option.cmd_timeout = cmd->global_option.time_out;
    CM_RETURN_IFERR(srv_dcc_delete((void *) session, &key, &option));
    return CM_SUCCESS;
}

static status_t srv_execute_query_cluster(session_t *session, dcc_text_t *ans_buf)
{
    CM_CHECK_NULL_PTR(session->req_buf);

    char *buffer = session->req_buf;
    buffer[0] = '\0';
    int len = srv_dcc_query_cluster_info(buffer, SRV_SESS_API_REQ_BUFF_LEN);
    if (len == 0) {
        LOG_DEBUG_ERR("srv_dcc_query_cluster_info failed");
        return CM_ERROR;
    }
    ans_buf->len = (uint32)strlen(buffer) + 1;
    return CM_SUCCESS;
}

static status_t srv_execute_query_leader(session_t *session, dcc_text_t *ans_buf)
{
    char *buffer = session->req_buf;
    CM_CHECK_NULL_PTR(buffer);
    buffer[0] = '\0';
    uint32 leader_id = 0;
    int ret = srv_dcc_query_leader_info(&leader_id);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("srv_dcc_query_leader_info failed");
        return ret;
    }
    int len = sprintf_s(buffer, SRV_SESS_API_REQ_BUFF_LEN, "%u", leader_id);
    if (len < 0 || (uint32)len > SRV_SESS_API_REQ_BUFF_LEN) {
        return CM_ERROR;
    }
    ans_buf->len = (uint32)strlen(buffer) + 1;
    return CM_SUCCESS;
}

status_t srv_exec_cmd_process(session_t *session, ctl_command_t *cmd, dcc_text_t *ans_buf)
{
    status_t ret = CM_SUCCESS;
    switch (cmd->type) {
        case CTL_KEYWORD_VERSION:
            (void)srv_show_version(session, ans_buf);
            break;
        case CTL_KEYWORD_HELP:
            (void)srv_show_help(session, ans_buf);
            break;
        case CTL_KEYWORD_GET:
            ret = srv_execute_get(session, cmd, ans_buf);
            break;
        case CTL_KEYWORD_PUT:
            ret = srv_execute_put(session, cmd, ans_buf);
            break;
        case CTL_KEYWORD_DELETE:
            ret = srv_execute_delete(session, cmd, ans_buf);
            break;
        case CTL_KEYWORD_QUERY_CLUSTER:
            ret = srv_execute_query_cluster(session, ans_buf);
            break;
        case CTL_KEYWORD_QUERY_LEADER:
            ret = srv_execute_query_leader(session, ans_buf);
            break;
        default:
            CM_THROW_ERROR(ERR_INVALID_CMD_TYPE, "");
            ret = CM_ERROR;
            break;
    }
    return ret;
}
