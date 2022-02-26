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
 * dcc_cmd_parse.c
 *    Client tool
 *
 * IDENTIFICATION
 *    src/utils/parse/dcc_cmd_parse.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcc_cmd_parse.h"
#include "cm_defs.h"
#include "cm_num.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline status_t ctl_parse_val(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR((argc == *cur));
    ctl_command->val = argv[*cur].str;
    ctl_command->val_len = argv[*cur].len;
    ++(*cur);
    return CM_SUCCESS;
}

static inline status_t ctl_parse_ept_val(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR((argc == *cur));
    ctl_command->command_option.expect_val = argv[*cur].str;
    ctl_command->command_option.expect_val_len = argv[*cur].len;
    ++(*cur);
    return CM_SUCCESS;
}

static inline status_t ctl_parse_key(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR((argc == *cur));
    ctl_command->key = argv[*cur].str;
    ctl_command->key_len = argv[*cur].len;
    ++(*cur);
    return CM_SUCCESS;
}

static inline uint32 ctl_has_command(uint32 flag, const ctl_command_t *ctl_command)
{
    return ctl_command->flag & flag;
}

static inline void ctl_set_command(uint32 flag, ctl_command_t *ctl_command)
{
    ctl_command->flag |= flag;
}

static status_t ctl_check_dup_command(uint32 flag, ctl_command_t *ctl_command)
{
    if (ctl_has_command(flag, ctl_command) > 0) {
        return CM_ERROR;
    }

    ctl_set_command(flag, ctl_command);

    return CM_SUCCESS;
}

static status_t ctl_parse_endpoints(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_ENDPOINTS, ctl_command));

    CM_RETURN_IFERR((argc == *cur));
    ctl_command->global_option.server_list = argv[*cur].str;
    ctl_command->global_option.flag |= CTL_OPTION_ENDPOINTS;
    ++(*cur);

    return CM_SUCCESS;
}

static status_t ctl_parse_timeout(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_TIMEOUT, ctl_command));

    CM_RETURN_IFERR((argc == *cur));
    CM_RETURN_IFERR(cm_str2uint32(argv[*cur].str, &ctl_command->global_option.time_out));
    ctl_command->global_option.flag |= CTL_OPTION_TIMEOUT;
    ++(*cur);

    return CM_SUCCESS;
}

static status_t ctl_parse_ssl_cacert(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_CACERT, ctl_command));

    CM_RETURN_IFERR((argc == *cur));
    ctl_command->global_option.ca_cert_file = argv[*cur].str;
    ctl_command->global_option.flag |= CTL_OPTION_CACERT;
    ++(*cur);

    return CM_SUCCESS;
}

static status_t ctl_parse_ssl_cert(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_CERT, ctl_command));

    CM_RETURN_IFERR((argc == *cur));
    ctl_command->global_option.cert_file = argv[*cur].str;
    ctl_command->global_option.flag |= CTL_OPTION_CERT;
    ++(*cur);

    return CM_SUCCESS;
}

static status_t ctl_parse_ssl_key(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_KEY, ctl_command));

    CM_RETURN_IFERR((argc == *cur));
    ctl_command->global_option.key_file = argv[*cur].str;
    ctl_command->global_option.flag |= CTL_OPTION_KEY;
    ++(*cur);

    return CM_SUCCESS;
}

static status_t ctl_parse_help(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_HELP, ctl_command));
    ctl_command->type = CTL_KEYWORD_HELP;
    return CM_SUCCESS;
}

static status_t ctl_parse_version(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_VERSION, ctl_command));
    ctl_command->type = CTL_KEYWORD_VERSION;
    return CM_SUCCESS;
}

static status_t ctl_parse_prefix(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_PREFIX, ctl_command));
    ctl_command->command_option.prefix = CM_TRUE;
    ctl_command->command_option.flag |= CTL_OPTION_PREFIX;
    return CM_SUCCESS;
}

static status_t ctl_parse_getchildren(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_GETCHILDREN, ctl_command));
    CM_RETURN_IFERR(ctl_parse_key(argv, argc, cur, ctl_command));
    ctl_command->type = CTL_KEYWORD_GETCHILDREN;
    return CM_SUCCESS;
}

static status_t ctl_parse_sequence(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_SEQUENCE, ctl_command));
    ctl_command->command_option.sequence = CM_TRUE;
    ctl_command->command_option.flag |= CTL_OPTION_SEQUENCE;
    return CM_SUCCESS;
}

static status_t ctl_parse_read_level(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_READ_LEVEL, ctl_command));
    CM_RETURN_IFERR((argc == *cur));
    CM_RETURN_IFERR(cm_str2uint32(argv[*cur].str, &ctl_command->command_option.read_level));
    ctl_command->global_option.flag |= CTL_OPTION_READ_LEVEL;
    ++(*cur);

    return CM_SUCCESS;
}

static status_t ctl_parse_expect_val(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_OPTION_EXPECT, ctl_command));
    CM_RETURN_IFERR(ctl_parse_ept_val(argv, argc, cur, ctl_command));
    ctl_command->command_option.flag |= CTL_OPTION_EXPECT;
    return CM_SUCCESS;
}

static status_t ctl_parse_get(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_GET, ctl_command));
    CM_RETURN_IFERR(ctl_parse_key(argv, argc, cur, ctl_command));
    ctl_command->type = CTL_KEYWORD_GET;
    return CM_SUCCESS;
}

static status_t ctl_parse_put(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_PUT, ctl_command));
    CM_RETURN_IFERR(ctl_parse_key(argv, argc, cur, ctl_command));
    CM_RETURN_IFERR(ctl_parse_val(argv, argc, cur, ctl_command));
    ctl_command->type = CTL_KEYWORD_PUT;

    return CM_SUCCESS;
}

static status_t ctl_parse_delete(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_DEL, ctl_command));
    CM_RETURN_IFERR(ctl_parse_key(argv, argc, cur, ctl_command));
    ctl_command->type = CTL_KEYWORD_DELETE;

    return CM_SUCCESS;
}

static status_t ctl_parse_watch(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_WATCH, ctl_command));
    CM_RETURN_IFERR(ctl_parse_key(argv, argc, cur, ctl_command));
    ctl_command->type = CTL_KEYWORD_WATCH;
    return CM_SUCCESS;
}

static status_t ctl_parse_query_cluster(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_QUERY_CLUSTER, ctl_command));
    ctl_command->type = CTL_KEYWORD_QUERY_CLUSTER;
    return CM_SUCCESS;
}

static status_t ctl_parse_query_leader(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_QUERY_LEADER, ctl_command));
    ctl_command->type = CTL_KEYWORD_QUERY_LEADER;
    return CM_SUCCESS;
}

static status_t clt_parse_lease_opt_type(const text_t *opt, clt_lease_opt_type_e *opt_type)
{
    if (cm_text_str_equal(opt, "create")) {
        *opt_type = CTL_LEASE_CREATE;
        return CM_SUCCESS;
    } else if (cm_text_str_equal(opt, "renew")) {
        *opt_type = CTL_LEASE_RENEW;
        return CM_SUCCESS;
    } else if (cm_text_str_equal(opt, "attach")) {
        *opt_type = CTL_LEASE_ATTACH;
        return CM_SUCCESS;
    } else if (cm_text_str_equal(opt, "destroy")) {
        *opt_type = CTL_LEASE_DESTROY;
        return CM_SUCCESS;
    } else if (cm_text_str_equal(opt, "query")) {
        *opt_type = CTL_LEASE_QUERY;
        return CM_SUCCESS;
    } else {
        return CM_ERROR;
    }
}

static status_t ctl_parse_lease_opt_and_args(const text_t argv[], int32 argc, int *cur,
    ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR((argc == *cur));

    clt_lease_opt_type_e opt_type;
    CM_RETURN_IFERR(clt_parse_lease_opt_type(&argv[*cur], &opt_type));
    if (ctl_command->type == CTL_KEYWORD_PUT && opt_type != CTL_LEASE_ATTACH) {
        return CM_ERROR;
    }
    ctl_command->command_option.lease_opt.opt_type = opt_type;
    ++(*cur);
    CM_RETURN_IFERR((argc == *cur));

    ctl_command->command_option.lease_opt.lease_name = argv[*cur].str;
    ctl_command->command_option.lease_opt.lease_name_len = argv[*cur].len;
    ++(*cur);
    if (opt_type == CTL_LEASE_CREATE) {
        CM_RETURN_IFERR((argc == *cur));
        CM_RETURN_IFERR(cm_str2uint32(argv[*cur].str, &(ctl_command->command_option.lease_opt.ttl)));
        ++(*cur);
    }

    return CM_SUCCESS;
}

static status_t ctl_parse_lease(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command)
{
    CM_RETURN_IFERR(ctl_check_dup_command(CTL_COMMAND_LEASE, ctl_command));
    CM_RETURN_IFERR(ctl_parse_lease_opt_and_args(argv, argc, cur, ctl_command));
    if (ctl_command->type != CTL_KEYWORD_PUT) {
        ctl_command->type = CTL_KEYWORD_LEASE;
    }
    return CM_SUCCESS;
}

ctl_option_item_t g_ctl_options[] = {
    {CTL_OPTION_HELP,           CTL_INIT_OPTION,    CTL_KEYWORD_HELP,          "--help",         ctl_parse_help},
    {CTL_OPTION_HELP,           CTL_INIT_OPTION,    CTL_KEYWORD_HELP,          "-h",             ctl_parse_help},
    {CTL_OPTION_VERSION,        CTL_INIT_OPTION,    CTL_KEYWORD_VERSION,       "--version",      ctl_parse_version},
    {CTL_OPTION_VERSION,        CTL_INIT_OPTION,    CTL_KEYWORD_VERSION,       "-v",             ctl_parse_version},
    {CTL_OPTION_ENDPOINTS,      CTL_ALL_OPTIONS,    CTL_KEYWORD_ENDPOINTS,     "--endpoints",    ctl_parse_endpoints},
    {CTL_OPTION_TIMEOUT,        CTL_ALL_OPTIONS,    CTL_KEYWORD_TIMEOUT,       "--timeout",      ctl_parse_timeout},
    {CTL_OPTION_CACERT,         CTL_ALL_OPTIONS,    CTL_KEYWORD_CACERT,        "--cacert",       ctl_parse_ssl_cacert},
    {CTL_OPTION_CERT,           CTL_ALL_OPTIONS,    CTL_KEYWORD_CERT,          "--cert",         ctl_parse_ssl_cert},
    {CTL_OPTION_KEY,            CTL_ALL_OPTIONS,    CTL_KEYWORD_KEY,           "--key",          ctl_parse_ssl_key},
    {CTL_OPTION_PREFIX,         CTL_PREFIX_SUB,     CTL_KEYWORD_PREFIX,        "--prefix",       ctl_parse_prefix},
    {CTL_OPTION_READ_LEVEL,     CTL_READ_LEVEl_SUB, CTL_KEYWORD_READ_LEVEL,    "--readlevel",    ctl_parse_read_level},
    {CTL_OPTION_EXPECT,         CTL_EXPECT_SUB,     CTL_KEYWORD_EXPECT,        "--expect",       ctl_parse_expect_val},
    {CTL_COMMAND_GET,           CTL_GET_SUB,        CTL_KEYWORD_GET,           "--get",          ctl_parse_get},
    {CTL_COMMAND_PUT,           CTL_PUT_SUB,        CTL_KEYWORD_PUT,           "--put",          ctl_parse_put},
    {CTL_COMMAND_DEL,           CTL_DELETE_SUB,     CTL_KEYWORD_DELETE,        "--delete",       ctl_parse_delete},
    {CTL_COMMAND_WATCH,         CTL_WATCH_SUB,      CTL_KEYWORD_WATCH,         "--watch",        ctl_parse_watch},
    {CTL_COMMAND_QUERY_CLUSTER, CTL_INIT_OPTION, CTL_KEYWORD_QUERY_CLUSTER, "--cluster_info", ctl_parse_query_cluster},
    {CTL_COMMAND_QUERY_LEADER,  CTL_INIT_OPTION, CTL_KEYWORD_QUERY_LEADER,  "--leader_info",  ctl_parse_query_leader},
    {CTL_COMMAND_LEASE,  CTL_LEASE_SUB, CTL_KEYWORD_LEASE,  "--lease",  ctl_parse_lease},
    {CTL_COMMAND_GETCHILDREN, CTL_GETCHILDREN_SUB, CTL_KEYWORD_GETCHILDREN, "--getchildren", ctl_parse_getchildren},
    {CTL_OPTION_SEQUENCE,   CTL_SEQUENCE_SUB,    CTL_KEYWORD_SEQUENCE,      "--sequence", ctl_parse_sequence},
};

static status_t ctl_parse_verify(const ctl_command_t *ctl_command)
{
    uint32 count = ELEMENT_COUNT(g_ctl_options);
    for (uint32 i = 0; i < count; i++) {
        if (g_ctl_options[i].type == ctl_command->type) {
            uint32 flag = g_ctl_options[i].opt_flag | g_ctl_options[i].sub_opt_flag;
            if ((flag | ctl_command->flag) <= flag) {
                return CM_SUCCESS;
            }
            break;
        }
    }

    return CM_ERROR;
}

status_t ctl_parse_process(const text_t argv[], int32 argc, int cur, ctl_command_t *ctl_command)
{
    bool8 has_command = CM_FALSE;
    if (argc == cur) {
        return CM_SUCCESS;
    }

    uint32 count = ELEMENT_COUNT(g_ctl_options);
    for (uint32 i = 0; i < count; i++) {
        if (cm_text_str_equal(&argv[cur], g_ctl_options[i].name)) {
            if (g_ctl_options[i].parse_command == NULL) {
                break;
            }
            ++cur;
            has_command = CM_TRUE;
            if (g_ctl_options[i].parse_command(argv, argc, &cur, ctl_command) != CM_SUCCESS) {
                return CM_ERROR;
            }
            break;
        }
    }

    if (has_command == CM_FALSE) {
        return ctl_parse_verify(ctl_command);
    }

    if (ctl_parse_process(argv, argc, cur, ctl_command) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return ctl_parse_verify(ctl_command);
}

#ifdef __cplusplus
}
#endif
