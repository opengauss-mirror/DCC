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
 * dcc_ctl_execute.c
 *    Client tool
 *
 * IDENTIFICATION
 *    src/tools/dcc_ctl/dcc_ctl_execute.c
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "dcc_ctl_execute.h"
#include "dcc_cmd_parse.h"
#include "clt_interface.h"
#include "cm_signal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTL_PRODUCT_NAME        "DCC"
#define CTL_NAME                "dcc_ctl"
#define CTL_WATCH_DELETE        "DELETE"
#define CTL_WATCH_PUT           "PUT"
#define CTL_SLEEP_500_MS        500
#define CTL_EXE_OK              "OK\n"
#define CTL_CONNECT_ERR         "connect to server failed\n"
#define CTL_FETCH_ERR           "still has values...\n"
#define CTL_WATCH_ERR           "unkown watch type\n"
#define CTL_SEQUENCE_BUF_LEN    (11)

static void *g_ctl_handle = NULL;
static dcc_result_t g_dcc_result = {0};

static inline void ctl_signal_handler(int signum)
{
    if (signum == SIGTERM || signum == SIGQUIT || signum == SIGINT) {
        dcc_close(&g_ctl_handle);
        exit(EXIT_SUCCESS);
    }
}

static inline void ctl_print_text(uint32 len, const char *text)
{
    if (len == 0) {
        return;
    }
    ctl_printf("%.*s\n", len, text);
}

static void ctl_show_version(void)
{
    ctl_printf("%s\n", dcc_clt_get_version());
}

static void ctl_show_usage(void)
{
    ctl_printf(CTL_PRODUCT_NAME " Developer Command - Line(" CTL_NAME ") help\n");
    ctl_printf("\nUsage:\n");
    ctl_printf("dcc_ctl [options]\n");
    ctl_printf("dcc_ctl [options] command [command options] [command arguments...]\n");

    ctl_printf("\nOptions:\n");
    ctl_printf("    --help, -h       Shows help information\n");
    ctl_printf("    --version, -v,   Shows version information\n");
    ctl_printf("    --endpoints,     Specifies the dcc server list(Example: \"127.0.0.1:1888,127.0.0.1:2888\")\n");
    ctl_printf("    --user,          Specifies the username/password\n");
    ctl_printf("    --cacert,        Specifies the root certificate file used for SSL authentication\n");
    ctl_printf("    --cert,          Specifies the client certificate file used for SSL authentication\n");
    ctl_printf("    --key,           Specifies the key file used for SSL authentication\n");
    ctl_printf("    --timeout,       Command execution timeout threshold\n");

    ctl_printf("\nCommands:\n");

    ctl_printf("    --get       Queries the value of a specified key\n");
    ctl_printf("        Command options:\n");
    ctl_printf("            --prefix: prefix matching\n");
    ctl_printf("            --readlevel 1: read from leader, 2: read from connected node, 3: consistent read\n");

    ctl_printf("    --getchildren       Queries the prefixed keys\n");
    ctl_printf("        Command options:\n");
    ctl_printf("            --readlevel 1: read from leader, 2: read from connected node, 3: consistent read\n");

    ctl_printf("    --put       key val     Updates or insert the value of a specified key\n");
    ctl_printf("        Command options:\n");
    ctl_printf("            --sequence : create an incremental sequence\n");
    ctl_printf("            --expect : compare and swap\n");

    ctl_printf("    --delete    key         Deletes the specified key\n");
    ctl_printf("        Command options:\n");
    ctl_printf("           --prefix: Prefix matching delete\n");
    ctl_printf("    --watch     key\n");
    ctl_printf("        Command options:\n");
    ctl_printf("           --prefix: Prefix matching watch\n");
    ctl_printf("    --lease create leasename ttl: Create a lease with leasename and ttl\n");
    ctl_printf("    --lease renew leasename: Renew a specified lease to keep it alive\n");
    ctl_printf("    --lease query leasename: Query a specified lease info\n");
    ctl_printf("\n");
}

static void ctl_show_help(void)
{
    ctl_show_version();
    ctl_show_usage();
}

static inline void ctl_print_error(void)
{
    int error_no = dcc_get_errorno();
    if (error_no == DCC_CLI_BAD_ARGUMENTS) {
        ctl_show_help();
    } else {
        ctl_printf("%s\n", dcc_get_error(error_no));
    }
}

static inline void ctl_init_open_option(dcc_open_option_t *open_option, ctl_command_t *cmd)
{
    open_option->time_out = cmd->global_option.time_out;
    open_option->server_list = cmd->global_option.server_list;
    open_option->ca_file = cmd->global_option.ca_cert_file;
    open_option->crt_file = cmd->global_option.cert_file;
    open_option->key_file = cmd->global_option.key_file;
}

static status_t ctl_get_connect(void **handle, ctl_command_t *ctl_command)
{
    dcc_open_option_t open_option = {0};
    open_option.clt_name = CTL_NAME;
    ctl_init_open_option(&open_option, ctl_command);
    if (dcc_open(&open_option, handle) != CM_SUCCESS) {
        ctl_printf(CTL_CONNECT_ERR);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline void ctl_init_get_option(dcc_option_t *option, const ctl_command_t *cmd)
{
    option->get_op.prefix = cmd->command_option.prefix;
    option->get_op.read_level = cmd->command_option.read_level;
}

static status_t clt_init_dcc_result(void)
{
    g_dcc_result.key = malloc(MAX_KEY_SIZE);
    if (g_dcc_result.key == NULL) {
        return CM_ERROR;
    }
    g_dcc_result.val = malloc(MAX_VAL_SIZE);
    if (g_dcc_result.val == NULL) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dcc_ctl_fetch(void)
{
    int ret;
    while (g_dcc_result.eof == CM_FALSE) {
        ret = dcc_fetch(g_ctl_handle, &g_dcc_result);
        if (ret != CM_SUCCESS) {
            ctl_printf(CTL_FETCH_ERR);
            return CM_ERROR;
        }
        ctl_print_text(g_dcc_result.key_len, g_dcc_result.key);
        ctl_print_text(g_dcc_result.val_len, g_dcc_result.val);
    }
    return CM_SUCCESS;
}

static status_t ctl_execute_get(ctl_command_t *cmd)
{
    CM_RETURN_IFERR(ctl_get_connect(&g_ctl_handle, cmd));
    CM_RETURN_IFERR(clt_init_dcc_result());
    dcc_option_t option = {0};
    ctl_init_get_option(&option, cmd);

    dcc_string_t key = {.data = cmd->key, .len = cmd->key_len};
    int ret = dcc_get(g_ctl_handle, &key, &option, &g_dcc_result);
    if (ret == CM_SUCCESS) {
        if (option.get_op.prefix == 0) {
            ctl_print_text(g_dcc_result.val_len, g_dcc_result.val);
            return CM_SUCCESS;
        } else {
            ctl_print_text(g_dcc_result.key_len, g_dcc_result.key);
            ctl_print_text(g_dcc_result.val_len, g_dcc_result.val);
            return dcc_ctl_fetch();
        }
    } else {
        ctl_print_error();
        return CM_ERROR;
    }
}

static status_t ctl_execute_getchildren(ctl_command_t *cmd)
{
    dcc_array_t result = {0};
    dcc_option_t option = {0};
    CM_RETURN_IFERR(ctl_get_connect(&g_ctl_handle, cmd));
    option.getchildren_op.read_level = cmd->command_option.read_level;
    dcc_string_t key = {.data = cmd->key, .len = cmd->key_len};
    int ret = dcc_getchildren(g_ctl_handle, &key, &option, &result);
    if (ret == CM_SUCCESS) {
        for (uint32 i = 0; i < result.count; i++) {
            ctl_print_text(result.strings[i]->len, result.strings[i]->data);
        }
        dcc_deinit_array(&result);
        return CM_SUCCESS;
    } else {
        ctl_print_error();
        return CM_ERROR;
    }
}


static inline void ctl_init_put_option(dcc_option_t *option, const ctl_command_t *cmd)
{
    option->put_op.expect_val_len = cmd->command_option.expect_val_len;
    option->put_op.expect_value = cmd->command_option.expect_val;
    option->put_op.sequence = cmd->command_option.sequence;
    option->put_op.lease_name.len = cmd->command_option.lease_opt.lease_name_len;
    option->put_op.lease_name.data = cmd->command_option.lease_opt.lease_name;
}

static status_t ctl_execute_put(ctl_command_t *cmd)
{
    CM_RETURN_IFERR(ctl_get_connect(&g_ctl_handle, cmd));
    dcc_option_t option = {0};
    char path[CTL_SEQUENCE_BUF_LEN];
    MEMS_RETURN_IFERR(memset_sp(path, CTL_SEQUENCE_BUF_LEN, 0, CTL_SEQUENCE_BUF_LEN));
    ctl_init_put_option(&option, cmd);
    dcc_string_t key = {.data = cmd->key, .len = cmd->key_len};
    dcc_string_t val = {.data = cmd->val, .len = cmd->val_len};
    dcc_string_t sequence = {.data = path, .len = CTL_SEQUENCE_BUF_LEN};
    int ret = dcc_put(g_ctl_handle, &key, &val, &option, &sequence);
    if (ret == CM_SUCCESS) {
        ctl_printf(CTL_EXE_OK);
        return CM_SUCCESS;
    } else {
        ctl_print_error();
        return CM_ERROR;
    }
}

static inline void ctl_init_delete_option(dcc_option_t *option, const ctl_command_t *cmd)
{
    option->delete_op.prefix = cmd->command_option.prefix;
}

static status_t ctl_execute_delete(ctl_command_t *cmd)
{
    CM_RETURN_IFERR(ctl_get_connect(&g_ctl_handle, cmd));
    dcc_option_t option = {0};
    ctl_init_delete_option(&option, cmd);
    dcc_string_t key = {.len = cmd->key_len, .data = cmd->key};
    int ret = dcc_delete(g_ctl_handle, &key, &option);
    if (ret == CM_SUCCESS) {
        ctl_printf(CTL_EXE_OK);
        return CM_SUCCESS;
    } else {
        ctl_print_error();
        return CM_ERROR;
    }
}

static int watch_proc(const char *key, unsigned int key_size, const dcc_watch_result_t *watch_result)
{
    switch (watch_result->watch_event) {
        case DCC_WATCH_EVENT_DELETE:
            ctl_print_text((uint32) strlen(CTL_WATCH_DELETE), CTL_WATCH_DELETE);
            ctl_print_text(key_size, key);
            break;
        case DCC_WATCH_EVENT_PUT:
            ctl_print_text((uint32) strlen(CTL_WATCH_PUT), CTL_WATCH_PUT);
            ctl_print_text(key_size, key);
            ctl_print_text(watch_result->data_changed_result.new_data_size, watch_result->data_changed_result.new_data);
            break;
        default:
            ctl_print_text((uint32) strlen(CTL_WATCH_ERR), CTL_WATCH_ERR);
            break;
    }
    return CM_SUCCESS;
}

static inline void ctl_register_signal(void)
{
    (void) cm_regist_signal(SIGTERM, ctl_signal_handler);
    (void) cm_regist_signal(SIGQUIT, ctl_signal_handler);
    (void) cm_regist_signal(SIGINT, ctl_signal_handler);
}

static status_t ctl_execute_watch(ctl_command_t *cmd)
{
    CM_RETURN_IFERR(ctl_get_connect(&g_ctl_handle, cmd));
    dcc_option_t option = {0};
    option.watch_op.prefix = cmd->command_option.prefix == CM_TRUE ? 1 : 0;
    dcc_string_t key = {.data = cmd->key, .len = cmd->key_len};
    int ret = dcc_watch(g_ctl_handle, &key, watch_proc, &option);
    ctl_register_signal();
    if (ret == CM_SUCCESS) {
        while (CM_TRUE) {
            cm_sleep(CTL_SLEEP_500_MS);
        }
        return CM_SUCCESS;
    } else {
        ctl_print_error();
        return CM_ERROR;
    }
}

static status_t ctl_execute_lease(ctl_command_t *cmd)
{
    CM_RETURN_IFERR(ctl_get_connect(&g_ctl_handle, cmd));
    int ret;
    dcc_string_t lease = { .data = cmd->command_option.lease_opt.lease_name,
        .len = cmd->command_option.lease_opt.lease_name_len };
    clt_lease_opt_type_e opt_type = cmd->command_option.lease_opt.opt_type;
    if (opt_type == CTL_LEASE_CREATE) {
        uint32 ttl = cmd->command_option.lease_opt.ttl;
        ret = dcc_lease_create(g_ctl_handle, &lease, ttl, CM_FALSE);
    } else if (opt_type == CTL_LEASE_RENEW) {
        ret = dcc_lease_keep_alive(g_ctl_handle, &lease);
    } else if (opt_type == CTL_LEASE_DESTROY) {
        ret = dcc_lease_destroy(g_ctl_handle, &lease);
    } else if (opt_type == CTL_LEASE_QUERY) {
        dcc_lease_info_t lease_info;
        ret = dcc_lease_query(g_ctl_handle, &lease, &lease_info);
        if (ret == CM_SUCCESS) {
            ctl_printf("lease %s with ttl(%us), remain_ttl(%us)\n", lease.data, lease_info.ttl, lease_info.remain_ttl);
            return CM_SUCCESS;
        }
    } else {
        ret = CM_ERROR;
    }

    if (ret == CM_SUCCESS) {
        ctl_printf(CTL_EXE_OK);
    } else {
        ctl_print_error();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t ctl_execute_process(ctl_command_t *ctl_command)
{
    status_t ret = CM_SUCCESS;
    switch (ctl_command->type) {
        case CTL_KEYWORD_VERSION:
            ctl_show_version();
            break;
        case CTL_KEYWORD_HELP:
            ctl_show_help();
            break;
        case CTL_KEYWORD_GET:
            ret = ctl_execute_get(ctl_command);
            break;
        case CTL_KEYWORD_PUT:
            ret = ctl_execute_put(ctl_command);
            break;
        case CTL_KEYWORD_DELETE:
            ret = ctl_execute_delete(ctl_command);
            break;
        case CTL_KEYWORD_WATCH:
            ret = ctl_execute_watch(ctl_command);
            break;
        case CTL_KEYWORD_LEASE:
            ret = ctl_execute_lease(ctl_command);
            break;
        case CTL_KEYWORD_GETCHILDREN:
            ctl_execute_getchildren(ctl_command);
            break;
        default:
            ret = CM_ERROR;
    }
    dcc_close(&g_ctl_handle);
    CM_FREE_PTR(g_dcc_result.key);
    CM_FREE_PTR(g_dcc_result.val);
    return ret;
}

#ifdef __cplusplus
}
#endif
