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
 * server.c
 *    DCC server main
 *
 * IDENTIFICATION
 *    src/server/server.c
 *
 * -------------------------------------------------------------------------
 */

#include "stdio.h"
#include "dcc_interface.h"
#include "cm_error.h"
#include "cm_log.h"
#include "util_error.h"
#include "srv_param.h"
#include "srv_config.h"
#include "srv_instance.h"
#include "srv_session.h"
#include "cm_timer.h"
#include "cm_file.h"
#include "cm_signal.h"


#ifdef __cplusplus
extern "C" {
#endif

static const char *g_lock_file = "dcc_server.lck";
static int32 g_lock_fd;
static bool8 g_server_running;
static void srv_usage(void)
{
    (void)printf("Usage: dcc [OPTION]\n"
           "   Or: dcc [-h|-H]\n"
           "   Or: dcc [-v|-V]\n"
           "   Or: dcc [mode] -D data_path\n"
           "Option:\n"
           "\t -h/-H                 show the help information.\n"
           "\t -v/-V                 show version information.\n"
           "\t -D                    specify DCC data path.\n");
}
#define MAX_DCC_ARG 3
#define SRV_LOOP_SLEEP_5_SECONDS 5
#define DCC_ARG_NUM2 2

static status_t srv_check_args(int argc, char * const argv[])
{
    int i = 1;
    if (argc > MAX_DCC_ARG) {
        (void)printf("too many argument\n");
        return CM_ERROR;
    }

    while (i < argc) {
        if ((strcmp(argv[i], "-D") == 0)) { /* dcc_server -D data_path */
            if (i + 1 >= argc) {
                (void)printf("invalid argument: %s\n", argv[i]);
                return CM_ERROR;
            }
            i++;
            uint32 len = (uint32)strlen((char *)argv[i]);
            if (len <= 1 || len >= (CM_MAX_PATH_LEN - 1)) {
                (void)printf("invalid argument: %s %s\n", argv[i - 1], argv[i]);
                return CM_ERROR;
            }
        } else {
            (void)printf("invalid argument: %s\n", argv[i]);
            return CM_ERROR;
        }
        i++;
    }
    return CM_SUCCESS;
}

static int srv_find_arg(int argc, char * const argv[], const char *find_arg)
{
    for (int i = 1; i < argc; i++) {
        if (cm_str_equal_ins(argv[i], find_arg)) {
            return i;
        }
    }
    return 0;
}

static status_t srv_process_setup_args(int argc, char *argv[])
{
    int pos = srv_find_arg(argc, argv, "-D");
    if (pos > 0 && (pos + 1) < argc) {
        CM_RETURN_IFERR(srv_set_param("DATA_PATH", argv[pos + 1]));
    }

    return CM_SUCCESS;
}

static void srv_print_version(void)
{
    (void)printf("%s\n", srv_dcc_get_version());
}

static void srv_instance_loop(void)
{
    date_t last = g_timer()->systime;
    while (g_server_running) {
        if ((g_timer()->systime - last) > SECONDS_PER_DAY) {
            (void)srv_chk_ssl_cert_expire();
            last = g_timer()->systime;
        }

        cm_sleep(SRV_LOOP_SLEEP_5_SECONDS);
    }
}

static status_t srv_lock_dcc_server(void)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = { 0 };
    char real_path[CM_FULL_PATH_BUFFER_SIZE] = { 0 };
    param_value_t param_data_path;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_DATA_PATH, &param_data_path));
    CM_RETURN_IFERR(realpath_file(param_data_path.str_val, real_path, CM_FULL_PATH_BUFFER_SIZE));
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "%s/%s",
                                 real_path, g_lock_file));

    if (cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY, &g_lock_fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return cm_lock_fd(g_lock_fd, CM_SLEEP_TIME);
}

static void clear_resource(void)
{
    (void)cm_unlock_fd(g_lock_fd);
    cm_close_file(g_lock_fd);
    deinit_config();
}

static void signal_handler(int sig_no)
{
    if (sig_no == SIGTERM || sig_no == SIGQUIT) {
        LOG_RUN_INF("dcc server received signal %d, begin exit gracefully", sig_no);
        g_server_running = CM_FALSE;
    }
}

static status_t srv_main_start(void)
{
    // handle signal
    (void)signal(SIGHUP, SIG_IGN);
    (void)signal(SIGINT, SIG_IGN);
    (void)cm_regist_signal(SIGTERM, signal_handler);
    (void)cm_regist_signal(SIGQUIT, signal_handler);

    // srv_config module init, file_config... ->  srv_param
    if (init_config() != CM_SUCCESS) {
        (void)printf("DCC config init failed, errcode: %d, errmsg: %s\n",
            cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        (void)fflush(stdout);

        return CM_ERROR;
    }

    if (srv_lock_dcc_server() != CM_SUCCESS) {
        (void)printf("Another dcc_server is running\n");
        (void)fflush(stdout);
        return CM_ERROR;
    }

    // srv start from the unified API
    if (srv_dcc_start() != CM_SUCCESS) {
        (void)printf("DCC start failed, errcode: %d, errmsg: %s\n",
            cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        (void)fflush(stdout);
        return CM_ERROR;
    }

    // srv instance startup
    if (srv_instance_startup() != CM_SUCCESS) {
        (void)printf("Instance startup failed, errcode: %d, errmsg: %s\n",
            cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        (void)fflush(stdout);
        LOG_RUN_INF("Instance startup failed, errcode: %d, errmsg: %s",
                    cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int main(int argc, char *argv[])
{
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_startup = CM_FALSE;
    if (argc == DCC_ARG_NUM2) {
        if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "-V") == 0) {
            srv_print_version();
            return CM_SUCCESS;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-H") == 0) {
            srv_usage();
            return CM_SUCCESS;
        }
    } else if (argc > 1) {
        CM_RETURN_IFERR(srv_check_args(argc, argv));
        CM_RETURN_IFERR(srv_process_setup_args(argc, argv));
    } else if (argc == 1) {
        srv_usage();
        return CM_SUCCESS;
    }

    if (srv_main_start() != CM_SUCCESS) {
        clear_resource();
        return CM_ERROR;
    }

    LOG_RUN_INF("DCC server started");
    g_server_running = CM_TRUE;

    srv_instance_loop();
    LOG_RUN_INF("DCC server exit");

    srv_instance_destroy();
    clear_resource();
    LOG_RUN_INF("DCC server shutdown");
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
