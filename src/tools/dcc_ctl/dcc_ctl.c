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
 * dcc_ctl.c
 *    Client tool
 *
 * IDENTIFICATION
 *    src/tools/dcc_ctl/dcc_ctl.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_error.h"
#include "cm_text.h"
#include "cm_types.h"
#include "cm_timer.h"
#include "parse/dcc_cmd_parse.h"
#include "dcc_ctl_execute.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CTL_DEFAULT_TIMEOUT     (3000)

static void init_ctl_command(ctl_command_t *ctl_command);

static status_t ctl_parse_args(const text_t argv[], int32 argc, ctl_command_t *ctl_command)
{
    if (ctl_parse_process(argv, argc, 1, ctl_command) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

int32 main(int32 argc, char *argv[])
{
    ctl_command_t ctl_command = {0};
    init_ctl_command(&ctl_command);

    text_t texts[argc];
    for (int32 i = 0; i < argc; i++) {
        texts[i].str = argv[i];
        texts[i].len = (uint32)strlen(argv[i]);
    }

    if (ctl_parse_args(texts, argc, &ctl_command) != CM_SUCCESS) {
        ctl_printf("Use `dcc_ctl --help` for a complete list of options.\n");
        exit(EXIT_FAILURE);
    }

    if (ctl_execute_process(&ctl_command) != CM_SUCCESS) {
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}

static inline void init_ctl_command(ctl_command_t *ctl_command)
{
    ctl_command->global_option.time_out = CTL_DEFAULT_TIMEOUT;
    ctl_command->command_option.read_level = CM_TRUE;
}

#ifdef __cplusplus
}
#endif