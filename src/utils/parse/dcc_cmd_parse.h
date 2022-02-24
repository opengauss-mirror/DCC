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
 * dcc_cmd_parse.h
 *    Client tool
 *
 * IDENTIFICATION
 *    src/utils/parse/dcc_cmd_parse.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DCC_CMD_PARSE_H__
#define __DCC_CMD_PARSE_H__

#include "cm_error.h"
#include "cm_text.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ctl_printf(fmt, ...)                    \
    do {                                        \
            (void)printf(fmt, ##__VA_ARGS__);         \
            (void)fflush(stdout);                     \
    } while (0)

// options
#define CTL_OPTION_ENDPOINTS    (1<<0)
#define CTL_OPTION_HELP         (1<<1)
#define CTL_OPTION_VERSION      (1<<2)
#define CTL_OPTION_PREFIX       (1<<3)
#define CTL_OPTION_READ_LEVEL   (1<<4)
#define CTL_OPTION_EXPECT       (1<<7)
#define CTL_OPTION_TIMEOUT      (1<<8)
#define CTL_OPTION_CACERT       (1<<9)
#define CTL_OPTION_CERT         (1<<10)
#define CTL_OPTION_KEY          (1<<11)
#define CTL_OPTION_SEQUENCE     (1<<12)

// command
#define CTL_COMMAND_PUT         (1<<16)
#define CTL_COMMAND_GET         (1<<17)
#define CTL_COMMAND_DEL         (1<<18)
#define CTL_COMMAND_WATCH       (1<<19)
#define CTL_COMMAND_QUERY_CLUSTER (1<<20)
#define CTL_COMMAND_QUERY_LEADER  (1<<21)
#define CTL_COMMAND_LEASE       (1<<22)
#define CTL_COMMAND_GETCHILDREN (1<<23)

#define CTL_INIT_OPTION     (0)
#define CTL_GLOBAL_OPTION \
    (CTL_OPTION_ENDPOINTS | CTL_OPTION_TIMEOUT | CTL_OPTION_CACERT | CTL_OPTION_CERT | CTL_OPTION_KEY)
#define CTL_EXPECT_SUB      (CTL_GLOBAL_OPTION)
#define CTL_GET_SUB         (CTL_OPTION_PREFIX | CTL_OPTION_READ_LEVEL | CTL_GLOBAL_OPTION)
#define CTL_PUT_SUB         (CTL_OPTION_EXPECT | CTL_GLOBAL_OPTION | CTL_COMMAND_LEASE | CTL_OPTION_SEQUENCE)
#define CTL_PREFIX_SUB      (CTL_OPTION_READ_LEVEL | CTL_GLOBAL_OPTION)
#define CTL_DELETE_SUB      (CTL_OPTION_PREFIX | CTL_GLOBAL_OPTION)
#define CTL_READ_LEVEl_SUB  (CTL_OPTION_PREFIX | CTL_GLOBAL_OPTION)
#define CTL_SEQUENCE_SUB    (CTL_GLOBAL_OPTION)
#define CTL_WATCH_SUB       (CTL_OPTION_PREFIX | CTL_GLOBAL_OPTION)
#define CTL_GETCHILDREN_SUB (CTL_GLOBAL_OPTION | CTL_OPTION_READ_LEVEL)
#define CTL_LEASE_SUB       (CTL_GLOBAL_OPTION)
#define CTL_ALL_OPTIONS     0xffff

typedef enum en_ctl_keyword {
    CTL_KEYWORD_UNKNOWN = 0,
    CTL_KEYWORD_HELP,
    CTL_KEYWORD_VERSION,
    CTL_KEYWORD_ENDPOINTS,
    CTL_KEYWORD_TIMEOUT,
    CTL_KEYWORD_CACERT,
    CTL_KEYWORD_CERT,
    CTL_KEYWORD_KEY,
    CTL_KEYWORD_PREFIX,
    CTL_KEYWORD_READ_LEVEL,
    CTL_KEYWORD_EPHEMERAL,
    CTL_KEYWORD_TTL,
    CTL_KEYWORD_SEQUENCE,
    CTL_KEYWORD_GET,
    CTL_KEYWORD_GETCHILDREN,
    CTL_KEYWORD_PUT,
    CTL_KEYWORD_DELETE,
    CTL_KEYWORD_WATCH,
    CTL_KEYWORD_EXPECT,
    CTL_KEYWORD_QUERY_CLUSTER,
    CTL_KEYWORD_QUERY_LEADER,
    CTL_KEYWORD_LEASE,
    CTL_KEYWORD_CEIL,
} ctl_keyword_t;

typedef struct st_ctl_global_option {
    uint32 flag;
    uint32 time_out;
    char *server_list;
    char *ca_cert_file;
    char *cert_file;
    char *key_file;
} ctl_global_option_t;

typedef enum {
    CTL_LEASE_CREATE = 0,
    CTL_LEASE_RENEW,
    CTL_LEASE_ATTACH,
    CTL_LEASE_DESTROY,
    CTL_LEASE_QUERY,
} clt_lease_opt_type_e;

typedef struct st_ctl_lease_cmd_option {
    clt_lease_opt_type_e opt_type;
    uint32 lease_name_len;
    char *lease_name;
    uint32 ttl;
} ctl_lease_option_t;

typedef struct st_ctl_cmd_option {
    uint32 flag;
    uint64 ttl;
    bool32 prefix;
    bool32 ephemeral;
    bool32 sequence;
    uint32 read_level;
    unsigned int expect_val_len;
    char *expect_val;
    ctl_lease_option_t lease_opt;
} ctl_cmd_option_t;

typedef struct st_ctl_command {
    uint32 flag;
    ctl_keyword_t type;
    ctl_global_option_t global_option;
    ctl_cmd_option_t command_option;
    unsigned int key_len;
    char *key;
    unsigned int val_len;
    char *val;
} ctl_command_t;

typedef status_t (*command_parse_t)(const text_t argv[], int32 argc, int *cur, ctl_command_t *ctl_command);

typedef struct st_ctl_option_item {
    uint32 opt_flag;
    uint32 sub_opt_flag;
    ctl_keyword_t type;
    char *name;
    command_parse_t parse_command;
} ctl_option_item_t;

status_t ctl_parse_process(const text_t argv[], int32 argc, int cur, ctl_command_t *ctl_command);

#ifdef __cplusplus
}
#endif

#endif