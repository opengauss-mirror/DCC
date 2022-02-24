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
 * clt_msg_adaptor.h
 *
 *
 * IDENTIFICATION
 *    src/client/clt_msg_adaptor.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CLT_MSG_ADAPTOR__
#define __CLT_MSG_ADAPTOR__

#include "interface/clt_interface.h"
#include "dcc_msg_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void convert_get_request(const dcc_string_t *key, const dcc_option_t *option, read_request_t *rd_request)
{
    rd_request->is_dir = option->get_op.prefix;
    rd_request->read_level = option->get_op.read_level;
    rd_request->key_size = key->len;
    rd_request->key = key->data;
}

static inline void convert_getchild_req(const dcc_string_t *key, const dcc_option_t *option, read_request_t *rd_request)
{
    rd_request->read_level = option->getchildren_op.read_level;
    rd_request->key_size = key->len;
    rd_request->key = key->data;
    rd_request->is_dir = 0;
}

static inline void convert_put_request(const dcc_string_t *key, const dcc_string_t *val, const dcc_option_t *option,
                                       write_request_t *wr_request)
{
    wr_request->sequence = option->put_op.sequence;
    wr_request->not_existed = option->put_op.not_existed;
    wr_request->key_size = key->len;
    wr_request->key = key->data;
    if (val == NULL || val->len == 0) {
        wr_request->val_size = 0;
        wr_request->val = NULL;
    } else {
        wr_request->val_size = val->len;
        wr_request->val = val->data;
    }
    wr_request->expect_val_size = option->put_op.expect_val_len;
    wr_request->expect_val = option->put_op.expect_value;
    wr_request->lease_name.len = option->put_op.lease_name.len;
    wr_request->lease_name.str = option->put_op.lease_name.data;
}

static inline void convert_del_request(const dcc_string_t *key, const dcc_option_t *option, del_request_t *del_request)
{
    del_request->is_dir = option->delete_op.prefix;
    del_request->key_size = key->len;
    del_request->key = key->data;
}

static inline void convert_watch_response(const watch_res_t *watch_res, dcc_watch_result_t *watch_result)
{
    watch_result->watch_event = watch_res->watch_event;
    watch_result->data_changed_result.new_data_size = watch_res->now_val_size;
    watch_result->data_changed_result.new_data = watch_res->now_val;
}

static inline void convert_watch_request(const dcc_string_t *key, uint32 session_id, const dcc_option_t *option,
                                         watch_request_t *watch_request)
{
    watch_request->session_id = session_id;
    watch_request->key_size = key->len;
    watch_request->key = key->data;
    watch_request->is_dir = option->watch_op.prefix;
}

#ifdef __cplusplus
}
#endif

#endif
