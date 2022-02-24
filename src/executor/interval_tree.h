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
 * interval_tree.h
 *    interval tree
 *
 * IDENTIFICATION
 *    src/executor/interval_tree.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __INTERVAL_TREE_H__
#define __INTERVAL_TREE_H__

#include "cm_defs.h"
#include "cm_types.h"
#include "cm_error.h"
#include "cm_list.h"
#include "cm_text.h"
#include "cm_num.h"
#include "dcc_range_cmp.h"
#include "executor_watch.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RB_RED      0
#define RB_BLACK    1

typedef struct st_rb_node {
    struct st_rb_node *left;
    struct st_rb_node *right;
    struct st_rb_node *parent;
    uint32 color;
} rb_node_t;

typedef void(*rb_free_func_t)(void *ptr);

typedef struct st_rbtree {
    rb_node_t *root;
    rb_node_t nil_node;
    uint32 node_count;
    spinlock_t lock;
} rb_tree_t;

typedef struct st_iv_node_t {
    rb_node_t rb_node;
    iv_t iv;
    text_t max;
    uint32 watch_cnt;
    watch_obj_t *first;
} iv_node_t;

typedef struct st_visitor_param {
    uint32 cmd;
    iv_t *iv;
    rb_node_t *node;
    void *ret;
} visitor_param_t;

typedef bool32(*node_visitor)(visitor_param_t *param);

void iv_tree_init(rb_tree_t* rb_tree);

status_t iv_tree_insert_node(rb_tree_t* rb_tree, rb_node_t *new_node);

void iv_tree_delete_node(rb_tree_t* rb_tree, rb_node_t *to_delete);

rb_node_t *iv_tree_search_node(rb_tree_t* rb_tree, iv_t *iv);

void iv_tree_stab_nodes(rb_tree_t* rb_tree, iv_t *iv, ptlist_t *list);

void iv_tree_free_nodes(rb_tree_t* rb_tree, const rb_free_func_t free_func);

#ifdef __cplusplus
}
#endif

#endif