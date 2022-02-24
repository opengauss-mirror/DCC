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
 * interval_tree.c
 *    interval tree
 *
 * IDENTIFICATION
 *    src/executor/interval_tree.c
 *
 * -------------------------------------------------------------------------
 */

#include "interval_tree.h"
#include "executor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NIL_NODE                      (&rb_tree->nil_node)
#define ROOT_NODE                     (rb_tree->root)
#define IS_LEFT_CHILD_NODE(node)      ((node)->parent->left == (node))
#define IS_BLACK_NODE(node)           ((node)->color == (RB_BLACK))
#define IS_RED_NODE(node)             ((node)->color == (RB_RED))

#define IV_FIND_VISITOR     1
#define IV_APPEND_VISITOR   2

static void iv_update_node_max(rb_node_t *to_update_node, const rb_node_t *sentinel)
{
    rb_node_t *rb_node = to_update_node;
    while (rb_node != sentinel) {
        text_t old_max = ((iv_node_t *) rb_node)->max;
        text_t max = ((iv_node_t *) rb_node)->iv.end;
        if (rb_node->left != sentinel && iv_byte_cmp(&((iv_node_t *) (rb_node->left))->max, &max) > 0) {
            max = ((iv_node_t *) (rb_node->left))->max;
        }
        if (rb_node->right != sentinel && iv_byte_cmp(&((iv_node_t *) (rb_node->right))->max, &max) > 0) {
            max = ((iv_node_t *) (rb_node->right))->max;
        }
        if (iv_byte_cmp(&old_max, &max) == 0) {
            break;
        }
        ((iv_node_t *) rb_node)->max = max;
        rb_node = rb_node->parent;
    }
}

static bool32 iv_generic_visit(visitor_param_t *param)
{
    if (param->cmd == IV_FIND_VISITOR) {
        if (iv_byte_cmp(&param->iv->begin, &((iv_node_t *) param->node)->iv.begin) != 0 ||
            iv_byte_cmp(&param->iv->end, &((iv_node_t *) param->node)->iv.end) != 0) {
            return CM_TRUE;
        }
        param->ret = param->node;
        return CM_FALSE;
    } else if (param->cmd == IV_APPEND_VISITOR) {
        ptlist_t *list = (ptlist_t *) param->ret;
        (void)cm_ptlist_add(list, (pointer_t) param->node);
        return CM_TRUE;
    }
    return CM_TRUE;
}

static bool32 iv_node_visit(rb_node_t *x, rb_node_t *sentinel, node_visitor nv, visitor_param_t *param)
{
    if (x == sentinel) {
        return CM_TRUE;
    }
    param->node = x;
    int32 v = iv_cmp(param->iv, &((iv_node_t *) x)->iv);
    if (v < 0) {
        if (!iv_node_visit(x->left, sentinel, nv, param)) {
            return CM_FALSE;
        }
    } else if (v > 0) {
        iv_t max_iv = {.begin = ((iv_node_t *) x)->iv.begin, .end = ((iv_node_t *) x)->max};
        if (iv_cmp(&max_iv, param->iv) == 0) {
            if (!iv_node_visit(x->left, sentinel, nv, param) ||
                !iv_node_visit(x->right, sentinel, nv, param)) {
                return CM_FALSE;
            }
        }
    } else {
        if (!nv(param) ||
            !iv_node_visit(x->left, sentinel, nv, param) ||
            !iv_node_visit(x->right, sentinel, nv, param)) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

static void cm_rbtree_left_rotate_node(rb_tree_t *rb_tree, rb_node_t *node_x)
{
    /*
    *   x                       y
    *  / \                     / \
    * lx  y      ----->       x  ry
    *    / \                 / \
    *   ly ry               lx ly
    */
    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(node_x != NULL);

    rb_node_t *nil_parent = NIL_NODE->parent;
    rb_node_t *node_y = node_x->right;

    node_x->right = node_y->left;
    node_y->left->parent = node_x;

    node_y->parent = node_x->parent;

    if (node_x->parent == NIL_NODE) {
        rb_tree->root = node_y;
    } else {
        if (IS_LEFT_CHILD_NODE(node_x)) {
            node_x->parent->left = node_y;
        } else {
            node_x->parent->right = node_y;
        }
    }

    iv_update_node_max(node_x, NIL_NODE);

    node_x->parent = node_y;
    node_y->left = node_x;

    iv_update_node_max(node_y, NIL_NODE);

    NIL_NODE->parent = nil_parent;
}

static void cm_rbtree_right_rotate_node(rb_tree_t *rb_tree, rb_node_t *node_y)
{
    /*
    *      y                   x
    *     / \                 / \
    *    x  ry   ----->      lx  y
    *   / \                     / \
    * lx  rx                   rx ry
    */
    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(node_y != NULL);

    rb_node_t *nil_parent = NIL_NODE->parent;
    rb_node_t *node_x = node_y->left;

    node_y->left = node_x->right;
    node_x->right->parent = node_y;

    node_x->parent = node_y->parent;

    if (node_y->parent == NIL_NODE) {
        rb_tree->root = node_x;
    } else {
        if (IS_LEFT_CHILD_NODE(node_y)) {
            node_y->parent->left = node_x;
        } else {
            node_y->parent->right = node_x;
        }
    }

    iv_update_node_max(node_y, NIL_NODE);

    node_y->parent = node_x;
    node_x->right = node_y;

    iv_update_node_max(node_x, NIL_NODE);

    NIL_NODE->parent = nil_parent;
}

static void cm_rbtree_insert_node_fixup(rb_tree_t *rb_tree, rb_node_t *node)
{
    rb_node_t *grandp_node = NULL;
    rb_node_t *parent_node = NULL;
    rb_node_t *uncle_node = NULL;

    while (node->parent->color == RB_RED) {
        parent_node = node->parent;
        grandp_node = parent_node->parent;

        if (grandp_node->left == parent_node) {
            uncle_node = grandp_node->right;
            if (uncle_node->color == RB_RED) {
                uncle_node->color = RB_BLACK;
                parent_node->color = RB_BLACK;
                grandp_node->color = RB_RED;
                node = grandp_node;
                continue;
            }

            if (parent_node->right == node) {
                node = parent_node;
                cm_rbtree_left_rotate_node(rb_tree, node);
            }

            node->parent->color = RB_BLACK;
            grandp_node->color = RB_RED;
            cm_rbtree_right_rotate_node(rb_tree, grandp_node);
        } else {
            uncle_node = grandp_node->left;
            if (IS_RED_NODE(uncle_node)) {
                uncle_node->color = RB_BLACK;
                parent_node->color = RB_BLACK;
                grandp_node->color = RB_RED;
                node = grandp_node;
                continue;
            }

            if (parent_node->left == node) {
                node = parent_node;
                cm_rbtree_right_rotate_node(rb_tree, node);
            }

            node->parent->color = RB_BLACK;
            grandp_node->color = RB_RED;
            cm_rbtree_left_rotate_node(rb_tree, grandp_node);
        }
    }

    rb_tree->root->color = RB_BLACK;
}

static void cm_rbtree_delete_node_fixup_left(rb_tree_t *rb_tree, rb_node_t **curr_node)
{
    rb_node_t *node = *curr_node;
    rb_node_t *bro_node = node->parent->right;

    if (IS_RED_NODE(bro_node)) {
        bro_node->color = RB_BLACK;
        node->parent->color = RB_RED;
        cm_rbtree_left_rotate_node(rb_tree, node->parent);
        bro_node = node->parent->right;
    }

    if (IS_BLACK_NODE(bro_node->left) && IS_BLACK_NODE(bro_node->right)) {
        bro_node->color = RB_RED;
        node = node->parent;
    } else {
        if (IS_BLACK_NODE(bro_node->right)) {
            bro_node->left->color = RB_BLACK;
            bro_node->color = RB_RED;
            cm_rbtree_right_rotate_node(rb_tree, bro_node);
            bro_node = node->parent->right;
        }

        bro_node->color = node->parent->color;
        node->parent->color = RB_BLACK;
        bro_node->right->color = RB_BLACK;
        cm_rbtree_left_rotate_node(rb_tree, node->parent);
        node = rb_tree->root;
    }

    *curr_node = node;
}

static void cm_rbtree_delete_node_fixup_right(rb_tree_t *rb_tree, rb_node_t **curr_node)
{
    rb_node_t *node = *curr_node;
    rb_node_t *bro_node = node->parent->left;
    if (IS_RED_NODE(bro_node)) {
        bro_node->color = RB_BLACK;
        node->parent->color = RB_RED;
        cm_rbtree_right_rotate_node(rb_tree, node->parent);
        bro_node = node->parent->left;
    }

    if (IS_BLACK_NODE(bro_node->left) && IS_BLACK_NODE(bro_node->right)) {
        bro_node->color = RB_RED;
        node = node->parent;
    } else {
        if (IS_BLACK_NODE(bro_node->left)) {
            bro_node->right->color = RB_BLACK;
            bro_node->color = RB_RED;
            cm_rbtree_left_rotate_node(rb_tree, bro_node);
            bro_node = node->parent->left;
        }
        bro_node->color = node->parent->color;
        node->parent->color = RB_BLACK;
        bro_node->left->color = RB_BLACK;
        cm_rbtree_right_rotate_node(rb_tree, node->parent);
        node = rb_tree->root;
    }

    *curr_node = node;
}

static void cm_rbtree_delete_node_fixup(rb_tree_t *rb_tree, rb_node_t *node)
{
    while (node != rb_tree->root && IS_BLACK_NODE(node)) {
        if (IS_LEFT_CHILD_NODE(node)) {
            cm_rbtree_delete_node_fixup_left(rb_tree, &node);
        } else {
            cm_rbtree_delete_node_fixup_right(rb_tree, &node);
        }
    }

    node->color = RB_BLACK;
}

static void cm_rbtree_delete_leaf_node(rb_tree_t *rb_tree, rb_node_t *node)
{
    rb_node_t *child_node = node->left != NIL_NODE ? node->left : node->right;
    child_node->parent = node->parent;

    if (node->parent == NIL_NODE) {
        rb_tree->root = child_node;
    } else {
        if (IS_LEFT_CHILD_NODE(node)) {
            node->parent->left = child_node;
        } else {
            node->parent->right = child_node;
        }
        iv_update_node_max(node->parent, NIL_NODE);
    }

    if (IS_BLACK_NODE(node)) {
        cm_rbtree_delete_node_fixup(rb_tree, child_node);
    }
    rb_tree->node_count--;
}

void iv_tree_init(rb_tree_t *rb_tree)
{
    rb_tree->node_count = 0;
    rb_tree->nil_node.color = RB_BLACK;
    rb_tree->nil_node.left = NULL;
    rb_tree->nil_node.right = NULL;
    rb_tree->nil_node.parent = NULL;
    rb_tree->root = &(rb_tree->nil_node);
    rb_tree->lock = 0;
}

status_t iv_tree_insert_node(rb_tree_t *rb_tree, rb_node_t *new_node)
{
    rb_node_t *cur_node = NULL;
    int32 cmp_res;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);
    CM_ASSERT(new_node != NULL);

    rb_node_t *temp_node = ROOT_NODE;
    ((iv_node_t *) new_node)->max = ((iv_node_t *) new_node)->iv.end;

    while (temp_node != NIL_NODE) {
        cur_node = temp_node;
        cmp_res = iv_byte_cmp(&((iv_node_t *) new_node)->iv.begin, &((iv_node_t *) temp_node)->iv.begin);
        if (cmp_res < 0) {
            temp_node = temp_node->left;
        } else {
            temp_node = temp_node->right;
        }
    }

    if (cur_node == NULL) {
        new_node->parent = NIL_NODE;
        rb_tree->root = new_node;
    } else {
        new_node->parent = cur_node;
        cmp_res = iv_byte_cmp(&((iv_node_t *) new_node)->iv.begin, &((iv_node_t *) cur_node)->iv.begin);
        if (cmp_res < 0) {
            cur_node->left = new_node;
        } else {
            cur_node->right = new_node;
        }
        iv_update_node_max(cur_node, NIL_NODE);
    }

    new_node->color = RB_RED;
    new_node->left = NIL_NODE;
    new_node->right = NIL_NODE;
    cm_rbtree_insert_node_fixup(rb_tree, new_node);
    rb_tree->node_count++;

    return CM_SUCCESS;
}

void iv_tree_delete_node(rb_tree_t *rb_tree, rb_node_t *to_delete)
{
    rb_node_t *node = to_delete;
    uint32 color;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(node != NULL);

    if (node->left == NIL_NODE || node->right == NIL_NODE) {
        cm_rbtree_delete_leaf_node(rb_tree, node);
        return;
    }

    rb_node_t *del_node = node;
    node = node->right;

    while (node->left != NIL_NODE) {
        node = node->left;
    }

    rb_node_t *child_node = node->right;
    color = node->color;
    child_node->parent = node->parent;

    if (node->parent == NIL_NODE) {
        rb_tree->root = child_node;
    } else {
        if (IS_LEFT_CHILD_NODE(node)) {
            node->parent->left = child_node;
        } else {
            node->parent->right = child_node;
        }
    }

    *node = *del_node;
    if (del_node->parent == NIL_NODE) {
        rb_tree->root = node;
    } else {
        if (IS_LEFT_CHILD_NODE(del_node)) {
            del_node->parent->left = node;
        } else {
            del_node->parent->right = node;
        }
        iv_update_node_max(del_node->parent, NIL_NODE);
    }

    del_node->left->parent = node;
    del_node->right->parent = node;

    if (color == RB_BLACK) {
        cm_rbtree_delete_node_fixup(rb_tree, child_node);
    }
    rb_tree->node_count--;

    return;
}

rb_node_t *iv_tree_search_node(rb_tree_t *rb_tree, iv_t *iv)
{
    if (rb_tree->node_count == 0 || iv == NULL) {
        return NULL;
    }
    rb_node_t *node = NULL;
    visitor_param_t param = {.node = NULL, .iv = iv, .cmd = IV_FIND_VISITOR, .ret = node};
    (void)iv_node_visit(rb_tree->root, NIL_NODE, iv_generic_visit, &param);
    return param.ret;
}

void iv_tree_stab_nodes(rb_tree_t *rb_tree, iv_t *iv, ptlist_t *list)
{
    if (rb_tree->node_count == 0) {
        return;
    }
    visitor_param_t param = {.node = NULL, .iv = iv, .cmd = IV_APPEND_VISITOR, .ret = (ptlist_t *) list};
    (void)iv_node_visit(rb_tree->root, NIL_NODE, iv_generic_visit, &param);
}

void iv_tree_free_nodes(rb_tree_t *rb_tree, const rb_free_func_t free_func)
{
    rb_node_t *prev_node;

    CM_ASSERT(rb_tree != NULL);
    CM_ASSERT(rb_tree->root != NULL);
    CM_ASSERT(free_func != NULL);

    if (rb_tree->root == NIL_NODE) {
        return;
    }

    rb_node_t *curr_node = rb_tree->root;

    while (curr_node != NIL_NODE) {
        while (curr_node->left != NIL_NODE) {
            curr_node = curr_node->left;
        }

        if (curr_node->right == NIL_NODE) {
            if (IS_LEFT_CHILD_NODE(curr_node)) {
                curr_node->parent->left = NIL_NODE;
            } else {
                curr_node->parent->right = NIL_NODE;
            }

            prev_node = curr_node->parent;
            free_func((void *) curr_node);
            curr_node = prev_node;
        } else {
            curr_node = curr_node->right;
        }
    }

    return;
}


#ifdef __cplusplus
}
#endif
