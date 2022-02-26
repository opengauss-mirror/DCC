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
 * executor_watch_group.c
 *
 *
 * IDENTIFICATION
 *    src/executor/executor_watch_group.c
 *
 * -------------------------------------------------------------------------
 */

#include "executor_watch_group.h"
#include "interval_tree.h"
#include "executor.h"

#ifdef __cplusplus
extern "C" {
#endif

static rb_tree_t *g_exc_watch_group = NULL;
#define EXC_WATCH_GROUP   (g_exc_watch_group)
#define EXC_WATCH_GROUP_LOCK   &(g_exc_watch_group->lock)


status_t exc_watch_group_init(void)
{
    LOG_RUN_INF("[EXC]init watch group start");
    g_exc_watch_group = (rb_tree_t *) malloc(sizeof(rb_tree_t));
    if (g_exc_watch_group == NULL) {
        CM_THROW_ERROR(ERR_MALLOC_MEM, "it init watch group");
        LOG_DEBUG_ERR("[EXC] malloc for watch group failed");
        return CM_ERROR;
    }
    iv_tree_init(g_exc_watch_group);
    LOG_RUN_INF("[EXC]init watch group end");
    return CM_SUCCESS;
}

static rb_node_t *exc_wg_find_by_text(const text_t *key)
{
    iv_t iv;
    iv.begin = *key;
    iv.end.len = key->len;
    iv.end.str = exc_alloc(key->len);
    if (iv.end.str == NULL) {
        return NULL;
    }

    errno_t err = memcpy_s(iv.end.str, key->len, key->str, key->len);
    if (err != EOK) {
        exc_free(iv.end.str);
        return NULL;
    }
    int32 len = (int32) key->len;
    for (int32 i = len - 1; i >= 0; i--) {
        if (((uint8)iv.end.str[i]) < IV_END_CHARACTER) {
            iv.end.str[i] += 1;
            break;
        }
    }
    rb_node_t *rb_node = iv_tree_search_node(EXC_WATCH_GROUP, &iv);
    exc_free(iv.end.str);
    LOG_DEBUG_INF("[EXC]find key:%.*s, end:%.*s", iv.begin.len, iv.begin.str, iv.end.len, iv.end.str);
    return rb_node;
}

static status_t exc_wg_add_watch_item(iv_node_t *iv_node, uint32 sid, dcc_watch_proc_t proc, bool32 *existed)
{
    watch_obj_t *head = iv_node->first;
    while (head != NULL) {
        if (sid == head->sid) {
            *existed = CM_TRUE;
            return CM_SUCCESS;
        }
        head = head->next;
    }

    watch_obj_t *watch_obj = exc_alloc(sizeof(watch_item_t));
    if (watch_obj == NULL) {
        CM_THROW_ERROR(ERR_MALLOC_MEM, "it allocs memory for add watch group item.");
        return CM_ERROR;
    }
    watch_obj->proc = proc;
    watch_obj->sid = sid;

    HASH_LIST_INSERT(iv_node, watch_obj);
    iv_node->watch_cnt++;

    return CM_SUCCESS;
}

static status_t exc_init_watch_iv_node(iv_node_t *iv_node, const text_t *key, uint32 sid, dcc_watch_proc_t proc)
{
    iv_node->watch_cnt = 0;
    bool32 existed = CM_FALSE;
    iv_node->iv.begin.str = (char *) iv_node + sizeof(iv_node_t);
    MEMS_RETURN_IFERR(memcpy_s(iv_node->iv.begin.str, key->len, key->str, key->len));
    iv_node->iv.begin.len = key->len;

    iv_node->iv.end.str = iv_node->iv.begin.str + key->len;
    MEMS_RETURN_IFERR(memcpy_s(iv_node->iv.end.str, key->len, key->str, key->len));
    int32 len = (int32) key->len;
    for (int32 i = len - 1; i >= 0; i--) {
        if (((uint8)iv_node->iv.end.str[i]) < IV_END_CHARACTER) {
            iv_node->iv.end.str[i] += 1;
            break;
        }
    }
    iv_node->iv.end.len = key->len;
    return exc_wg_add_watch_item(iv_node, sid, proc, &existed);
}

static iv_node_t *exc_watch_group_node_init(const text_t *key, uint32 sid, dcc_watch_proc_t proc)
{
    uint32 size = sizeof(iv_node_t) + 2 * key->len;
    iv_node_t *iv_node = exc_alloc(size);
    if (iv_node == NULL) {
        return NULL;
    }
    errno_t errnu = memset_s(iv_node, size, 0, size);
    if (errnu != EOK) {
        return NULL;
    }

    status_t ret = exc_init_watch_iv_node(iv_node, key, sid, proc);
    if (ret != CM_SUCCESS) {
        return NULL;
    }
    return iv_node;
}

status_t exc_watch_group_insert(const text_t *key, uint32 sid, dcc_watch_proc_t proc, text_t *watch_key)
{
    status_t ret;
    bool32 existed = CM_FALSE;
    cm_spin_lock(EXC_WATCH_GROUP_LOCK, NULL);
    iv_node_t *iv_node = (iv_node_t *) exc_wg_find_by_text(key);
    if (iv_node == NULL) {
        iv_node = exc_watch_group_node_init(key, sid, proc);
        if (iv_node == NULL) {
            cm_spin_unlock(EXC_WATCH_GROUP_LOCK);
            CM_THROW_ERROR(ERR_EXC_INIT_GROUP_NODE_FAILED, "");
            return CM_ERROR;
        }
        ret = iv_tree_insert_node(EXC_WATCH_GROUP, &iv_node->rb_node);
        if (ret == CM_SUCCESS && watch_key != NULL) {
            watch_key->str = iv_node->iv.begin.str;
            watch_key->len = iv_node->iv.begin.len;
        }
        cm_spin_unlock(EXC_WATCH_GROUP_LOCK);
        LOG_DEBUG_INF("[EXC]new a rb node");
        return ret;
    }

    ret = exc_wg_add_watch_item(iv_node, sid, proc, &existed);
    cm_spin_unlock(EXC_WATCH_GROUP_LOCK);
    if (watch_key != NULL && !existed) {
        watch_key->str = iv_node->iv.begin.str;
        watch_key->len = iv_node->iv.begin.len;
    }
    LOG_DEBUG_INF("[EXC]add to a existed rb node's list");
    return ret;
}

void exc_watch_group_delete(const text_t *key, uint32 sid)
{
    cm_spin_lock(EXC_WATCH_GROUP_LOCK, NULL);
    iv_node_t *iv_node = (iv_node_t *) exc_wg_find_by_text(key);
    if (iv_node == NULL) {
        cm_spin_unlock(EXC_WATCH_GROUP_LOCK);
        return;
    }

    watch_obj_t *to_delete_obj = NULL;
    watch_obj_t *obj = iv_node->first;
    while (obj) {
        if (obj->sid == sid) {
            to_delete_obj = obj;
            break;
        }
        obj = obj->next;
    }
    if (to_delete_obj != NULL) {
        HASH_LIST_REMOVE(iv_node, to_delete_obj);
        exc_free(to_delete_obj);
        iv_node->watch_cnt--;
        LOG_DEBUG_INF("[EXC]delete a iv from list");
        if (iv_node->watch_cnt == 0) {
            iv_tree_delete_node(EXC_WATCH_GROUP, &iv_node->rb_node);
            exc_free((void *) iv_node);
            LOG_DEBUG_INF("[EXC]delete a rb node");
        }
    }
    cm_spin_unlock(EXC_WATCH_GROUP_LOCK);
}

status_t exc_watch_group_proc(msg_entry_t *entry, int event_type)
{
    iv_t iv;
    ptlist_t head;
    dcc_event_t watch_event;
    watch_event.kvp = &entry->kvp;
    watch_event.event_type = event_type;
    watch_event.is_prefix_notify = 1;

    cm_ptlist_init(&head);
    text_t *key = (text_t *) ENTRY_K(entry);
    iv.begin = *key;

    iv.end.str = exc_alloc(key->len);
    if (iv.end.str == NULL) {
        return CM_ERROR;
    }
    int32 ret = memcpy_s(iv.end.str, key->len, key->str, key->len);
    if (ret != EOK) {
        exc_free(iv.end.str);
    }
    iv.end.len = key->len;
    int32 len = (int32) key->len;
    for (int32 i = len - 1; i >= 0; i--) {
        if (((uint8)iv.end.str[i]) < IV_END_CHARACTER) {
            iv.end.str[i] += 1;
            break;
        }
    }
    cm_spin_lock(EXC_WATCH_GROUP_LOCK, NULL);
    iv_tree_stab_nodes(EXC_WATCH_GROUP, &iv, &head);
    exc_free(iv.end.str);
    LOG_DEBUG_INF("[EXC]find overlaped nodes: %u", head.count);
    for (uint32 i = 0; i < head.count; i++) {
        iv_node_t *iv_node = (iv_node_t *) head.items[i];
        watch_obj_t *cur = iv_node->first;
        while (cur != NULL) {
            watch_event.sid = cur->sid;
            cur->proc((void *) &watch_event);
            cur = cur->next;
        }
    }
    cm_spin_unlock(EXC_WATCH_GROUP_LOCK);
    cm_destroy_ptlist(&head);
    return CM_SUCCESS;
}

static void exc_watch_group_free_node(void *node)
{
    iv_node_t *iv_node = (iv_node_t *) node;
    watch_obj_t *cur = iv_node->first;
    watch_obj_t *tmp = NULL;
    while (cur != NULL) {
        tmp = cur->next;
        exc_free(cur);
        cur = tmp;
    }
    exc_free(iv_node);
}

void exc_watch_group_deinit(void)
{
    cm_spin_lock(EXC_WATCH_GROUP_LOCK, NULL);
    iv_tree_free_nodes(EXC_WATCH_GROUP, exc_watch_group_free_node);
    cm_spin_unlock(EXC_WATCH_GROUP_LOCK);
}

#ifdef __cplusplus
}
#endif