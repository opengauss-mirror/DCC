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
 * clt_watch_manager.c
 *
 *
 * IDENTIFICATION
 *    src/client/clt_watch_manager.c
 *
 * -------------------------------------------------------------------------
 */

#include "clt_watch_manager.h"
#include "cm_hash.h"
#include "cm_text.h"
#include "util_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLT_PREFIX_IV_KEY_SIZE_1    (1)
#define CLT_PREFIX_IV_KEY_SIZE_2    (2)

static clt_watch_node_t *clt_watch_list_find(clt_watch_list_t *watch_list, const text_t *key)
{
    clt_watch_node_t *cur = watch_list->first;
    while (cur != NULL) {
        if (iv_byte_cmp(key, &cur->clt_watch_iv.begin) == 0) {
            return cur;
        }
        cur = cur->next;
    }

    return NULL;
}

status_t clt_watch_pool_init(clt_watch_manager_t **watch_manager)
{
    size_t total_size = sizeof(clt_watch_manager_t) + sizeof(clt_watch_list_t) + sizeof(clt_watch_list_t);
    total_size = CM_ALIGN8(total_size);
    if (total_size == 0) {
        LOG_DEBUG_ERR("[CLI]invalid watch pool size %zu", total_size);
        return CM_ERROR;
    }
    *watch_manager = (clt_watch_manager_t *) malloc(total_size);
    if ((*watch_manager) == NULL) {
        LOG_DEBUG_ERR("[CLI]watch pool init malloc memory failed %zu", total_size);
        return CM_ERROR;
    }
    errno_t rc_memzero = memset_sp(*watch_manager, total_size, 0, total_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(*watch_manager);
        return CM_ERROR;
    }
    (*watch_manager)->watch_group_list = (clt_watch_list_t*)((char*)(*watch_manager) + sizeof(clt_watch_manager_t));
    (*watch_manager)->watch_key_list = (clt_watch_list_t*)((char*)((*watch_manager)->watch_group_list) +
                                        sizeof(clt_watch_list_t));
    return CM_SUCCESS;
}

void clt_watch_pool_deinit(clt_watch_manager_t *watch_manager)
{
    if (watch_manager == NULL) {
        return;
    }
    cm_spin_lock(&watch_manager->watch_group_list->lock, NULL);
    clt_free_watch_obj(watch_manager->watch_group_list->first);
    cm_spin_unlock(&watch_manager->watch_group_list->lock);

    cm_spin_lock(&watch_manager->watch_key_list->lock, NULL);
    clt_free_watch_obj(watch_manager->watch_key_list->first);
    cm_spin_unlock(&watch_manager->watch_key_list->lock);

    CM_FREE_PTR(watch_manager);
}

static clt_watch_node_t *alloc_watch_item(bool32 is_prefix, const text_t *key, const dcc_watch_proc_t watch_proc)
{
    errno_t err;
    uint32 size = sizeof(clt_watch_node_t) + key->len *
        (is_prefix == CM_TRUE ? CLT_PREFIX_IV_KEY_SIZE_2 : CLT_PREFIX_IV_KEY_SIZE_1);

    clt_watch_node_t *watch_node = (clt_watch_node_t *) malloc(size);
    if (watch_node == NULL) {
        return NULL;
    }

    watch_node->proc = watch_proc;

    watch_node->clt_watch_iv.begin.len = key->len;
    watch_node->clt_watch_iv.begin.str = (char *) watch_node + sizeof(clt_watch_node_t);
    err = memcpy_s(watch_node->clt_watch_iv.begin.str, key->len, key->str, key->len);
    if (err != EOK) {
        CM_FREE_PTR(watch_node);
        return NULL;
    }

    if (is_prefix == CM_TRUE) {
        watch_node->clt_watch_iv.end.len = key->len;
        watch_node->clt_watch_iv.end.str = watch_node->clt_watch_iv.begin.str + key->len;
        err = memcpy_s(watch_node->clt_watch_iv.end.str, key->len, key->str, key->len);
        if (err != EOK) {
            CM_FREE_PTR(watch_node);
            return NULL;
        }
        char *to_change = watch_node->clt_watch_iv.end.str;
        int32 len = (int32) (watch_node->clt_watch_iv.end.len);
        for (int32 i = len - 1; i >= 0; i--) {
            if (((uint8) to_change[i]) < IV_END_CHARACTER) {
                to_change[i] = to_change[i] + 1;
                break;
            }
        }

        LOG_DEBUG_INF("[CLI]add watch key, prefix: %u, key begin: %.*s, key end: %.*s", is_prefix,
            watch_node->clt_watch_iv.begin.len, watch_node->clt_watch_iv.begin.str,
            watch_node->clt_watch_iv.end.len, watch_node->clt_watch_iv.end.str);
    } else {
        watch_node->clt_watch_iv.end.str = NULL;
        watch_node->clt_watch_iv.end.len = 0;
        LOG_DEBUG_INF("[CLI]add watch key, prefix: %u, key begin: %.*s", is_prefix,
            watch_node->clt_watch_iv.begin.len, watch_node->clt_watch_iv.begin.str);
    }

    return watch_node;
}

static status_t clt_watch_inter_add(clt_watch_list_t *watch_list, bool32 is_prefix, const text_t *key,
                                    const dcc_watch_proc_t watch_proc)
{
    LOG_DEBUG_INF("[CLI] add watch key: %.*s, prefix: %u", key->len, key->str, is_prefix);
    cm_spin_lock(&watch_list->lock, NULL);
    clt_watch_node_t *item = clt_watch_list_find(watch_list, key);
    if (item != NULL) {
        item->proc = watch_proc;
        cm_spin_unlock(&watch_list->lock);
        return CM_SUCCESS;
    }
    clt_watch_node_t *node = alloc_watch_item(is_prefix, key, watch_proc);
    if (node == NULL) {
        LOG_DEBUG_ERR("[CLI]alloc watch key item failed");
        cm_spin_unlock(&watch_list->lock);
        return CM_ERROR;
    }

    CLT_HASH_LIST_INSERT(watch_list, node);
    watch_list->node_cnt++;
    cm_spin_unlock(&watch_list->lock);
    return CM_SUCCESS;
}

status_t clt_watch_pool_add(clt_watch_manager_t *watch_manager, bool32 is_prefix, const text_t *key,
                            const dcc_watch_proc_t watch_proc)
{
    if (is_prefix == CM_TRUE) {
        return clt_watch_inter_add(watch_manager->watch_group_list, CM_TRUE, key, watch_proc);
    } else {
        return clt_watch_inter_add(watch_manager->watch_key_list, CM_FALSE, key, watch_proc);
    }
}

static void clt_watch_inter_del(clt_watch_list_t *watch_list, const text_t *key)
{
    cm_spin_lock(&watch_list->lock, NULL);
    clt_watch_node_t *item = clt_watch_list_find(watch_list, key);
    if (item != NULL) {
        CLT_HASH_LIST_REMOVE(watch_list, item);
    }
    cm_spin_unlock(&watch_list->lock);
    CM_FREE_PTR(item);
}

void clt_watch_pool_del(clt_watch_manager_t *watch_manager, bool32 is_prefix, const text_t *key)
{
    LOG_DEBUG_INF("[CLI]delete key:%.*s, prefix:%u", key->len, key->str, is_prefix);
    if (is_prefix == CM_TRUE) {
        clt_watch_inter_del(watch_manager->watch_group_list, key);
    } else {
        clt_watch_inter_del(watch_manager->watch_key_list, key);
    }
}

status_t clt_watch_pool_call(clt_watch_manager_t *watch_manager, const text_t *key, uint32 is_prefix,
    const dcc_watch_result_t *result)
{
    uint32 cnt = 0;
    clt_watch_node_t *cur;
    clt_watch_list_t *watch_list;
    if (is_prefix == CM_TRUE) {
        watch_list = watch_manager->watch_group_list;
        cur = watch_list->first;
        cm_spin_lock(&watch_list->lock, NULL);
        while (cur != NULL) {
            if (iv_byte_cmp(key, &cur->clt_watch_iv.begin) >= 0 && iv_byte_cmp(key, &cur->clt_watch_iv.end) < 0) {
                cnt++;
                cur->proc(key->str, key->len, result);
            }
            cur = cur->next;
        }
        LOG_DEBUG_INF("[CLI]trigger prefix watch proc cnt: %u", cnt);
    } else {
        watch_list = watch_manager->watch_key_list;
        cur = watch_list->first;
        cm_spin_lock(&watch_list->lock, NULL);
        while (cur != NULL) {
            if (iv_byte_cmp(key, &cur->clt_watch_iv.begin) == 0) {
                cur->proc(key->str, key->len, result);
            }
            cur = cur->next;
        }
        LOG_DEBUG_INF("[CLI]trigger watch proc cnt: %u", cnt);
    }
    cm_spin_unlock(&watch_list->lock);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif