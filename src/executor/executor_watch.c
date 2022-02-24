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
 * executor_watch.c
 *
 *
 * IDENTIFICATION
 *    src/executor/executor_watch.c
 *
 * -------------------------------------------------------------------------
 */

#include "executor_watch.h"
#include "cm_hash_pool.h"
#include "cm_hash.h"
#include "cm_text.h"
#include "util_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

static watch_pool_t *g_watch_pool = NULL;
#define WATCH_POOL (g_watch_pool)

status_t exc_watch_init(void)
{
    uint32 total_size = OFFSET_OF(watch_pool_t, buckets) + EXC_WATCH_BUCKET_NUM * sizeof(watch_bucket_t);
    total_size = CM_ALIGN8(total_size);
    if (total_size == 0) {
        LOG_DEBUG_ERR("[EXC] invalid memory size %u.", total_size);
        return CM_ERROR;
    }

    WATCH_POOL = (watch_pool_t *)malloc(total_size);
    if (WATCH_POOL == NULL) {
        LOG_DEBUG_ERR("[EXC] watch pool init malloc memory failed %u.", total_size);
        return CM_ERROR;
    }
    errno_t rc_memzero = memset_sp(WATCH_POOL, (size_t)total_size, 0, (size_t)total_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(WATCH_POOL);
        LOG_DEBUG_ERR("[EXC] watch pool init reset memory failed");
        return CM_ERROR;
    }
    WATCH_POOL->bucket_count = EXC_WATCH_BUCKET_NUM;
    return CM_SUCCESS;
}

void exc_watch_deinit(void)
{
    CM_FREE_PTR(WATCH_POOL);
}

static inline bool32 item_matched(watch_item_t *item, const text_t *key)
{
    cm_spin_lock(&item->lock, NULL);
    if (!cm_text_str_equal(key, item->key) || !item->valid) {
        cm_spin_unlock(&item->lock);
        return CM_FALSE;
    }
    item->ref_count++;
    cm_spin_unlock(&item->lock);
    return CM_TRUE;
}

static inline watch_item_t* find_watch_item_unsafe(watch_bucket_t *bucket, const text_t *key)
{
    watch_item_t *item = bucket->first;
    while (item) {
        if (item_matched(item, key)) {
            return item;
        }
        item = item->next;
    }
    return NULL;
}

static inline watch_item_t* find_watch_item(const text_t *key)
{
    uint32 hash_value = cm_hash_bytes((uint8 *)key->str, key->len, INFINITE_HASH_RANGE);
    watch_bucket_t *bucket = &WATCH_POOL->buckets[hash_value % WATCH_POOL->bucket_count];

    cm_spin_lock(&bucket->lock, NULL);
    watch_item_t *item = find_watch_item_unsafe(bucket, key);
    cm_spin_unlock(&bucket->lock);
    return item;
}

static void item_dec_ref(watch_item_t *item)
{
    bool32 need_free = CM_FALSE;

    cm_spin_lock(&item->lock, NULL);
    CM_ASSERT(item->ref_count > 0);
    if (item->ref_count > 1 || item->valid) {
        item->ref_count--;
    } else {
        need_free = CM_TRUE;
    }
    cm_spin_unlock(&item->lock);

    if (!need_free) {
        return;
    }

    watch_bucket_t *bucket = item->bucket;
    cm_spin_lock(&bucket->lock, NULL);
    HASH_LIST_REMOVE(bucket, item);
    cm_spin_unlock(&bucket->lock);
    exc_free(item);
}

static inline watch_obj_t* find_watch_obj_unsafe(watch_item_t *item, uint32 sid)
{
    watch_obj_t *obj = item->first;
    while (obj) {
        if (obj->sid == sid) {
            return obj;
        }
        obj = obj->next;
    }
    return NULL;
}

static status_t watch_item_add_obj(watch_item_t *item, uint32 sid, dcc_watch_proc_t proc, bool32 *existed)
{
    cm_spin_lock(&item->lock, NULL);
    if (find_watch_obj_unsafe(item, sid) != NULL) {
        *existed = CM_TRUE;
        cm_spin_unlock(&item->lock);
        return CM_SUCCESS;
    }

    watch_obj_t *obj = (watch_obj_t*)exc_alloc(sizeof(watch_obj_t));
    if (obj == NULL) {
        cm_spin_unlock(&item->lock);
        CM_THROW_ERROR(ERR_MALLOC_MEM, "it allocs memory for watch object.");
        LOG_DEBUG_ERR("[EXC] add watch obj malloc obj failed");
        return CM_ERROR;
    }
    obj->sid = sid;
    obj->proc = proc;
    HASH_LIST_INSERT(item, obj);
    if (!item->valid) {
        item->valid = CM_TRUE;
    }
    cm_spin_unlock(&item->lock);
    return CM_SUCCESS;
}

static inline void watch_item_del_obj(watch_item_t *item, uint32 sid)
{
    cm_spin_lock(&item->lock, NULL);
    watch_obj_t *obj = find_watch_obj_unsafe(item, sid);
    if (obj == NULL) {
        cm_spin_unlock(&item->lock);
        return;
    }

    HASH_LIST_REMOVE(item, obj);
    item->valid = (item->first != NULL);
    cm_spin_unlock(&item->lock);
    exc_free(obj);
}

static watch_item_t* alloc_watch_item(watch_bucket_t *bucket, const text_t *key)
{
    watch_item_t *item = (watch_item_t*)exc_alloc(sizeof(watch_item_t) + key->len + 1);
    if (item == NULL) {
        CM_THROW_ERROR(ERR_MALLOC_MEM, "it allocs memory for watch item.");
        LOG_DEBUG_ERR("[EXC] add watch obj malloc item failed");
        return NULL;
    }
    item->key = (char*)item + sizeof(watch_item_t);
    errno_t errcode = strncpy_s(item->key, key->len + 1, key->str, key->len);
    if (errcode != EOK) {
        exc_free(item);
        LOG_DEBUG_ERR("[EXC] add watch obj copy key failed");
        return NULL;
    }
    item->key[key->len] = '\0';
    item->valid  = CM_TRUE;
    item->first  = NULL;
    item->bucket = bucket;
    item->ref_count = 0;
    item->lock = 0;
    return item;
}

status_t exc_add_watch(const text_t *key, uint32 sid, dcc_watch_proc_t proc, text_t *watch_key)
{
    bool32 existed = CM_FALSE;
    uint32 hash_value = cm_hash_bytes((uint8 *)key->str, key->len, INFINITE_HASH_RANGE);
    watch_bucket_t *bucket = &WATCH_POOL->buckets[hash_value % WATCH_POOL->bucket_count];

    cm_spin_lock(&bucket->lock, NULL);
    watch_item_t *item = find_watch_item_unsafe(bucket, key);
    if (item != NULL) {
        cm_spin_unlock(&bucket->lock);
        status_t ret = watch_item_add_obj(item, sid, proc, &existed);
        if (ret == CM_SUCCESS && watch_key != NULL && !existed) {
            watch_key->str = item->key;
            watch_key->len = key->len;
        }
        item_dec_ref(item);
        return ret;
    }

    item = alloc_watch_item(bucket, key);
    if (item == NULL) {
        cm_spin_unlock(&bucket->lock);
        return CM_ERROR;
    }

    if (watch_item_add_obj(item, sid, proc, &existed) != CM_SUCCESS) {
        cm_spin_unlock(&bucket->lock);
        exc_free(item);
        return CM_ERROR;
    }

    HASH_LIST_INSERT(bucket, item);
    cm_spin_unlock(&bucket->lock);
    if (watch_key != NULL) {
        watch_key->str = item->key;
        watch_key->len = key->len;
    }
    return CM_SUCCESS;
}

void exc_del_watch(const text_t *key, uint32 sid)
{
    watch_item_t *item = find_watch_item(key);
    if (item == NULL) {
        return;
    }
    watch_item_del_obj(item, sid);
    item_dec_ref(item);
}

status_t exc_watch_cb_proc(msg_entry_t* entry, int event_type)
{
    watch_item_t *item = find_watch_item((text_t*)ENTRY_K(entry));
    if (item == NULL) {
        return CM_SUCCESS;
    }

    dcc_event_t watch_event;
    watch_event.kvp = &entry->kvp;
    watch_event.event_type = event_type;
    watch_event.is_prefix_notify = 0;

    cm_spin_lock(&item->lock, NULL);
    watch_obj_t *obj = item->first;
    while (obj != NULL) {
        watch_event.sid = obj->sid;
        obj->proc((void *)&watch_event);
        obj = obj->next;
    }
    cm_spin_unlock(&item->lock);
    item_dec_ref(item);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

