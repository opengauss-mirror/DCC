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
 * executor_lease.c
 *    executor lease
 *
 * IDENTIFICATION
 *    src/executor/executor_lease.c
 *
 * -------------------------------------------------------------------------
 */

#include "executor_lease.h"
#include "cm_hash_pool.h"
#include "cm_hash.h"
#include "cm_text.h"
#include "util_defs.h"
#include "dcf_interface.h"
#include "executor.h"
#include "executor_watch.h"
#include "executor_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EXC_LEASE_NAME_MAX_SIZE 64
#define EXC_LEASE_DB_VAL_MAX_SIZE 64
#define EXC_LEASE_BUCKET_NUM 2048
#define EXC_LEASE_EXPIRE_CHECK_PERIOD 500 // ms
#define EXC_LEASE_DB_VAL_SPLIT_CHAR "#"
#define EXC_LEASE_DB_VAL_ENCLOSE_CHAR 0
static void* g_exc_lease_handle = NULL;
static lease_mgr_t *g_lease_mgr = NULL;
#define LEASE_MGR (g_lease_mgr)
#define LEASE_POOL (LEASE_MGR->lease_pool)

static inline lease_item_t* find_lease_item_unsafe(lease_bucket_t *bucket, const text_t *lease_name)
{
    lease_item_t *item = bucket->first;
    while (item) {
        if (cm_text_str_equal(lease_name, item->name)) {
            return item;
        }
        item = item->next;
    }
    return NULL;
}

static inline lease_item_t* find_lease_item(const text_t *leasename)
{
    uint32 hash_value = cm_hash_bytes((uint8 *)leasename->str, leasename->len, INFINITE_HASH_RANGE);
    lease_bucket_t *bucket = &(LEASE_POOL->buckets[hash_value % LEASE_POOL->bucket_cnt]);
    cm_spin_lock(&bucket->lock, NULL);
    lease_item_t *item = find_lease_item_unsafe(bucket, leasename);
    cm_spin_unlock(&bucket->lock);
    return item;
}

static inline uint64 exc_lease_expire_time(const date_t renew_time, const uint32 ttl)
{
    uint64 ttl_ms = (uint64)ttl * MILLISECS_PER_SECOND;
    uint64 dur_time_ms = ((uint64)(cm_now() - renew_time)) / MICROSECS_PER_MILLISEC;
    uint64 remain_ttl_ms = (ttl_ms > dur_time_ms) ? (ttl_ms - dur_time_ms) : 0;
    return cm_clock_now_ms() + remain_ttl_ms;
}

static status_t alloc_lease_expire_ele(lease_item_t *item, const text_t *lease_name)
{
    lease_expire_ele_t *expire_ele = (lease_expire_ele_t *)exc_alloc(sizeof(lease_expire_ele_t) +
        lease_name->len + 1);
    if (expire_ele == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] alloc lease expire_ele failed");
        return CM_ERROR;
    }
    expire_ele->idx = 0;
    expire_ele->expire_time = exc_lease_expire_time(item->renew_time, item->ttl);
    expire_ele->name = (char*)expire_ele + sizeof(lease_expire_ele_t);
    if (memcpy_s(expire_ele->name, lease_name->len + 1, lease_name->str, lease_name->len) != EOK) {
        exc_free(expire_ele);
        LOG_DEBUG_ERR("[EXC LEASE] copy expire ele name failed, when alloc lease item");
        return CM_ERROR;
    }
    expire_ele->name[lease_name->len] = '\0';
    item->expire_ele = expire_ele;
    LOG_DEBUG_INF("[EXC LEASE] alloced expire ele when alloc lease item, name:%s expire_time:%llu",
        expire_ele->name, expire_ele->expire_time);
    return CM_SUCCESS;
}

static lease_item_t* alloc_lease_item(lease_bucket_t *bucket, const text_t *lease_name, const uint32 ttl,
    const date_t renew_time)
{
    // alloc lease item self
    uint32 key_pool_size = OFFSET_OF(lease_key_pool_t, buckets) + EXC_LEASE_BUCKET_NUM * sizeof(key_bucket_t);
    uint32 size = sizeof(lease_item_t) + key_pool_size + lease_name->len + 1;
    lease_item_t *item = (lease_item_t *)exc_alloc(size);
    if (item == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] alloc lease item failed");
        return NULL;
    }
    errno_t errcode = memset_s(item, size, 0, size);
    if (errcode != EOK) {
        exc_free(item);
        return NULL;
    }
    // init lease key pool
    item->key_pool = (lease_key_pool_t *)((char*)item + sizeof(lease_item_t));
    item->key_pool->bucket_cnt = EXC_LEASE_BUCKET_NUM;

    item->name = (char*)item + sizeof(lease_item_t) + key_pool_size;
    errcode = memcpy_s(item->name, lease_name->len + 1, lease_name->str, lease_name->len);
    if (errcode != EOK) {
        exc_free(item);
        LOG_DEBUG_ERR("[EXC LEASE] copy lease name fialed when alloc lease item");
        return NULL;
    }
    item->name[lease_name->len] = '\0';
    item->bucket = bucket;
    item->ttl = ttl;
    item->renew_time = renew_time;

    // alloc expire ele
    if (exc_is_leader()) {
        if (alloc_lease_expire_ele(item, lease_name) != CM_SUCCESS) {
            exc_free(item);
            return NULL;
        }
    }

    return item;
}

static inline key_item_t* find_lease_key_unsafe(key_bucket_t *bucket, const text_t *key)
{
    key_item_t *item = bucket->first;
    while (item) {
        if (cm_text_str_equal(key, item->key)) {
            return item;
        }
        item = item->next;
    }
    return NULL;
}

static key_item_t* alloc_lease_key_item(key_bucket_t *bucket, const text_t *key)
{
    key_item_t *item = (key_item_t*)exc_alloc(sizeof(key_item_t) + key->len + 1);
    if (item == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] alloc lease key item failed");
        return NULL;
    }
    item->key = (char*)item + sizeof(key_item_t);
    errno_t errcode = memcpy_s(item->key, key->len + 1, key->str, key->len);
    if (errcode != EOK) {
        exc_free(item);
        LOG_DEBUG_ERR("[EXC LEASE] copy lease key failed when alloc lease key item");
        return NULL;
    }
    item->key[key->len] = '\0';
    item->bucket = bucket;
    return item;
}


static status_t exc_write_lease_to_db(const text_t *lease_name, const lease_item_t *item, bool32 is_del)
{
    char db_lease_name[EXC_LEASE_NAME_MAX_SIZE] = {0};
    MEMS_RETURN_IFERR(memcpy_s(db_lease_name, EXC_LEASE_NAME_MAX_SIZE,
        EXC_LEASE_NAME_PREFIX, EXC_LEASE_NAME_PREFIX_LEN));
    MEMS_RETURN_IFERR(memcpy_s(db_lease_name + EXC_LEASE_NAME_PREFIX_LEN,
        EXC_LEASE_NAME_MAX_SIZE - EXC_LEASE_NAME_PREFIX_LEN, lease_name->str, lease_name->len));
    text_t writekey = {
        .str = db_lease_name,
        .len = EXC_LEASE_NAME_PREFIX_LEN + lease_name->len };
    if (is_del) {
        uint32 tmp;
        exc_wr_handle_delete(DCC_LEASE_TABLE_ID, &writekey, CM_FALSE, &tmp);
    } else {
        char lease_val[EXC_LEASE_DB_VAL_MAX_SIZE] = { 0 };
        int len = sprintf_s(lease_val, EXC_LEASE_NAME_MAX_SIZE, "%u#%lld", item->ttl, item->renew_time);
        if (len < 0) {
            return CM_ERROR;
        }
        text_t writeval = {
            .str = lease_val,
            .len = strlen(lease_val) + 1 };
        exc_wr_handle_put(DCC_LEASE_TABLE_ID, &writekey, &writeval);
    }

    exc_wr_handle_commit();
    LOG_RUN_ERR("[EXC LEASE] exc_write_lease_to_db failed.");
    return CM_SUCCESS;
}

static void exc_dealing_leasekey_del(text_t *key)
{
    errno_t ret;
    uint64 total_size = sizeof(msg_entry_t);
    msg_entry_t *entry = (msg_entry_t *)exc_alloc(total_size);
    if (entry == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] alloc msg entry failed.");
        return;
    }
    ret = memset_s(entry, total_size, 0, total_size);
    if (ret != EOK) {
        exc_free(entry);
        return;
    }
    entry->cmd = DCC_CMD_DELETE;
    entry->kvp.key.len = key->len;
    entry->kvp.key.value = key->str;
    entry->all_op.del_op.is_prefix = CM_FALSE;
    exc_entry_inc_ref(entry);
    exc_dealing_del(entry);
}

static status_t exc_write_leasekey_to_db(text_t *key, const text_t *lease_name, bool32 is_lease_destroy,
    bool32 is_commit)
{
    uint32 size = EXC_LEASE_KEY_PREFIX_LEN + key->len;
    char *db_key = exc_alloc(size);
    if (db_key == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_alloc leasekey buf failed.");
        return CM_ERROR;
    }
    if (memcpy_s(db_key, size, EXC_LEASE_KEY_PREFIX, EXC_LEASE_KEY_PREFIX_LEN) != EOK) {
        LOG_DEBUG_ERR("[EXC LEASE] db_key memcpy failed when exc write leasekey to db");
        exc_free(db_key);
        return CM_ERROR;
    }
    if (memcpy_s(db_key + EXC_LEASE_KEY_PREFIX_LEN, size - EXC_LEASE_KEY_PREFIX_LEN, key->str, key->len) != EOK) {
        LOG_DEBUG_ERR("[EXC LEASE] db_key memcpy failed when exc write leasekey to db");
        exc_free(db_key);
        return CM_ERROR;
    }
    text_t writekey = {
        .str = db_key,
        .len = size };
    if (lease_name == NULL || CM_IS_EMPTY_STR(lease_name->str)) {
        if (is_lease_destroy) {
            exc_dealing_leasekey_del(key);
        }
        uint32 tmp;
        exc_wr_handle_delete(DCC_LEASE_TABLE_ID, &writekey, CM_FALSE, &tmp);
    } else {
        exc_wr_handle_put(DCC_LEASE_TABLE_ID, &writekey, (text_t *) lease_name);
    }
    if (is_commit) {
        exc_wr_handle_commit();
    }

    exc_free(db_key);
    return CM_SUCCESS;
}

static status_t exc_lease_del_keys_in_db(lease_item_t *item)
{
    lease_key_pool_t *key_pool = item->key_pool;
    CM_CHECK_NULL_PTR(key_pool);
    status_t ret;
    key_bucket_t *key_bucket = NULL;
    key_item_t *key_item = NULL;
    key_item_t *key_item_tmp = NULL;
    for (uint32 i = 0; i < key_pool->bucket_cnt; i++) {
        key_bucket = &key_pool->buckets[i];
        key_item = key_bucket->first;
        while (key_item) {
            text_t lease_key = { .len = strlen(key_item->key), .str = key_item->key };
            // rm leasekey from db
            ret = exc_write_leasekey_to_db(&lease_key, NULL, CM_TRUE, CM_FALSE);
            if (ret != CM_SUCCESS) {
                LOG_DEBUG_ERR("[EXC LEASE] exc_lease_del_keys_in_db write leasekey to db failed.");
                return ret;
            }
            // rm leasekey from key_pool of leaseitem
            key_item_tmp = key_item->next;
            HASH_LIST_REMOVE(key_bucket, key_item);
            exc_free(key_item);
            key_item = key_item_tmp;
        }
    }
    exc_wr_handle_commit();
    return CM_SUCCESS;
}

static status_t lease_item_del_key(lease_item_t *item, const text_t *key)
{
    lease_key_pool_t *key_pool = item->key_pool;
    uint32 hash_value = cm_hash_bytes((uint8 *)key->str, key->len, INFINITE_HASH_RANGE);
    key_bucket_t *bucket = &key_pool->buckets[hash_value % key_pool->bucket_cnt];
    cm_spin_lock(&bucket->lock, NULL);
    key_item_t *key_item = find_lease_key_unsafe(bucket, key);
    if (key_item == NULL) {
        cm_spin_unlock(&bucket->lock);
        return CM_ERROR;
    }
    HASH_LIST_REMOVE(bucket, key_item);
    cm_spin_unlock(&bucket->lock);
    exc_free(key_item);
    return CM_SUCCESS;
}

status_t exc_cb_consensus_lease_create(const text_t *leasename, uint32 ttl)
{
    // add lease to leasepool
    uint32 hash_value = cm_hash_bytes((uint8 *)leasename->str, leasename->len, INFINITE_HASH_RANGE);
    lease_bucket_t *bucket = &LEASE_POOL->buckets[hash_value % LEASE_POOL->bucket_cnt];
    cm_spin_lock(&bucket->lock, NULL);
    lease_item_t *item = find_lease_item_unsafe(bucket, leasename);
    cm_spin_unlock(&bucket->lock);
    if (item != NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] lease item already exist when create, name:%s", item->name);
        return CM_ERROR;
    }
    item = alloc_lease_item(bucket, leasename, ttl, cm_now());
    if (item == NULL) {
        return CM_ERROR;
    }

    // write lease to db
    if (exc_write_lease_to_db(leasename, item, CM_FALSE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_write_lease_to_db failed when consensus lease create");
        exc_free(item);
        return CM_ERROR;
    }

    if (exc_is_leader()) {
        // add lease to expireque
        cm_spin_lock(&g_lease_mgr->lock, NULL);
        status_t ret = exc_pque_insert(&g_lease_mgr->pque, item->expire_ele);
        cm_spin_unlock(&g_lease_mgr->lock);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[EXC LEASE] pque insert expire item failed, name:%s", item->name);
            exc_free(item);
            return CM_ERROR;
        }
    }

    cm_spin_lock(&bucket->lock, NULL);
    HASH_LIST_INSERT(bucket, item);
    cm_spin_unlock(&bucket->lock);
    return CM_SUCCESS;
}

status_t exc_cb_consensus_lease_renew(const text_t *leasename)
{
    lease_item_t *item = find_lease_item(leasename);
    if (item == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] lease item to renew not exist, name:%s", leasename->str);
        return CM_ERROR;
    }
    item->renew_time = cm_now();
    // update lease renew time in db
    if (exc_write_lease_to_db(leasename, item, CM_FALSE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_write_lease_to_db failed when consensus lease renew");
        return CM_ERROR;
    }
    if (!exc_is_leader()) {
        return CM_SUCCESS;
    }
    item->expire_ele->expire_time = exc_lease_expire_time(item->renew_time, item->ttl);
    cm_spin_lock(&g_lease_mgr->lock, NULL);
    status_t ret = exc_pque_adjust(&g_lease_mgr->pque, item->expire_ele->idx);
    cm_spin_unlock(&g_lease_mgr->lock);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] pque adjust failed when lease renew, name:%s", item->name);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t exc_cb_consensus_lease_sync(const text_t *leasename, const date_t renew_time)
{
    if (exc_is_leader()) {
        return CM_SUCCESS;
    }

    lease_item_t *item = find_lease_item(leasename);
    if (item == NULL) {
        return CM_ERROR;
    }
    item->renew_time = renew_time;
    // update lease renew time in db
    if (exc_write_lease_to_db(leasename, item, CM_FALSE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_write_lease_to_db failed when consensus lease sync");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[EXC LEASE] lease sync success, name:%s renew_time:%lld", item->name, item->renew_time);
    return CM_SUCCESS;
}

status_t exc_cb_consensus_lease_destroy(const text_t *leasename)
{
    // del lease from leasepool
    uint32 hash_value = cm_hash_bytes((uint8 *)leasename->str, leasename->len, INFINITE_HASH_RANGE);
    lease_bucket_t *bucket = &LEASE_POOL->buckets[hash_value % LEASE_POOL->bucket_cnt];
    cm_spin_lock(&bucket->lock, NULL);
    lease_item_t *item = find_lease_item_unsafe(bucket, leasename);
    cm_spin_unlock(&bucket->lock);
    if (item == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] lease item to destroy not exist, name:%s", leasename->str);
        return CM_ERROR;
    }

    // del all lease keys in db
    if (exc_lease_del_keys_in_db(item) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_cb_consensus_lease_destroy del keys in db failed.");
        return CM_ERROR;
    }

    // del lease in db
    if (exc_write_lease_to_db(leasename, item, CM_TRUE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_write_lease_to_db failed when consensus lease destroy");
        return CM_ERROR;
    }

    if (exc_is_leader()) {
        // remove lease from expireque
        cm_spin_lock(&g_lease_mgr->lock, NULL);
        status_t ret = exc_pque_delete(&g_lease_mgr->pque, item->expire_ele->idx);
        cm_spin_unlock(&g_lease_mgr->lock);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[EXC LEASE] pque delete expire item failed, name:%s", item->name);
            return CM_ERROR;
        }
    }

    // remove and free lease item
    cm_spin_lock(&bucket->lock, NULL);
    HASH_LIST_REMOVE(bucket, item);
    cm_spin_unlock(&bucket->lock);
    exc_free(item);

    return CM_SUCCESS;
}

status_t exc_cb_consensus_lease_attach(text_t *key, const text_t *leasename)
{
    lease_item_t *item = find_lease_item(leasename);
    if (item == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] lease not exist which key try to attach");
        return CM_ERROR;
    }

    // add key to lease key_pool
    lease_key_pool_t *key_pool = item->key_pool;
    uint32 hash_value = cm_hash_bytes((uint8 *)key->str, key->len, INFINITE_HASH_RANGE);
    key_bucket_t *bucket = &key_pool->buckets[hash_value % key_pool->bucket_cnt];
    cm_spin_lock(&bucket->lock, NULL);
    key_item_t *key_item = find_lease_key_unsafe(bucket, key);
    cm_spin_unlock(&bucket->lock);
    if (key_item != NULL) {
        LOG_DEBUG_WAR("[EXC LEASE] lease key item already exist, key_item name:%s", key_item->key);
        return CM_SUCCESS;
    }
    key_item = alloc_lease_key_item(bucket, key);
    if (key_item == NULL) {
        return CM_ERROR;
    }

    // persist leasekey to db
    if (exc_write_leasekey_to_db(key, leasename, CM_FALSE, CM_TRUE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_cb_consensus_lease_attach write leasekey to db failed.");
        exc_free(key_item);
        return CM_ERROR;
    }
    cm_spin_lock(&bucket->lock, NULL);
    HASH_LIST_INSERT(bucket, key_item);
    cm_spin_unlock(&bucket->lock);
    return CM_SUCCESS;
}

status_t exc_cb_consensus_lease_detach(text_t *key, const text_t *leasename)
{
    lease_item_t *item = find_lease_item(leasename);
    if (item == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] lease not exist which key try to detach");
        return CM_ERROR;
    }

    // rm leasekey from db
    if (exc_write_leasekey_to_db(key, NULL, CM_FALSE, CM_TRUE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc_cb_consensus_lease_detach write leasekey to db failed.");
        return CM_ERROR;
    }

    // rm key from key pool of leaseitem
    return lease_item_del_key(item, key);
}

static status_t exc_lease_reload(void)
{
    text_t range = {
        .str = EXC_LEASE_NAME_PREFIX, .len = EXC_LEASE_NAME_PREFIX_LEN };
    bool32 eof = CM_TRUE;
    text_t result_key, result_val;
    CM_RETURN_IFERR(db_open_cursor(g_exc_lease_handle, &range, CM_PREFIX_FLAG, &eof));
    while (!eof) {
        CM_RETURN_IFERR(exc_cursor_fetch(g_exc_lease_handle, &result_key, &result_val));
        text_t key_real = {
            .str = result_key.str + EXC_LEASE_NAME_PREFIX_LEN, .len = result_key.len - EXC_LEASE_NAME_PREFIX_LEN };
        uint32 hash_value = cm_hash_bytes((uint8 *)key_real.str, key_real.len, INFINITE_HASH_RANGE);
        lease_bucket_t *bucket = &LEASE_POOL->buckets[hash_value % LEASE_POOL->bucket_cnt];
        uint32 ttl;
        date_t renew_time;
        text_t ttl_text, renew_time_text;
        cm_split_text(&result_val, (EXC_LEASE_DB_VAL_SPLIT_CHAR)[0], EXC_LEASE_DB_VAL_ENCLOSE_CHAR,
            &ttl_text, &renew_time_text);
        CM_RETURN_IFERR(cm_text2uint32(&ttl_text, &ttl));
        CM_RETURN_IFERR(cm_text2uint64(&renew_time_text, (uint64 *)&renew_time));
        lease_item_t *item = alloc_lease_item(bucket, &key_real, ttl, renew_time);
        if (item == NULL) {
            return CM_ERROR;
        }
        HASH_LIST_INSERT(bucket, item);
        CM_RETURN_IFERR(exc_cursor_next(g_exc_lease_handle, &eof));
    }

    range.str = EXC_LEASE_KEY_PREFIX;
    range.len = EXC_LEASE_KEY_PREFIX_LEN;
    CM_RETURN_IFERR(db_open_cursor(g_exc_lease_handle, &range, CM_PREFIX_FLAG, &eof));
    while (!eof) {
        CM_RETURN_IFERR(exc_cursor_fetch(g_exc_lease_handle, &result_key, &result_val));
        lease_item_t *item = find_lease_item(&result_val);
        if (item == NULL) {
            return CM_ERROR;
        }
        text_t key_real = {
            .str = result_key.str + EXC_LEASE_KEY_PREFIX_LEN, .len = result_key.len - EXC_LEASE_KEY_PREFIX_LEN };
        lease_key_pool_t *key_pool = item->key_pool;
        uint32 hash_value = cm_hash_bytes((uint8 *)key_real.str, key_real.len, INFINITE_HASH_RANGE);
        key_bucket_t *bucket = &key_pool->buckets[hash_value % key_pool->bucket_cnt];
        key_item_t *key_item = alloc_lease_key_item(bucket, &key_real);
        if (key_item == NULL) {
            return CM_ERROR;
        }
        HASH_LIST_INSERT(bucket, key_item);
        CM_RETURN_IFERR(exc_cursor_next(g_exc_lease_handle, &eof));
    }

    return CM_SUCCESS;
}

static void exc_lease_expire_entry(thread_t *thread)
{
    cm_set_thread_name("lease_expire");
    LOG_RUN_INF("[EXC LEASE] lease_expire thread started, tid:%lu, close:%u", thread->id, thread->closed);
    while (!thread->closed) {
        if (exc_is_leader()) {
            exc_proc_lease_expire(&g_lease_mgr->pque, &g_lease_mgr->lock);
        }
        cm_sleep(EXC_LEASE_EXPIRE_CHECK_PERIOD);
    }
    LOG_RUN_INF("[EXC LEASE] lease_expire thread closed, tid:%lu, close:%u", thread->id, thread->closed);

    cm_release_thread(thread);
}

static status_t exc_lease_expire_init(void)
{
    CM_RETURN_IFERR(exc_pque_init(&g_lease_mgr->pque, EXC_LEASE_MAX_NUM));
    if (cm_create_thread(exc_lease_expire_entry, 0, NULL, &g_lease_mgr->expire) != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC LEASE] create lease expire thread failed");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline void exc_lease_mgr_clean(void)
{
    exc_free_handle(g_exc_lease_handle);
    g_exc_lease_handle = NULL;
    CM_FREE_PTR(LEASE_POOL);
    CM_FREE_PTR(g_lease_mgr);
}

status_t exc_lease_mgr_init(void)
{
    uint32 size = sizeof(lease_mgr_t);
    g_lease_mgr = (lease_mgr_t *)malloc(size);
    if (g_lease_mgr == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] lease mgr malloc failed");
        return CM_ERROR;
    }
    if (memset_s(g_lease_mgr, size, 0, size) != EOK) {
        CM_FREE_PTR(g_lease_mgr);
        return CM_ERROR;
    }

    size = OFFSET_OF(lease_pool_t, buckets) + EXC_LEASE_BUCKET_NUM * sizeof(lease_bucket_t);
    size = CM_ALIGN8(size);
    LEASE_POOL = (lease_pool_t *)malloc(size);
    if (LEASE_POOL == NULL) {
        LOG_DEBUG_ERR("[EXC LEASE] lease mgr lease pool malloc failed %u.", size);
        CM_FREE_PTR(g_lease_mgr);
        return CM_ERROR;
    }
    if (memset_s(LEASE_POOL, size, 0, size) != EOK) {
        CM_FREE_PTR(LEASE_POOL);
        CM_FREE_PTR(g_lease_mgr);
        return CM_ERROR;
    }
    LEASE_POOL->bucket_cnt = EXC_LEASE_BUCKET_NUM;

    if (exc_alloc_handle(&g_exc_lease_handle) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] exit alloc handle for lease failed");
        CM_FREE_PTR(LEASE_POOL);
        CM_FREE_PTR(g_lease_mgr);
        return CM_ERROR;
    }
    if (exc_read_handle4table(g_exc_lease_handle, EXC_DCC_LEASE_KV_TABLE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC] exit open table for lease failed");
        exc_lease_mgr_clean();
        return CM_ERROR;
    }

    if (exc_lease_reload() != CM_SUCCESS) {
        LOG_RUN_ERR("[EXC LEASE] exc_lease_reload failed");
        exc_lease_mgr_clean();
        return CM_ERROR;
    }

    if (exc_lease_expire_init() != CM_SUCCESS) {
        exc_lease_mgr_clean();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void exc_lease_mgr_deinit(void)
{
    if (g_lease_mgr == NULL) {
        return;
    }
    if (!g_lease_mgr->expire.closed) {
        cm_close_thread(&g_lease_mgr->expire);
    }
    if (g_exc_lease_handle != NULL) {
        exc_free_handle(g_exc_lease_handle);
        g_exc_lease_handle = NULL;
    }
    exc_pque_deinit(&g_lease_mgr->pque);
    CM_FREE_PTR(LEASE_POOL);
    CM_FREE_PTR(g_lease_mgr);
}

static status_t exc_lease_sync_proposal(const lease_item_t *item)
{
    uint32 offset = 0;
    uint32 size = (uint32)(2 * sizeof(uint32) + strlen(item->name) + sizeof(uint64));
    size = CM_ALIGN4(size);
    char *buff = exc_alloc(size);
    text_t leaseid = {
        .len = strlen(item->name), .str = item->name };
    uint32 cmd = DCC_CMD_LEASE_SYNC;
    exc_put_uint32(buff, cmd, &offset);
    if (exc_put_text(buff, size, &leaseid, &offset) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc put text for lease_sync failed");
        exc_free(buff);
        return CM_ERROR;
    }
    exc_put_uint64(buff, (uint64)item->renew_time, &offset);
    uint64 index;
    if (dcf_universal_write(EXC_STREAM_ID_DEFAULT, buff, size, 0, &index) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] dcf_universal_write for lease_sync failed");
        exc_free(buff);
        return CM_ERROR;
    }
    exc_free(buff);
    return CM_SUCCESS;
}

status_t exc_lease_promote(void)
{
    LOG_RUN_INF("[EXC LEASE] exc lease promote begin");
    for (uint32 i = 0; i < LEASE_POOL->bucket_cnt; i++) {
        lease_bucket_t *bucket = &(LEASE_POOL->buckets[i]);
        cm_spin_lock(&bucket->lock, NULL);
        lease_item_t *item = bucket->first;
        cm_spin_unlock(&bucket->lock);
        while (item) {
            if (item->expire_ele == NULL) {
                const text_t lease_name = { .str = item->name, .len = strlen(item->name) };
                CM_RETURN_IFERR(alloc_lease_expire_ele(item, &lease_name));
            }
            cm_spin_lock(&g_lease_mgr->lock, NULL);
            status_t ret = exc_pque_insert(&g_lease_mgr->pque, item->expire_ele);
            cm_spin_unlock(&g_lease_mgr->lock);
            if (ret != CM_SUCCESS) {
                LOG_DEBUG_ERR("[EXC LEASE] exc pque insert failed when promote and sync lease");
                return CM_ERROR;
            }
            if (exc_lease_sync_proposal(item) != CM_SUCCESS) {
                LOG_DEBUG_ERR("[EXC LEASE] exc lease sync proposal failed.");
                return CM_ERROR;
            }
            item = item->next;
        }
    }
    LOG_RUN_INF("[EXC LEASE] exc lease promote end");
    return CM_SUCCESS;
}

void exc_lease_demote(void)
{
    exc_pque_deinit(&g_lease_mgr->pque);
}

static status_t exc_proposal(void *handle, const text_t *buf, unsigned long long write_key, unsigned long long *index)
{
    if (buf->str == NULL || buf->len == 0) {
        return CM_ERROR;
    }

    if (dcf_universal_write(EXC_STREAM_ID_DEFAULT, buf->str, buf->len, write_key, index) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t exc_lease_create(void *handle, const text_t *buf, unsigned long long write_key, unsigned long long *index)
{
    status_t ret = exc_proposal(handle, buf, write_key, index);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc lease create failed.");
    }
    return ret;
}

status_t exc_lease_destroy(void *handle, const text_t *buf, unsigned long long write_key, unsigned long long *index)
{
    status_t ret = exc_proposal(handle, buf, write_key, index);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc lease destroy failed.");
    }
    return ret;
}

status_t exc_lease_renew(void *handle, const text_t *buf, unsigned long long write_key, unsigned long long *index)
{
    status_t ret = exc_proposal(handle, buf, write_key, index);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[EXC LEASE] exc lease renew failed.");
    }
    return ret;
}

static status_t exc_lease_query_meta(const text_t *leasename, uint32 *ttl, date_t *renew_time)
{
    uint32 hash_value = cm_hash_bytes((uint8 *)leasename->str, leasename->len, INFINITE_HASH_RANGE);
    lease_bucket_t *bucket = &(LEASE_POOL->buckets[hash_value % LEASE_POOL->bucket_cnt]);
    cm_spin_lock(&bucket->lock, NULL);
    lease_item_t *item = find_lease_item_unsafe(bucket, leasename);
    if (item == NULL) {
        cm_spin_unlock(&bucket->lock);
        return CM_ERROR;
    }
    *ttl = item->ttl;
    *renew_time = item->renew_time;
    cm_spin_unlock(&bucket->lock);
    return CM_SUCCESS;
}

status_t exc_lease_query(void *handle, const text_t *leasename, exc_lease_info_t *lease_info)
{
    uint32 ttl;
    date_t renew_time;

    status_t ret = exc_lease_query_meta(leasename, &ttl, &renew_time);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    lease_info->ttl = ttl;
    uint32 dur_time = (uint32)(((uint64)(cm_now() - renew_time)) / MICROSECS_PER_SECOND);
    lease_info->remain_ttl = (ttl > dur_time) ? (ttl - dur_time) : 0;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

