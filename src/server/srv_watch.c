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
 * srv_watch.c
 *    watch events proc
 *
 * IDENTIFICATION
 *    src/server/srv_watch.c
 *
 * -------------------------------------------------------------------------
 */
#include "dcc_msg_cmd.h"
#include "dcc_msg_protocol.h"
#include "cs_pipe.h"
#include "util_defs.h"
#include "srv_session.h"
#include "srv_watch.h"

#ifdef __cplusplus
extern "C" {
#endif

watch_mgr_t *g_dcc_watch_mgr = NULL;

static status_t watch_send_msg_node(watch_msg_queue_t *watch_que, watch_msg_node_t *watch_node)
{
    cs_packet_t *pack = &watch_que->pack;
    session_t *sess = NULL;

    int ret = srv_get_sess_by_id(watch_node->sid, &sess);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[WATCH] get session fail, sid:%u", watch_node->sid);
        return ret;
    }

    cs_init_set(pack, CS_LOCAL_VERSION);
    pack->head->cmd = DCC_CMD_WATCH;
    watch_res_t rsp = {
        .watch_event = watch_node->event_type,
        .is_dir = watch_node->is_prefix_notify,
        .key_size = ENTRY_K(watch_node->entry)->len,
        .key = ENTRY_K(watch_node->entry)->value,
        .now_val_size = ENTRY_V(watch_node->entry)->len,
        .now_val = ENTRY_V(watch_node->entry)->value
    };
    ret = encode_watch_res(pack, &rsp);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[WATCH] encode watch msg node res failed, ret:%d", ret);
        return ret;
    }
    ret = cs_write(sess->pipe, pack);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[WATCH] watch sent msg node cs_write failed, ret:%d", ret);
    }
    return ret;
}

static watch_msg_node_t* srv_alloc_watch_node(dcc_event_t *watch_event)
{
    watch_msg_node_t *watch_node = (watch_msg_node_t *)exc_alloc(sizeof(watch_msg_node_t));
    if (watch_node == NULL) {
        return NULL;
    }
    watch_node->sid = watch_event->sid;
    watch_node->event_type = watch_event->event_type;
    watch_node->is_prefix_notify = watch_event->is_prefix_notify;
    msg_entry_t *entry = (msg_entry_t*)watch_event->kvp;
    exc_entry_inc_ref(entry);
    watch_node->entry = entry;
    return watch_node;
}

static inline void srv_free_watch_node(watch_msg_node_t *watch_node)
{
    exc_entry_dec_ref(watch_node->entry);
    exc_free(watch_node);
}

void watch_send_msg(void)
{
    watch_msg_queue_t *watch_que = NULL;
    watch_msg_node_t *watch_node = NULL;
    biqueue_node_t *node = NULL;

    for (int i = 0; i < DCC_MAX_SESS_WATCH_QUE_NUM; i++) {
        watch_que = g_dcc_watch_mgr->watch_que[i];
        if (biqueue_empty(&watch_que->que)) {
            continue;
        }

        uint32 que_len = watch_que->que_len;
        LOG_DEBUG_INF("[WATCH] watch_send_msg cur watch_que info: que_id:%u que_len:%u", watch_que->id, que_len);
        while (que_len--) {
            cm_spin_lock(&watch_que->lock, NULL);
            node = biqueue_del_head(&watch_que->que);
            if (node == NULL) {
                cm_spin_unlock(&watch_que->lock);
                break;
            }
            (watch_que->que_len)--;
            cm_spin_unlock(&watch_que->lock);
            (void)cm_atomic_dec(&g_dcc_watch_mgr->total_msg_cnt);
            watch_node = OBJECT_OF(watch_msg_node_t, node);
            if (watch_send_msg_node(watch_que, watch_node) != CM_SUCCESS) {
                LOG_DEBUG_ERR("[WATCH] watch send msg node failed, sid:%u type:%u key:%s value:%s",
                    watch_node->sid, watch_node->event_type, T2S((text_t*)ENTRY_K(watch_node->entry)),
                    T2S_EX((text_t*)ENTRY_V(watch_node->entry)));
                srv_free_watch_node(watch_node);
                continue;
            }

            LOG_DEBUG_INF("[WATCH] watch send msg node succeed, sid:%u type:%u key:%s value:%s",
                watch_node->sid, watch_node->event_type, T2S((text_t*)ENTRY_K(watch_node->entry)),
                T2S_EX((text_t*)ENTRY_V(watch_node->entry)));
            srv_free_watch_node(watch_node);
        }
    }
    return;
}

static void watch_msg_send_entry(thread_t *thread)
{
    cm_set_thread_name("send_watch_msg");
    LOG_RUN_INF("[WATCH] send_watch_msg thread started, tid:%lu, close:%u", thread->id, thread->closed);
    while (!thread->closed) {
        if (g_dcc_watch_mgr->total_msg_cnt == 0) {
            (void)cm_event_timedwait(&g_dcc_watch_mgr->event, CM_SLEEP_1_FIXED);
            continue;
        }
        watch_send_msg();
    }
    LOG_RUN_INF("[WATCH] send_watch_msg thread closed, tid:%lu, close:%u", thread->id, thread->closed);

    cm_release_thread(thread);
}

status_t srv_init_watch_mgr(void)
{
    if (g_dcc_watch_mgr == NULL) {
        g_dcc_watch_mgr = (watch_mgr_t *)malloc(sizeof(watch_mgr_t));
        if (g_dcc_watch_mgr == NULL) {
            LOG_RUN_ERR("[WATCH] srv_init_watch_mgr malloc watch_mgr failed");
            return CM_ERROR;
        }
    }
    int ret = memset_s(g_dcc_watch_mgr, sizeof(watch_mgr_t), 0, sizeof(watch_mgr_t));
    if (ret != EOK) {
        CM_FREE_PTR(g_dcc_watch_mgr);
        return CM_ERROR;
    }

    if (cm_event_init(&g_dcc_watch_mgr->event) != CM_SUCCESS) {
        CM_FREE_PTR(g_dcc_watch_mgr);
        LOG_RUN_ERR("[WATCH] srv_init_watch_mgr failed.");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < DCC_MAX_SESS_WATCH_QUE_NUM; i++) {
        watch_msg_queue_t *watch_que = (watch_msg_queue_t *)malloc(sizeof(watch_msg_queue_t));
        if (watch_que == NULL) {
            LOG_RUN_ERR("[WATCH] srv_init_watch_mgr malloc watch_que failed.");
            return CM_ERROR;
        }
        ret = memset_s(watch_que, sizeof(watch_msg_queue_t), 0, sizeof(watch_msg_queue_t));
        if (ret != EOK) {
            CM_FREE_PTR(watch_que);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return CM_ERROR;
        }
        watch_que->id = i;
        biqueue_init(&watch_que->que);
        cs_init_pack(&watch_que->pack, 0, CM_MAX_PACKET_SIZE);
        g_dcc_watch_mgr->watch_que[i] = watch_que;
    }

    ret = cm_create_thread(watch_msg_send_entry, 0, NULL, &g_dcc_watch_mgr->thread);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[WATCH] create send watch msg thread failed");
        return CM_ERROR;
    }

    LOG_RUN_INF("srv init sess watch mgr succeed.");

    return CM_SUCCESS;
}

void srv_uninit_watch_mgr(void)
{
    if (g_dcc_watch_mgr == NULL) {
        return;
    }

    if (!g_dcc_watch_mgr->thread.closed) {
        cm_close_thread(&g_dcc_watch_mgr->thread);
    }

    for (int i = 0; i < DCC_MAX_SESS_WATCH_QUE_NUM; i++) {
        CM_FREE_PTR(g_dcc_watch_mgr->watch_que[i]);
    }

    CM_FREE_PTR(g_dcc_watch_mgr);
}

int srv_proc_watch_event(dcc_event_t *watch_event)
{
    LOG_DEBUG_INF("[WATCH] session recved watch event with sid:%u type:%u key:%s value:%s", watch_event->sid,
        watch_event->event_type, T2S((text_t*)&watch_event->kvp->key), T2S_EX((text_t*)&watch_event->kvp->value));

    watch_msg_node_t *watch_node = srv_alloc_watch_node(watch_event);
    if (watch_node == NULL) {
        LOG_DEBUG_ERR("[WATCH] srv_proc_watch_event alloc sess watch node failed.");
        return CM_ERROR;
    }

    uint32 watch_que_idx = watch_event->sid % DCC_MAX_SESS_WATCH_QUE_NUM;
    watch_msg_queue_t *watch_que = g_dcc_watch_mgr->watch_que[watch_que_idx];

    cm_spin_lock(&watch_que->lock, NULL);
    biqueue_add_tail(&watch_que->que, QUEUE_NODE_OF(watch_node));
    (watch_que->que_len)++;
    cm_spin_unlock(&watch_que->lock);
    (void)cm_atomic_inc(&g_dcc_watch_mgr->total_msg_cnt);

    LOG_DEBUG_INF("[WATCH] session enqued watch event: sid:%u que_id:%u que_len:%u total_msg_cnt:%lld",
        watch_event->sid, watch_que_idx, watch_que->que_len, g_dcc_watch_mgr->total_msg_cnt);

    cm_event_notify(&g_dcc_watch_mgr->event);

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

