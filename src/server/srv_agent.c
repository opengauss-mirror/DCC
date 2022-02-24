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
 * srv_agent.c
 *    agent interface
 *
 * IDENTIFICATION
 *    src/server/srv_agent.c
 *
 * -------------------------------------------------------------------------
 */
#include "util_defs.h"
#include "cm_atomic.h"
#include "cm_log.h"
#include "srv_instance.h"
#include "cm_memory.h"
#include "srv_session.h"
#include "dcc_msg_protocol.h"
#include "srv_agent.h"

status_t srv_create_agent_pool(agent_pool_t *agent_pool)
{
    size_t size;
    uint32 loop;
    agent_t *agent = NULL;

    agent_pool->curr_count = 0;
    agent_pool->extended_count = 0;
    size = sizeof(agent_t) * agent_pool->optimized_count;
    if (size == 0 || size / sizeof(agent_t) != agent_pool->optimized_count) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating agent pool");
        return CM_ERROR;
    }
    agent_pool->agents = (agent_t *)malloc(size);
    if (agent_pool->agents == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating agent pool");
        return CM_ERROR;
    }
    errno_t ret = memset_s(agent_pool->agents, size, 0, size);
    if (ret != EOK) {
        CM_FREE_PTR(agent_pool->agents);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    agent_pool->lock_idle = 0;
    biqueue_init(&agent_pool->idle_agents);

    agent_pool->lock_new = 0;
    biqueue_init(&agent_pool->blank_agents);
    for (loop = 0; loop < agent_pool->optimized_count; ++loop) {
        agent = &agent_pool->agents[loop];
        agent->reactor = agent_pool->reactor;
        agent->is_extend = CM_FALSE;
        biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(agent));
    }
    agent_pool->blank_count = agent_pool->optimized_count;

    if (cm_event_init(&agent_pool->idle_evnt) != CM_SUCCESS) {
        CM_FREE_PTR(agent_pool->agents);
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void shrink_pool_core(agent_pool_t *agent_pool)
{
    agent_t *agent = NULL;
    biqueue_node_t *next = NULL;

    if (agent_pool->idle_count == 0) {
        return;
    }

    cm_spin_lock(&agent_pool->lock_idle, NULL);
    biqueue_node_t *curr = biqueue_first(&agent_pool->idle_agents);
    biqueue_node_t *end = biqueue_end(&agent_pool->idle_agents);

    while (curr != end) {
        agent = OBJECT_OF(agent_t, curr);
        next = curr->next;
        if (agent->is_extend == CM_TRUE) {
            // waiting to return to blank list
            cm_spin_lock(&agent_pool->lock_new, NULL);
            agent->thread.closed = CM_TRUE;
            biqueue_del_node(QUEUE_NODE_OF(agent));
            agent_pool->idle_count--;
            cm_spin_unlock(&agent_pool->lock_new);
        }
        curr = next;
    }

    agent_pool->shrink_hit_count = 0;
    cm_spin_unlock(&agent_pool->lock_idle);
}

void srv_shrink_agent_pool(agent_pool_t *agent_pool)
{
    if (agent_pool->extended_count == 0) {
        return;
    }

    agent_pool->shrink_hit_count++;

    if (agent_pool->shrink_hit_count > (long)AGENT_SHRINK_THRESHOLD(g_srv_inst->reactor_pool.agents_shrink_threshold)) {
        LOG_DEBUG_INF("[agent_pool] begin with shrink extend agents ...");
        shrink_pool_core(agent_pool);
        LOG_DEBUG_INF("[agent_pool] end of shrink extend agents.");
    }
}

static void close_extend_agent(agent_pool_t *agent_pool)
{
    if (agent_pool->ext_agents == NULL) {
        return;
    }

    agent_t *slot_agents = NULL;
    uint32 slot_used_id = CM_ALIGN_CEIL(agent_pool->extended_count, AGENT_EXTEND_STEP);

    LOG_RUN_INF("[agent] close extend agents' thread, extended slot count: %u", slot_used_id);

    for (uint32 i = 0; i < slot_used_id; ++i) {
        slot_agents = agent_pool->ext_agents[i].slot_agents;
        for (uint16 j = 0; j < agent_pool->ext_agents[i].slot_agent_count; j++) {
            slot_agents[j].thread.closed = CM_TRUE;
        }
    }
}

static void free_extend_agent(agent_pool_t *agent_pool)
{
    if (agent_pool->ext_agents == NULL) {
        return;
    }

    agent_t *slot_agents = NULL;
    uint32 slot_used_id = CM_ALIGN_CEIL(agent_pool->extended_count, AGENT_EXTEND_STEP);
    LOG_RUN_INF("[agent] free extend agents, extended slot count: %u", slot_used_id);

    for (uint32 i = 0; i < slot_used_id; ++i) {
        slot_agents = agent_pool->ext_agents[i].slot_agents;
        CM_FREE_PTR(slot_agents);
    }
    CM_FREE_PTR(agent_pool->ext_agents);
    agent_pool->extended_count = 0;
}

static void srv_shutdown_agent_pool(agent_pool_t *agent_pool)
{
    close_extend_agent(agent_pool);

    if (agent_pool->agents != NULL) {
        for (uint32 i = 0; i < agent_pool->optimized_count; i++) {
            agent_pool->agents[i].thread.closed = CM_TRUE;
        }
    }

    while (agent_pool->curr_count > 0) {
        cm_sleep(1);
    }
    LOG_RUN_INF("[agent] all agents' thread have been closed");

    biqueue_init(&agent_pool->idle_agents);
    biqueue_init(&agent_pool->blank_agents);
    agent_pool->blank_count = 0;
    agent_pool->idle_count = 0;
    CM_FREE_PTR(agent_pool->agents);

    free_extend_agent(agent_pool);
}

void srv_destroy_agent_pool(agent_pool_t *agent_pool)
{
    LOG_RUN_INF("[agent] begin to destroy agent pool");
    srv_shutdown_agent_pool(agent_pool);
    LOG_RUN_INF("[agent] destroy agent pool end");
}

static void srv_free_agent_res(agent_t *agent)
{
    cs_try_free_packet_buffer(&agent->send_pack);
    cs_try_free_packet_buffer(&agent->recv_pack);

    CM_FREE_PTR(agent->area_buf);
}

static void srv_return_agent2blankqueue(agent_t *agent)
{
    agent_pool_t *agent_pool = &agent->reactor->agent_pool;

    if (agent->next != NULL) {
        // remove agent from idle queue
        cm_spin_lock(&agent_pool->lock_idle, NULL);
        if (agent->next != NULL) {
            biqueue_del_node(QUEUE_NODE_OF(agent));
            agent_pool->idle_count--;
        }
        cm_spin_unlock(&agent_pool->lock_idle);
    }

    // add agent to blank queue
    cm_spin_lock(&agent_pool->lock_new, NULL);
    biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(agent));
    srv_free_agent_res(agent);

    --agent_pool->curr_count;
    agent_pool->blank_count++;

    cm_spin_unlock(&agent_pool->lock_new);
}

static status_t allocate_slot(agent_pool_t *agent_pool)
{
    uint32 buf_size;
    errno_t rc_memzero;

    // allocate slots according to step, then allocate agents to each slots
    uint32 slot_count = (agent_pool->max_count - agent_pool->optimized_count) / AGENT_EXTEND_STEP + 1;
    LOG_DEBUG_INF("[agent] allocate extend slots count: %u", slot_count);

    buf_size = (uint32)sizeof(extend_agent_t) * slot_count;
    if (buf_size == 0 || buf_size / sizeof(extend_agent_t) != slot_count) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending agent pool, slot allocation failed");
        return CM_ERROR;
    }
    agent_pool->ext_agents = (extend_agent_t *)malloc(buf_size);
    if (agent_pool->ext_agents == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "extending agent pool, slot allocation failed");
        return CM_ERROR;
    }
    rc_memzero = memset_sp(agent_pool->ext_agents, (size_t)buf_size, 0, (size_t)buf_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(agent_pool->ext_agents);
        CM_THROW_ERROR(ERR_RESET_MEMORY, "extending agent pool");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t extend_agent_pool(agent_pool_t *agent_pool)
{
    uint32 buf_size, slot_id, expansion_count;
    agent_t *new_agents = NULL;
    errno_t rc_memzero;

    if (agent_pool->optimized_count + agent_pool->extended_count == agent_pool->max_count) {
        return CM_SUCCESS;
    }

    if (agent_pool->ext_agents == NULL) {
        CM_RETURN_IFERR(allocate_slot(agent_pool));
    }
    expansion_count = agent_pool->max_count - (agent_pool->extended_count + agent_pool->optimized_count);
    expansion_count = MIN(expansion_count, AGENT_EXTEND_STEP);
    slot_id = agent_pool->extended_count / AGENT_EXTEND_STEP;

    LOG_DEBUG_INF("[agent] extend agents, expansion_count: %u, slot_id: %u", expansion_count, slot_id);

    buf_size = (uint32)sizeof(agent_t) * expansion_count;
    if (buf_size == 0 || buf_size / sizeof(agent_t) != expansion_count) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "expanding agent pool");
        return CM_ERROR;
    }

    new_agents = (agent_t *)malloc(buf_size);
    if (new_agents == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_size, "expanding agent pool");
        return CM_ERROR;
    }

    rc_memzero = memset_sp(new_agents, (size_t)buf_size, 0, (size_t)buf_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(new_agents);
        CM_THROW_ERROR(ERR_RESET_MEMORY, "expanding agent pool");
        return CM_ERROR;
    }

    for (uint32 loop = 0; loop < expansion_count; ++loop) {
        new_agents[loop].reactor = agent_pool->reactor;
        new_agents[loop].is_extend = CM_TRUE;
        biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(&new_agents[loop]));
        agent_pool->blank_count++;
    }

    agent_pool->ext_agents[slot_id].slot_agents = new_agents;
    agent_pool->ext_agents[slot_id].slot_agent_count = expansion_count;
    agent_pool->extended_count += expansion_count;
    agent_pool->shrink_hit_count = 0;

    return CM_SUCCESS;
}

void srv_process_free_session(session_t *session)
{
    srv_deinit_session(session);
    srv_detach_agent(session);
    CM_MFENCE;
    srv_return_session(session);
    LOG_DEBUG_INF("[agent] free session %u successfully.", session->id);
    return;
}

static status_t srv_diag_proto_type(session_t *session)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;

    CM_RETURN_IFERR(cs_read_bytes(session->pipe, (char *)&proto_code, sizeof(proto_code), &size));

    if (size != (int32)sizeof(proto_code) || proto_code != CM_PROTO_CODE) {
        LOG_DEBUG_ERR("[agent] invalid proto code:0x%x, size:%d", proto_code, size);
        CM_THROW_ERROR(ERR_INVALID_PROTOCOL, "");
        return CM_ERROR;
    }

    session->proto_type = PROTO_TYPE_DCC_CMD;

    MEMS_RETURN_IFERR(memset_s(&ack, sizeof(link_ready_ack_t), 0, sizeof(link_ready_ack_t)));
    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.version = CS_LOCAL_VERSION;
    ack.flags = 0;
    if ((session->pipe_entity.type == CS_TYPE_TCP) && (g_srv_inst->ssl_acceptor_fd != NULL)) {
        ack.flags |= CSO_SUPPORT_SSL;
    }
    return cs_send_bytes(session->pipe, (const char *)&ack, sizeof(link_ready_ack_t));
}

static status_t srv_process_single_session(session_t *session)
{
    bool32 ready = CM_FALSE;
    CM_RETURN_IFERR(cs_wait(session->pipe, CS_WAIT_FOR_READ, (int32)CM_POLL_WAIT, &ready));
    if (!ready) {
        return CM_SUCCESS;
    }

    /* process request command */
    if (session->proto_type == PROTO_TYPE_UNKNOWN) {
        status_t ret = srv_diag_proto_type(session);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[agent] srv process session diag proto type fail, sessid:%u", session->id);
        }
        return ret;
    } else {
        return srv_process_command(session);
    }
}

void srv_detach_agent(session_t *session)
{
    agent_t *agent = session->agent;
    if (agent == NULL) {
        LOG_DEBUG_WAR("[agent] srv detach agent is NULL, sessid:%u", session->id);
        return;
    }
    agent_pool_t *agent_pool = &agent->reactor->agent_pool;

    agent->session = NULL;

    cm_spin_lock(&agent_pool->lock_idle, NULL);
    biqueue_add_tail(&agent_pool->idle_agents, QUEUE_NODE_OF(agent));
    agent_pool->idle_count++;
    cm_spin_unlock(&agent_pool->lock_idle);
    cm_event_notify(&agent_pool->idle_evnt);
    LOG_DEBUG_INF("[agent] detach session %u from agent %lu success, idle agent num %u.",
        session->id, agent->thread.id, agent_pool->idle_count);
    CM_MFENCE;
    session->agent = NULL;
}

static void srv_detach_agent_and_set_oneshot(session_t *session, agent_t *agent)
{
    agent->reactor->agent_pool.shrink_hit_count = 0;
    cm_spin_lock(&session->detaching_lock, NULL);
    srv_detach_agent(session);
    CM_MFENCE;
    if (reactor_set_oneshot(session) != CM_SUCCESS) {
        LOG_RUN_ERR("[agent] set oneshot flag of socket failed, session %u, reactor %lu",
            session->id, session->reactor->thread.id);
    }
    cm_spin_unlock(&session->detaching_lock);
}

static void srv_try_process_multi_sessions(agent_t *agent)
{
    session_t *session = NULL;
    status_t ret = CM_SUCCESS;

    for (;;) {
        // event will be set by reactor
        if (cm_event_timedwait(&agent->event, CM_SLEEP_50_FIXED) == CM_SUCCESS) {
            break;
        }

        if (agent->thread.closed) {
            return;
        }
    }

    session = agent->session;
    if (!session->is_reg) {
        srv_process_free_session(session);
        return;
    }
    LOG_DEBUG_INF("[agent] begin to process socket event session %u.", session->id);

    while (!agent->thread.closed) {
        ret = srv_process_single_session(session);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[agent] srv_process_single_session fail, sessionid:%u", session->id);
        }
        if (!session->is_reg) {
            return;
        } else if (reactor_in_dedicated_mode(agent->reactor)) {
            continue;
        } else {
            srv_detach_agent_and_set_oneshot(session, agent);
            return;
        }
    }
}

static void srv_agent_entry(thread_t *thread)
{
    agent_t *agent = (agent_t *)thread->argument;

    cs_init_pack(&agent->recv_pack, 0, CM_MAX_PACKET_SIZE);
    cs_init_pack(&agent->send_pack, 0, CM_MAX_PACKET_SIZE);

    cm_set_thread_name("dcc_agent");
    LOG_RUN_INF("[agent] agent thread started, tid:%lu, close:%u", thread->id, thread->closed);
    while (!thread->closed) {
        srv_try_process_multi_sessions(agent);
    }
    LOG_RUN_INF("[agent] agent thread closed, tid:%lu, close:%u", thread->id, thread->closed);

    cm_release_thread(thread);
    srv_return_agent2blankqueue(agent);
}

static status_t srv_start_agent(agent_t *agent, thread_entry_t entry)
{
    return cm_create_thread(entry, 0, agent, &agent->thread);
}

static status_t srv_create_agent(agent_t *agent)
{
    if (cm_event_init(&agent->event) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }
    if (srv_start_agent(agent, srv_agent_entry) != CM_SUCCESS) {
        LOG_RUN_ERR("[agent] create agent thread failed");
        srv_free_agent_res(agent);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[agent] create agent(%lu) succeed", agent->thread.id);
    return CM_SUCCESS;
}

static status_t srv_try_create_agent(agent_pool_t *agent_pool, agent_t **agent)
{
    biqueue_node_t *node = NULL;
    bool32 need_create;

    if (agent_pool->curr_count == agent_pool->max_count) {
        *agent = NULL;
        return CM_SUCCESS;
    }

    if (agent_pool->curr_count == agent_pool->optimized_count + agent_pool->extended_count) {
        cm_spin_lock(&agent_pool->lock_new, NULL);
        if (extend_agent_pool(agent_pool) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[agent] try to expand agent pool failed, current expanded count: %u.",
                agent_pool->extended_count);
            cm_spin_unlock(&agent_pool->lock_new);
            return CM_ERROR;
        }
        cm_spin_unlock(&agent_pool->lock_new);
    }

    // there is no idle agent, the following two condition are true, then create a new one
    // 1.agent number not reached the optimized and the extended
    // 2.session count greater than current agent count
    cm_spin_lock(&agent_pool->lock_new, NULL);
    need_create = agent_pool->curr_count < agent_pool->optimized_count + agent_pool->extended_count &&
                  (uint32) agent_pool->reactor->session_count > agent_pool->curr_count;

    if (!need_create) {
        cm_spin_unlock(&agent_pool->lock_new);
        *agent = NULL;
        return CM_SUCCESS;
    }
    node = biqueue_del_head(&agent_pool->blank_agents);
    ++agent_pool->curr_count;
    agent_pool->blank_count--;
    cm_spin_unlock(&agent_pool->lock_new);

    // create a new agent, allocate memory and start
    *agent = OBJECT_OF(agent_t, node);
    if (srv_create_agent(*agent) != CM_SUCCESS) {
        srv_return_agent2blankqueue(*agent);
        *agent = NULL;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

inline void srv_bind_sess_agent(session_t *session, agent_t *agent)
{
    session->agent = agent;
    session->recv_pack = &agent->recv_pack;
    session->send_pack = &agent->send_pack;
    agent->session = session;

    LOG_DEBUG_INF("[agent] srv bind sessid(%u) with agent(%lu)", session->id, agent->thread.id);

    return;
}

static status_t srv_try_attach_agent(session_t *session, agent_t **agent)
{
    status_t status;
    biqueue_node_t *node = NULL;
    agent_pool_t *agent_pool = NULL;

    agent_pool = &session->reactor->agent_pool;
    // get agent from idle pool, if failed, try to create a new one
    if (!biqueue_empty(&agent_pool->idle_agents)) {
        cm_spin_lock(&agent_pool->lock_idle, NULL);
        node = biqueue_del_head(&agent_pool->idle_agents);
        if (node != NULL) {
            agent_pool->idle_count--;
        }
        cm_spin_unlock(&agent_pool->lock_idle);

        if (node != NULL) {
            *agent = OBJECT_OF(agent_t, node);
            srv_bind_sess_agent(session, *agent);
            return CM_SUCCESS;
        }
    }

    status = srv_try_create_agent(agent_pool, agent);
    CM_RETURN_IFERR(status);

    if (*agent != NULL) {
        srv_bind_sess_agent(session, *agent);
    }

    return CM_SUCCESS;
}

#define SRV_TRY_ATTACH_AGENT_FAIL_LOG_THRESHOLD 100
status_t srv_attach_agent(session_t *session, agent_t **agent, bool32 nowait)
{
    status_t status = CM_ERROR;
    agent_pool_t *agent_pool = NULL;
    uint32 count = 0;
    bool32 is_log = CM_FALSE;
    CM_ASSERT(session->agent == NULL);
    agent_pool = &session->reactor->agent_pool;
    *agent = NULL;
    for (;;) {
        status = srv_try_attach_agent(session, agent);
        CM_RETURN_IFERR(status);

        if (*agent != NULL) {
            if (agent_pool->shrink_hit_count > 0) {
                agent_pool->shrink_hit_count--;
            }
            if (is_log == CM_TRUE) {
                LOG_DEBUG_INF("[agent] srv attach agent recovery: session-id: %u", session->id);
            }
            return CM_SUCCESS;
        }

        if (nowait) {
            return CM_ERROR;
        }

        if ((++count % SRV_TRY_ATTACH_AGENT_FAIL_LOG_THRESHOLD) == 0 && !is_log) {
            LOG_DEBUG_WAR("[agent] system busy, wait for idle agent, session id %u active agent count %u, "
                "session count %d", session->id, agent_pool->curr_count, session->reactor->session_count);
            is_log = CM_TRUE;
            count = 0;
        }

        agent_pool->shrink_hit_count = 0;

        cm_event_wait(&agent_pool->idle_evnt);

        REACTOR_STATUS_INVALID_FOR_RETURN(session->reactor);
    }
}

