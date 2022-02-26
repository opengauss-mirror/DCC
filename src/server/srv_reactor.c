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
 * srv_reactor.c
 *    reactor realization
 *
 * IDENTIFICATION
 *    src/server/srv_reactor.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_error.h"
#include "cm_memory.h"
#include "cm_queue.h"
#include "cm_spinlock.h"
#include "cm_epoll.h"
#include "util_defs.h"
#include "srv_instance.h"
#include "srv_reactor.h"

#define SLEEP_TIME             5
#define WAIT_TIME             50

static status_t reactor_add_epoll_session(session_t *session)
{
    reactor_t *reactor = session->reactor;
    struct epoll_event ev;
    int fd = (int)session->pipe->link.tcp.sock;

    CM_ASSERT(session->agent == NULL);
    (void)cm_atomic32_inc(&reactor->session_count);
    ev.events = EPOLLIN |  EPOLLRDHUP | EPOLLONESHOT;
    ev.data.ptr = session;
    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        LOG_RUN_ERR("[reactor] register session to reactor failed, session %u, reactor %lu, active agent num %u",
            session->id, reactor->thread.id, reactor->agent_pool.curr_count);
        (void)cm_atomic32_dec(&reactor->session_count);
        return CM_ERROR;
    }
    session->is_reg = CM_TRUE;
    LOG_DEBUG_INF("[reactor] register session %u to reactor %lu sucessfully, current session count %ld",
        session->id, reactor->thread.id, (long)reactor->session_count);

    return CM_SUCCESS;
}

status_t reactor_register_session(session_t *session)
{
    reactor_pool_t *pool = &g_srv_inst->reactor_pool;
    reactor_t *reactor = NULL;
    uint32 count = 0;

    while (1) {
        ++count;
        reactor = &pool->reactors[pool->roudroubin++ % pool->reactor_count];
        // if agent pool no idle, continue to check
        if (reactor_in_dedicated_mode(reactor)) {
            break;
        }

        if (count == pool->reactor_count) {
            reactor = &pool->reactors[pool->roudroubin2++ % pool->reactor_count];
            break;
        }
    }

    session->reactor = reactor;
    CM_MFENCE;

    return reactor_add_epoll_session(session);
}

void reactor_unregister_session(session_t *session)
{
    int fd = (int)session->pipe->link.tcp.sock;
    reactor_t *reactor = session->reactor;

    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_DEL, fd, NULL) != 0) {
        LOG_RUN_ERR("[reactor] unregister session from reactor failed, session %u, reactor %lu",
            session->id, reactor->thread.id);
        return;
    }

    (void)cm_atomic32_dec(&reactor->session_count);
    session->is_reg = CM_FALSE;
    LOG_DEBUG_INF("[reactor] unregister session %u from reactor %lu, current session count %d",
        session->id, reactor->thread.id, reactor->session_count);
}

static void reactor_entry(thread_t *thread);

static status_t reactor_work(reactor_t *reactor)
{
    if (cm_create_thread(reactor_entry, 0, reactor, &reactor->thread) != CM_SUCCESS) {
        LOG_RUN_ERR("[reactor] failed to create reactor thread");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline uint32 avg_round_ceil(uint32 a, uint32 b)
{
    return (((a) + (b) - 1) / (b));
}

static inline void reactor_init_kill_events(reactor_t *reactor)
{
    reactor_pool_t *pool = &g_srv_inst->reactor_pool;
    kill_event_queue_t *queue = &reactor->kill_events;
    queue->r_pos = 0;
    queue->w_pos = 0;
    queue->w_lock = 0;
    queue->count = avg_round_ceil(CM_MAX_SESSIONS, pool->reactor_count);
    queue->sesses = (session_t **)(pool->sess_buf + reactor->id * queue->count * sizeof(session_t *));
}

static inline status_t reactor_start(reactor_t *reactor, uint32 optimized_count, uint32 max_count)
{
    reactor->status = REACTOR_STATUS_RUNNING;
    reactor->epollfd = epoll_create1(0);
    reactor_init_kill_events(reactor);

    reactor->agent_pool.reactor = reactor;
    reactor->agent_pool.max_count = max_count;
    reactor->agent_pool.optimized_count = optimized_count;
    CM_RETURN_IFERR(srv_create_agent_pool(&reactor->agent_pool));

    return reactor_work(reactor);
}

static status_t reactor_start_pool(void)
{
    reactor_t *reactor = NULL;
    uint32 size;
    uint32 loop;
    uint32 max_agents, remainder1, avg_magents;
    uint32 optimized_agents, remainder2, avg_oagents;

    reactor_pool_t *pool = &g_srv_inst->reactor_pool;
    size = pool->reactor_count;
    max_agents = g_srv_inst->attr.max_worker_count / pool->reactor_count;
    remainder1 = g_srv_inst->attr.max_worker_count % pool->reactor_count;

    optimized_agents = g_srv_inst->attr.optimized_worker_count / pool->reactor_count;
    remainder2 = g_srv_inst->attr.optimized_worker_count % pool->reactor_count;

    for (loop = 0; loop < size; loop++) {
        reactor = &pool->reactors[loop];
        reactor->id = loop;
        avg_magents = max_agents + (loop < remainder1 ? 1 : 0);
        avg_oagents = optimized_agents + (loop < remainder2 ? 1 : 0);
        CM_RETURN_IFERR(reactor_start(reactor, avg_oagents, avg_magents));
    }

    return CM_SUCCESS;
}

status_t reactor_create_pool(void)
{
    size_t size;
    reactor_pool_t *pool = &g_srv_inst->reactor_pool;
    errno_t ret;

    pool->roudroubin = 0;
    pool->roudroubin2 = 0;
    uint32 count = avg_round_ceil(CM_MAX_SESSIONS, pool->reactor_count);
    size = (sizeof(reactor_t) + sizeof(session_t *) * count) * pool->reactor_count;

    if (size == 0 || size / (sizeof(reactor_t) + sizeof(session_t *) * count) != pool->reactor_count) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)0, "creating reactor pool");
        return CM_ERROR;
    }
    pool->reactors = (reactor_t *)malloc(size);
    if (pool->reactors == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating reactor pool");
        return CM_ERROR;
    }

    ret = memset_s(pool->reactors, size, 0, size);
    if (ret != EOK) {
        CM_FREE_PTR(pool->reactors);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (ret));
        return CM_ERROR;
    }
    pool->sess_buf = (char *)(pool->reactors + pool->reactor_count);
    if (reactor_start_pool() != CM_SUCCESS) {
        reactor_destroy_pool();
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void reactor_destroy_pool(void)
{
    reactor_t *reactor = NULL;
    uint32 loop;
    uint32 size;

    reactor_pool_t *pool = &g_srv_inst->reactor_pool;
    size = pool->reactor_count;

    for (loop = 0; loop < size; loop++) {
        reactor = &pool->reactors[loop];
        cm_close_thread(&reactor->thread);
        srv_destroy_agent_pool(&reactor->agent_pool);
        reactor->status = REACTOR_STATUS_STOPPED;
    }
    pool->reactor_count = 0;
    CM_FREE_PTR(pool->reactors);
}

void reactor_pause_pool(void)
{
    reactor_pool_t *pool = &g_srv_inst->reactor_pool;
    reactor_t *reactor = NULL;
    for (uint32 i = 0; i < pool->reactor_count; i++) {
        reactor = &pool->reactors[i];
        reactor->status = REACTOR_STATUS_PAUSING;
        while (reactor->status != REACTOR_STATUS_PAUSED && !reactor->thread.closed) {
            cm_sleep(CM_SLEEP_5_FIXED);
        }
    }
}

status_t reactor_set_oneshot(session_t *session)
{
    struct epoll_event ev;
    int fd = (int)session->pipe->link.tcp.sock;

    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT;
    ev.data.ptr = session;

    if (epoll_ctl(session->reactor->epollfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t reactor_handle_event(const reactor_t *reactor, session_t *sess)
{
    int32 err_code;
    const char *message = NULL;
    agent_t *agent = NULL;

    status_t status = srv_attach_agent(sess, &agent, CM_FALSE);
    if (status != CM_SUCCESS) {
        cm_get_error(&err_code, &message);
        LOG_RUN_ERR("[reactor] attach agent failed, sid [%u], reactor %lu err_err_code %d",
            sess->id, reactor->thread.id, err_code);
        if (err_code == ERR_ALLOC_MEMORY || err_code == ERR_CREATE_THREAD) {
            cm_sleep(WAIT_TIME);
        }
        return CM_ERROR;
    }

    if (agent != NULL) {
        LOG_DEBUG_INF("[reactor] receive message from session %u, attached agent %lu", sess->id, agent->thread.id);
        cm_event_notify(&agent->event);
    }

    return CM_SUCCESS;
}

void reactor_add_kill_event(session_t *sess)
{
    uint32 next_w_pos;

    reactor_t *reactor = sess->reactor;
    kill_event_queue_t *kill_events = &reactor->kill_events;
    for (;;) {
        cm_spin_lock(&kill_events->w_lock, NULL);
        next_w_pos = (kill_events->w_pos + 1) % kill_events->count;
        if (next_w_pos != kill_events->r_pos) {
            break;
        }
        cm_spin_unlock(&kill_events->w_lock);
        cm_sleep(SLEEP_TIME);
    }
    kill_events->sesses[kill_events->w_pos] = sess;
    CM_MFENCE;
    kill_events->w_pos = next_w_pos;
    cm_spin_unlock(&kill_events->w_lock);
    LOG_DEBUG_INF("[reactor] add session %u to kill event queue [w_pos %u, r_pos %u] success.",
        sess->id, reactor->kill_events.w_pos, reactor->kill_events.r_pos);
    return;
}

static status_t reactor_deal_kill_events(reactor_t *reactor)
{
    status_t status;
    uint32 last_w_pos, last_r_pos, r_pos;
    session_t *sess = NULL;
    agent_t *agent = NULL;

    kill_event_queue_t *kill_events = &reactor->kill_events;
    last_w_pos = kill_events->w_pos;
    last_r_pos = kill_events->r_pos;
    r_pos = kill_events->r_pos;

    if (SECUREC_LIKELY(last_w_pos == last_r_pos)) {
        return CM_SUCCESS;
    }

    while (r_pos != last_w_pos) {
        sess = kill_events->sesses[r_pos];
        if (sess == NULL) {
            r_pos = (r_pos + 1) % kill_events->count;
            last_r_pos = (last_r_pos + 1) % kill_events->count;
            continue;
        }

        // there's session still processing by an agent
        cm_spin_lock(&sess->detaching_lock, NULL);
        if (sess->agent != NULL) {
            r_pos = (r_pos + 1) % kill_events->count;
            LOG_DEBUG_INF("[reactor] deal kill events session[%u] agent is not null, "
                "last_w_pos %u, last_r_pos %u, r_pos %u", sess->id, last_w_pos, last_r_pos, r_pos);
            cm_spin_unlock(&sess->detaching_lock);
            continue;
        }
        cm_spin_unlock(&sess->detaching_lock);

        status = srv_attach_agent(sess, &agent, CM_FALSE);
        if (status != CM_SUCCESS) {
            LOG_RUN_ERR("[reactor] deal kill events attach agent failed, "
                "sid [%u] last_w_pos %u, last_r_pos %u, r_pos %u", sess->id, last_w_pos, last_r_pos, r_pos);
            kill_events->r_pos = last_r_pos;
            return CM_ERROR;
        }

        if (agent != NULL) {
            kill_events->sesses[r_pos] = kill_events->sesses[last_r_pos];
            kill_events->sesses[last_r_pos] = NULL;

            last_r_pos = (last_r_pos + 1) % kill_events->count;
            r_pos = (r_pos + 1) % kill_events->count;

            LOG_DEBUG_INF("[reactor] attached agent to release session, "
                "sid [%u], last_w_pos %u, last_r_pos %u, r_pos %u", (uint32)sess->id, last_w_pos, last_r_pos, r_pos);
            reactor_unregister_session(sess);
            cm_event_notify(&agent->event);
        }
    }
    kill_events->r_pos = last_r_pos;

    return CM_SUCCESS;
}

static void reactor_wait4events(reactor_t *reactor)
{
    session_t *sess = NULL;
    int loop, nfds;
    struct epoll_event events[CM_EV_WAIT_NUM];
    struct epoll_event *ev = NULL;

    // first deal with session killed
    status_t status = reactor_deal_kill_events(reactor);
    if (status != CM_SUCCESS) {
        LOG_DEBUG_ERR("[reactor] reactor deal kill events failed");
        return;
    }

    if (reactor->status != REACTOR_STATUS_RUNNING) {
        return;
    }

    nfds = epoll_wait(reactor->epollfd, events, CM_EV_WAIT_NUM, CM_EV_WAIT_TIMEOUT);
    if (nfds == -1) {
        if (errno != EINTR) {
            LOG_RUN_ERR("[reactor] failed to wait for connection request");
        }
        return;
    }
    if (nfds == 0) {
        return;
    }

    for (loop = 0; loop < nfds; ++loop) {
        ev = &events[loop];
        sess = (session_t *)ev->data.ptr;

        if (reactor->status != REACTOR_STATUS_RUNNING) {
            if (reactor_set_oneshot(sess) != CM_SUCCESS) {
                LOG_RUN_ERR("[reactor] set oneshot flag of socket failed, session %u, reactor %lu",
                    sess->id, reactor->thread.id);
            }
            continue;
        }

        if (ev->events & EPOLLRDHUP) {
            LOG_RUN_ERR("[reactor] epoll wait event as EPOLLRDHUP, session id %u, reactor %lu",
                sess->id, reactor->thread.id);
            reactor_add_kill_event(sess);
            continue;
        }

        status_t ret = reactor_handle_event(reactor, sess);
        if (ret != CM_SUCCESS) {
            return;
        }
    }
}

static void reactor_handle_events(reactor_t *reactor)
{
    reactor_wait4events(reactor);

    if (reactor_in_dedicated_mode(reactor)) {
        cm_sleep(SLEEP_TIME);
        srv_shrink_agent_pool(&reactor->agent_pool);
    }
}

static void reactor_entry(thread_t *thread)
{
    reactor_t *reactor = (reactor_t *)thread->argument;

    cm_set_thread_name("dcc_reactor");
    LOG_RUN_INF("[reactor] reactor thread started");
    while (!thread->closed) {
        reactor_handle_events(reactor);
        if (reactor->status == REACTOR_STATUS_PAUSING) {
            reactor->status = REACTOR_STATUS_PAUSED;
        }
    }
    LOG_RUN_INF("[reactor] reactor thread closed");
    (void)epoll_close(reactor->epollfd);
}

