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
 * srv_instance.c
 *    instance interface
 *
 * IDENTIFICATION
 *    src/server/srv_instance.c
 *
 * -------------------------------------------------------------------------
 */
#include "stdio.h"
#include "srv_reactor.h"
#include "srv_session.h"
#include "srv_param.h"
#include "srv_watch.h"
#include "cm_cipher.h"
#include "cm_file.h"
#include "cm_utils.h"
#include "srv_instance.h"

srv_inst_t *g_srv_inst = NULL;

srv_inst_t* srv_get_instance(void)
{
    return g_srv_inst;
}

static status_t srv_load_params(void)
{
    param_value_t param_value;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LSNR_ADDR, &param_value));
    PRTS_RETURN_IFERR(snprintf_s(g_srv_inst->lsnr.tcp_service.host[0], CM_MAX_IP_LEN, CM_MAX_IP_LEN - 1,
        "%s", param_value.str_val));

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_LSNR_PORT, &param_value));
    g_srv_inst->lsnr.tcp_service.port = (uint16)param_value.uint32_val;

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_REACTOR_THREADS, &param_value));
    reactor_pool_t *reactor_pool = &g_srv_inst->reactor_pool;
    reactor_pool->reactor_count = param_value.uint32_val;

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_OPTIMIZED_WORKER_THREADS, &param_value));
    g_srv_inst->attr.optimized_worker_count = param_value.uint32_val;

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_MAX_WORKER_THREADS, &param_value));
    g_srv_inst->attr.max_worker_count = param_value.uint32_val;

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_MAX_ALLOWED_PACKET, &param_value));
    g_srv_inst->attr.max_allowed_packet = param_value.uint32_val;

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SRV_AGENT_SHRINK_THRESHOLD, &param_value));
    g_srv_inst->reactor_pool.agents_shrink_threshold = param_value.uint32_val;

    LOG_RUN_INF("[INST] server load params successfully, lsnr host:%s port:%u reactor_cnt:%u optimized_worker_count:%u "
        "max_worker_count:%u max_allowed_packet:%u agent_shrink_threshold:%u",
        g_srv_inst->lsnr.tcp_service.host[0], g_srv_inst->lsnr.tcp_service.port, reactor_pool->reactor_count,
        g_srv_inst->attr.optimized_worker_count, g_srv_inst->attr.max_worker_count,
        g_srv_inst->attr.max_allowed_packet, g_srv_inst->reactor_pool.agents_shrink_threshold);

    return CM_SUCCESS;
}

static status_t load_key_file(char *file_path, char *file_name, void *buf, int32 buf_size, int32 *read_size)
{
    char full_file_name[CM_FULL_PATH_BUFFER_SIZE] = { 0 };
    char real_file_name[CM_FULL_PATH_BUFFER_SIZE] = { 0 };
    PRTS_RETURN_IFERR(snprintf_s(full_file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/%s",
        file_path, file_name));
    CM_RETURN_IFERR(realpath_file(full_file_name, real_file_name, CM_FULL_PATH_BUFFER_SIZE));
    if (!cm_file_exist(real_file_name)) {
        LOG_RUN_INF("[INST]file_name=%s is not exist.", real_file_name);
        return CM_SUCCESS;
    }

    int32 fd = -1;
    if (cm_open_file(real_file_name, O_RDONLY | O_BINARY, &fd) != CM_SUCCESS) {
        LOG_RUN_ERR("[INST]open file_name=%s failed.", real_file_name);
        return CM_ERROR;
    }

    if (cm_read_file(fd, buf, buf_size, read_size) != CM_SUCCESS) {
        cm_close_file(fd);
        LOG_RUN_ERR("[INST]read file_name=%s failed.", real_file_name);
        return CM_ERROR;
    }
    cm_close_file(fd);
    return CM_SUCCESS;
}

static status_t srv_verify_ssl_key_pwd(ssl_config_t *para, char *plain, uint32 size)
{
    cipher_t cipher = {{ 0 }};
    param_value_t param_value;
    char *file_path;

    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_KEYPWD_FILE_PATH, &param_value));
    file_path = param_value.str_val;

    int32 read_size = 0;
    CM_RETURN_IFERR(load_key_file(file_path, KEY_RAND_FILE, cipher.rand, RANDOM_LEN, &read_size));
    CM_RETURN_IFERR(load_key_file(file_path, KEY_SALT_FILE, cipher.salt, RANDOM_LEN, &read_size));
    CM_RETURN_IFERR(load_key_file(file_path, KEY_IV_FILE, cipher.IV, RANDOM_LEN, &read_size));

    CM_RETURN_IFERR(load_key_file(file_path, KEY_CIPHER_FILE, cipher.cipher_text, (int32)CM_PASSWORD_BUFFER_SIZE,
        &read_size));
    cipher.cipher_len = (uint32)read_size;

    if (cipher.cipher_len > 0) {
        if (cm_decrypt_pwd(&cipher, (uchar*)plain, &size) != CM_SUCCESS) {
            MEMS_RETURN_IFERR(memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher)));
            return CM_ERROR;
        }
        para->key_password = plain;
    }

    MEMS_RETURN_IFERR(memset_s(&cipher, sizeof(cipher), 0, sizeof(cipher)));
    return CM_SUCCESS;
}

status_t srv_chk_ssl_cert_expire(void)
{
    if (g_srv_inst->ssl_acceptor_fd == NULL) {
        return CM_SUCCESS;
    }

    param_value_t alert_threshold;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_CERT_EXPIRE_ALERT_THRESHOLD, &alert_threshold));
    if (alert_threshold.uint32_val < CM_MIN_SSL_EXPIRE_THRESHOLD ||
        alert_threshold.uint32_val > CM_MAX_SSL_EXPIRE_THRESHOLD) {
        LOG_RUN_ERR("[INST]invalid ssl expire alert threshold %u, must between %u and %u",
            alert_threshold.uint32_val, CM_MIN_SSL_EXPIRE_THRESHOLD, CM_MAX_SSL_EXPIRE_THRESHOLD);
        return CM_ERROR;
    }
    ssl_ca_cert_expire(g_srv_inst->ssl_acceptor_fd, (int32)alert_threshold.uint32_val);
    return CM_SUCCESS;
}

static status_t srv_init_ssl(void)
{
    ssl_config_t para = { 0 };
    char plain[CM_PASSWD_MAX_LEN + 1] = { 0 };
    param_value_t ssl_enable, ca, key, cert, crl, cipher, verify_peer;

    g_srv_inst->ssl_acceptor_fd = NULL;

    // required parameters
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_ENABLE, &ssl_enable));
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_KEY, &key));
    para.key_file = key.str_val;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_CERT, &cert));
    para.cert_file = cert.str_val;

    if (ssl_enable.uint32_val == 0) {
        LOG_RUN_INF("[INST] srv_init_ssl: ssl is disabled.");
        return CM_SUCCESS;
    }

    if (CM_IS_EMPTY_STR(para.cert_file) || CM_IS_EMPTY_STR(para.key_file)) {
        LOG_RUN_ERR("[INST] srv_init_ssl: cert_file(%s) or key_file(%s) error.", para.cert_file, para.key_file);
        return CM_ERROR;
    }

    // optional parameters
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_CA, &ca));
    para.ca_file = ca.str_val;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_CRL, &crl));
    para.crl_file = crl.str_val;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_CIPHER, &cipher));
    para.cipher = cipher.str_val;
    CM_RETURN_IFERR(srv_get_param(DCC_PARAM_SSL_VERIFY_PEER, &verify_peer));
    para.verify_peer = CM_IS_EMPTY_STR(para.ca_file) ? CM_FALSE : verify_peer.uint32_val;

    /* require no public access to key file */
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(para.key_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(para.cert_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(para.ca_file));

    // verify ssl key password
    if (srv_verify_ssl_key_pwd(&para, plain, sizeof(plain) - 1) != CM_SUCCESS) {
        LOG_RUN_ERR("[INST] srv verify ssl keypwd failed.");
        return CM_ERROR;
    }

    // create acceptor context
    g_srv_inst->ssl_acceptor_fd = cs_ssl_create_acceptor_fd(&para);
    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
    if (g_srv_inst->ssl_acceptor_fd == NULL) {
        LOG_RUN_ERR("[INST] srv create ssl acceptor context failed.");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(srv_chk_ssl_cert_expire());

    LOG_RUN_INF("[INST] srv_init_ssl: ssl is enabled.");
    return CM_SUCCESS;
}

void srv_deinit_ssl(void)
{
    if (g_srv_inst->ssl_acceptor_fd != NULL) {
        cs_ssl_free_context(g_srv_inst->ssl_acceptor_fd);
        g_srv_inst->ssl_acceptor_fd = NULL;
        LOG_RUN_INF("srv deinit ssl end.");
    }
}

static status_t srv_instance_create(void)
{
    if (g_srv_inst == NULL) {
        g_srv_inst = (srv_inst_t *)malloc(sizeof(srv_inst_t));
        if (g_srv_inst == NULL) {
            return CM_ERROR;
        }
        if (memset_s(g_srv_inst, sizeof(srv_inst_t), 0, sizeof(srv_inst_t)) != EOK) {
            CM_FREE_PTR(g_srv_inst);
            return CM_ERROR;
        }
        g_srv_inst->attr.inst_type = INST_TYPE_CS;
    }

    return CM_SUCCESS;
}

status_t srv_instance_startup(void)
{
    if (srv_instance_create() != CM_SUCCESS) {
        LOG_RUN_ERR("[INST] failed to create server instance");
        return CM_ERROR;
    }

    if (srv_load_params() != CM_SUCCESS) {
        CM_FREE_PTR(g_srv_inst);
        LOG_RUN_ERR("[INST] failed to load server params");
        return CM_ERROR;
    }

    if (srv_init_session_pool() != CM_SUCCESS) {
        CM_FREE_PTR(g_srv_inst);
        LOG_RUN_ERR("[INST] failed to init session pool");
        return CM_ERROR;
    }

    if (reactor_create_pool() != CM_SUCCESS) {
        CM_FREE_PTR(g_srv_inst);
        LOG_RUN_ERR("[INST] failed to create reactor pool");
        return CM_ERROR;
    }

    if (srv_start_lsnr() != CM_SUCCESS) {
        reactor_destroy_pool();
        CM_FREE_PTR(g_srv_inst);
        LOG_RUN_ERR("[INST] failed to start lsnr");
        return CM_ERROR;
    }

    if (srv_init_ssl() != CM_SUCCESS) {
        srv_stop_lsnr(LSNR_TYPE_ALL);
        reactor_destroy_pool();
        CM_FREE_PTR(g_srv_inst);
        LOG_RUN_ERR("[INST] failed to init ssl");
        return CM_ERROR;
    }

    if (srv_init_watch_mgr() != CM_SUCCESS) {
        srv_deinit_ssl();
        srv_stop_lsnr(LSNR_TYPE_ALL);
        reactor_destroy_pool();
        srv_uninit_watch_mgr();
        CM_FREE_PTR(g_srv_inst);
        LOG_RUN_ERR("[INST] failed to init watch mgr");
        return CM_ERROR;
    }

    LOG_RUN_INF("[INST] srv instance started.");
    (void)printf("dcc server started successfully\n");
    return CM_SUCCESS;
}

static void srv_add_all_sess_kill(void)
{
    uint32 i;
    session_pool_t *pool = &g_srv_inst->session_pool;

    /* add all user session to be killed */
    for (i = 0; i < pool->hwm; i++) {
        session_t *session = pool->sessions[i];
        if (session == NULL || session->is_free) {
            continue;
        }
        // wait until session registered
        while (!session->is_reg) {
            cm_sleep(CM_SLEEP_5_FIXED);
        }
        reactor_add_kill_event(session);
    }
    LOG_RUN_INF("srv add all session kill end");
}

static void srv_wait_agents_done(void)
{
    LOG_RUN_INF("begin to wait agents done, pause all listener and reactor pool");
    srv_pause_lsnr(LSNR_TYPE_ALL);
    reactor_pause_pool();

    // wait agents done and all session free
    srv_add_all_sess_kill();
    srv_wait_all_session_free();

    LOG_RUN_INF("end to wait all agents done");
    return;
}

void srv_instance_destroy(void)
{
    if (g_srv_inst == NULL) {
        return;
    }

    srv_wait_agents_done();
    srv_kill_all_session();
    srv_deinit_ssl();

    // uninit watch mgr
    LOG_RUN_INF("[INST] begin to uninit watch mgr");
    srv_uninit_watch_mgr();

    // stop listener
    LOG_RUN_INF("[INST] begin to stop all listener");
    srv_stop_lsnr(LSNR_TYPE_ALL);

    // stop reactor pool
    LOG_RUN_INF("[INST] begin to stop reactor");
    reactor_destroy_pool();

    if (srv_dcc_stop() != CM_SUCCESS) {
        LOG_RUN_INF("Exception occurred during DCC shutdown, errcode: %d, errmsg: %s",
            cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
    }

    CM_FREE_PTR(g_srv_inst);
}

