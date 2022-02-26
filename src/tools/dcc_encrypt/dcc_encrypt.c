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
 * dcc_encrypt.c
 *    Ciphering tool
 *
 * IDENTIFICATION
 *    src/tools/dcc_encrypt/dcc_encrypt.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_text.h"
#include "cm_types.h"
#include "cm_file.h"
#include "cm_cipher.h"
#include "cm_encrypt.h"

#include "securec.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include "openssl/x509.h"
#include "openssl/ssl.h"
#include "openssl/asn1.h"
#include "openssl/hmac.h"


#ifdef __cplusplus
extern "C" {
#endif

#define CMD_PRINTF(fmt, ...)                    \
    do {                                        \
            (void)printf(fmt, ##__VA_ARGS__);   \
            (void)fflush(stdout);               \
    } while (0)

#define ENCRYPT_RAND_FILE_NAME      "client.key.rand"
#define ENCRYPT_CIPHER_FILE_NAME    "client.key.cipher"
#define ENCRYPT_CMD_LEN             1024
#define ENCRYPT_SPLIT_STRING        " "
#define ENCRYPT_ENCLOSE_CHAR        0
#define PASSWD_NAME                 "--passwd"
#define ENCRYPT_HELP                "--help"
#define ENCTYPT_HELP1               "-h"

static cipher_t g_dcc_cipher = {0};

static status_t dcc_encrypt_random_passwd(void);

static status_t dcc_save_rand(const cipher_t *cipher)
{
    int fd;
    status_t ret = cm_create_file(ENCRYPT_RAND_FILE_NAME, O_RDWR | O_BINARY | O_APPEND | O_SYNC, &fd);
    if (ret != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    ret = cm_write_file(fd, cipher->rand, RANDOM_LEN);
    if (ret != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    ret = cm_write_file(fd, cipher->salt, RANDOM_LEN);
    if (ret != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    ret = cm_write_file(fd, cipher->IV, RANDOM_LEN);
    if (ret != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    cm_close_file(fd);
    return CM_SUCCESS;
}

static status_t dcc_save_cipher(const cipher_t *cipher)
{
    int fd;
    status_t ret = cm_create_file(ENCRYPT_CIPHER_FILE_NAME, O_RDWR | O_BINARY | O_APPEND | O_SYNC, &fd);
    if (ret != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    ret = cm_write_file(fd, cipher->cipher_text, cipher->cipher_len);
    if (ret != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    cm_close_file(fd);
    return CM_SUCCESS;
}

static status_t dcc_save(const cipher_t *cipher)
{
    status_t ret = dcc_save_rand(cipher);
    if (ret != CM_SUCCESS) {
        CMD_PRINTF("save failed\n");
        return CM_ERROR;
    }
    ret = dcc_save_cipher(cipher);
    if (ret != CM_SUCCESS) {
        CMD_PRINTF("save failed\n");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t dcc_encrypt_pwd(uchar *plain_text, uint32 plain_len)
{
    status_t ret;
    ret = cm_encrypt_pwd(plain_text, plain_len, &g_dcc_cipher);
    if (ret != CM_SUCCESS) {
        CMD_PRINTF("encrypt failed\n");
    }

    CM_RETURN_IFERR(dcc_save(&g_dcc_cipher));
    MEMS_RETURN_IFERR(memset_sp(plain_text, (size_t) plain_len, 0, (size_t) plain_len));

    return CM_SUCCESS;
}


static status_t dcc_encrypt_help(void)
{
    CMD_PRINTF("\nUsage:\n");
    CMD_PRINTF("dcc_encrypt [options]\n");
    CMD_PRINTF("dcc_encrypt [options] command [command options] [command arguments...]\n");
    CMD_PRINTF("\nOptions:\n");
    CMD_PRINTF("    --help, -h,     Shows help information\n");
    CMD_PRINTF("    --random,       encrypt a random password\n");
    CMD_PRINTF("    --passwd,       encrypt the specified password\n");
    return CM_SUCCESS;
}

static status_t dcc_parse_exc(int32 argc, char *argv[])
{
    status_t ret;
    text_t cmd_line;
    cmd_line.str = (char *) malloc(ENCRYPT_CMD_LEN);
    cmd_line.len = 0;
    for (uint32 i = 1; i < (uint32) argc; i++) {
        if (cm_concat_string(&cmd_line, ENCRYPT_CMD_LEN, argv[i]) != CM_SUCCESS) {
            CM_FREE_PTR(cmd_line.str);
            return CM_ERROR;
        }
        if (cm_concat_string(&cmd_line, ENCRYPT_CMD_LEN, ENCRYPT_SPLIT_STRING) != CM_SUCCESS) {
            CM_FREE_PTR(cmd_line.str);
            return CM_ERROR;
        }
    }

    cm_trim_text(&cmd_line);

    text_t left;
    text_t right;
    cm_split_text(&cmd_line, (ENCRYPT_SPLIT_STRING)[0], ENCRYPT_ENCLOSE_CHAR, &left, &right);
    cm_trim_text(&left);
    cm_trim_text(&right);

    if (cm_text_str_equal(&left, PASSWD_NAME)) {
        cm_split_text(&right, (ENCRYPT_SPLIT_STRING)[0], ENCRYPT_ENCLOSE_CHAR, &left, &right);
        cm_trim_text(&left);
        ret = dcc_encrypt_pwd((uchar *) left.str, left.len);
        CMD_PRINTF("encrypt password success\n");
    } else if (cm_text_str_equal(&left, ENCRYPT_HELP) || cm_text_str_equal(&left, ENCTYPT_HELP1)) {
        ret = dcc_encrypt_help();
    } else {
        ret = dcc_encrypt_random_passwd();
        CMD_PRINTF("encrypt passwd success, the password is random word\n");
    }

    CM_FREE_PTR(cmd_line.str);
    return ret;
}

static status_t dcc_encrypt_random_passwd(void)
{
    uchar *passwd = (uchar *) malloc(CM_PASSWD_MAX_LEN);
    if (passwd == NULL) {
        return CM_ERROR;
    }

    status_t ret = cm_rand(passwd, CM_PASSWD_MAX_LEN);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(passwd);
        return CM_ERROR;
    }

    ret = dcc_encrypt_pwd(passwd, CM_PASSWD_MAX_LEN);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(passwd);
        return CM_ERROR;
    }

    MEMS_RETURN_IFERR(memset_sp(passwd, CM_PASSWD_MAX_LEN, 0, CM_PASSWD_MAX_LEN));
    CM_FREE_PTR(passwd);

    return CM_SUCCESS;
}

int32 main(int32 argc, char *argv[])
{
    status_t ret;
    ret = dcc_parse_exc(argc, argv);
    if (ret != CM_SUCCESS) {
        CMD_PRINTF("encrypt failed\n");
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}

#ifdef __cplusplus
}
#endif