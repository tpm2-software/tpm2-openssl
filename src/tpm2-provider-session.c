/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#include "tpm2-provider-session.h"

void
tpm2_session_init(TPM2_SESSION *session)
{
    session->handle       = ESYS_TR_NONE;
    session->tpmkey       = ESYS_TR_NONE;
    session->bindkey      = ESYS_TR_NONE;
    session->tpmkey_flush = 0;
    session->bindkey_flush = 0;
    session->tpmkey_uri   = NULL;
    session->bind_uri     = NULL;
}

/* Read entire file contents into a newly allocated buffer. */
static int
read_file_contents(BIO *bio, uint8_t **buffer)
{
    int size = 1024;
    int len  = 0;

    if ((*buffer = OPENSSL_malloc(size)) == NULL)
        return -1;

    do {
        int res;

        if (size - len < 64) {
            uint8_t *newbuf;
            size += 1024;
            if ((newbuf = OPENSSL_realloc(*buffer, size)) == NULL)
                goto error;
            *buffer = newbuf;
        }
        res = BIO_read(bio, *buffer + len, size - len);
        if (res < 0)
            goto error;
        len += res;
    } while (!BIO_eof(bio));

    return len;
error:
    OPENSSL_free(*buffer);
    return -1;
}

/*
 * Load a key from a URI into an ESYS_TR handle.
 *
 * On success sets *object and *needs_flush and returns 1.
 * *needs_flush == 1 means Esys_FlushContext() must be used to unload the key;
 * *needs_flush == 0 means Esys_TR_Close() is sufficient.
 */
static int
tpm2_session_load_key(const OSSL_CORE_HANDLE *core,
                      tpm2_semaphore_t esys_lock,
                      ESYS_CONTEXT *esys_ctx,
                      const TPM2_CAPABILITY *capability,
                      const char *uri,
                      ESYS_TR *object,
                      int *needs_flush)
{
    TSS2_RC r;

    *needs_flush = 0;
    *object = ESYS_TR_NONE;

    /* ------------------------------------------------------------------ */
    /* handle:0xNNNNNNNN  – reference to a persistent / transient handle  */
    /* ------------------------------------------------------------------ */
    if (!strncmp(uri, "handle:", 7)) {
        unsigned long int value;
        char *end_ptr = NULL;

        value = strtoul(uri + 7, &end_ptr, 16);
        if (*end_ptr != '\0' || value > UINT32_MAX) {
            TPM2_ERROR_raise(core, TPM2_ERR_INPUT_CORRUPTED);
            return 0;
        }

        if (!tpm2_semaphore_lock(esys_lock))
            return 0;
        r = Esys_TR_FromTPMPublic(esys_ctx, (TPM2_HANDLE)value,
                                  ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                  object);
        tpm2_semaphore_unlock(esys_lock);
        TPM2_CHECK_RC(core, r, TPM2_ERR_CANNOT_LOAD_KEY, return 0);

        *needs_flush = 0;
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* object:FILE  – serialised ESYS_TR context (Esys_TR_Serialize)      */
    /* ------------------------------------------------------------------ */
    if (!strncmp(uri, "object:", 7)) {
        BIO     *bio;
        uint8_t *buffer = NULL;
        int      buffer_size;

        if ((bio = BIO_new_file(uri + 7, "rb")) == NULL) {
            TPM2_ERROR_raise(core, TPM2_ERR_CANNOT_LOAD_KEY);
            return 0;
        }
        buffer_size = read_file_contents(bio, &buffer);
        BIO_free(bio);
        if (buffer_size < 0) {
            TPM2_ERROR_raise(core, TPM2_ERR_CANNOT_LOAD_KEY);
            return 0;
        }

        if (!tpm2_semaphore_lock(esys_lock)) {
            OPENSSL_free(buffer);
            return 0;
        }
        r = Esys_TR_Deserialize(esys_ctx, buffer, buffer_size, object);
        tpm2_semaphore_unlock(esys_lock);
        OPENSSL_free(buffer);
        TPM2_CHECK_RC(core, r, TPM2_ERR_CANNOT_LOAD_KEY, return 0);

        *needs_flush = 0;
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* FILE  – TSS2 PEM private-key file                                  */
    /* ------------------------------------------------------------------ */
    {
        TPM2_KEYDATA keydata = {0};
        ESYS_TR      parent = ESYS_TR_NONE;
        TPM2B_DIGEST parent_auth = { .size = 0 };
        BIO         *bio;

        if ((bio = BIO_new_file(uri, "rb")) == NULL) {
            TPM2_ERROR_raise(core, TPM2_ERR_CANNOT_LOAD_KEY);
            return 0;
        }
        if (!tpm2_keydata_read(bio, &keydata, KEY_FORMAT_PEM)) {
            BIO_free(bio);
            TPM2_ERROR_raise(core, TPM2_ERR_INPUT_CORRUPTED);
            return 0;
        }
        BIO_free(bio);

        if (keydata.privatetype == KEY_TYPE_HANDLE) {
            /* Persistent handle recorded in the PEM file. */
            if (!tpm2_semaphore_lock(esys_lock))
                return 0;
            r = Esys_TR_FromTPMPublic(esys_ctx, keydata.handle,
                                      ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                      object);
            tpm2_semaphore_unlock(esys_lock);
            TPM2_CHECK_RC(core, r, TPM2_ERR_CANNOT_LOAD_KEY, return 0);
            *needs_flush = 0;
        } else if (keydata.privatetype == KEY_TYPE_BLOB) {
            /* Key blob: must be loaded under its parent. */
            if (keydata.parent && keydata.parent != TPM2_RH_OWNER) {
                DBG("SESSION LOAD parent: persistent 0x%x\n", keydata.parent);
                if (!tpm2_load_parent(core, esys_lock, esys_ctx,
                                      keydata.parent, &parent_auth, &parent))
                    return 0;
            } else {
                DBG("SESSION LOAD parent: primary 0x%x\n", TPM2_RH_OWNER);
                if (!tpm2_build_primary(core, esys_lock, esys_ctx,
                                        capability->algorithms,
                                        ESYS_TR_RH_OWNER, &parent_auth, &parent))
                    return 0;
            }

            if (!tpm2_semaphore_lock(esys_lock)) {
                tpm2_esys_flush_context(esys_lock, esys_ctx, parent);
                return 0;
            }
            r = Esys_Load(esys_ctx, parent,
                          ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                          &keydata.priv, &keydata.pub, object);

            /* Clean up parent regardless of Esys_Load result. */
            if (keydata.parent && keydata.parent != TPM2_RH_OWNER)
                Esys_TR_Close(esys_ctx, &parent);
            else
                Esys_FlushContext(esys_ctx, parent);

            tpm2_semaphore_unlock(esys_lock);
            TPM2_CHECK_RC(core, r, TPM2_ERR_CANNOT_LOAD_KEY, return 0);
            *needs_flush = 1; /* transient: must FlushContext */
        } else {
            TPM2_ERROR_raise(core, TPM2_ERR_INPUT_CORRUPTED);
            return 0;
        }
    }

    return 1;
}

int
tpm2_session_start(const OSSL_CORE_HANDLE *core,
                   tpm2_semaphore_t esys_lock,
                   ESYS_CONTEXT *esys_ctx,
                   const TPM2_CAPABILITY *capability,
                   TPM2_SESSION *session)
{
    static const TPMT_SYM_DEF symDef = {
        .algorithm   = TPM2_ALG_AES,
        .keyBits.aes = 128,
        .mode.aes    = TPM2_ALG_CFB
    };
    const char *bind_auth_str;
    TSS2_RC r;

    /* End any pre-existing session before starting a fresh one. */
    if (session->handle != ESYS_TR_NONE)
        tpm2_session_end(esys_lock, esys_ctx, session);

    /* Nothing to do if no session URIs are configured. */
    if (!session->tpmkey_uri && !session->bind_uri)
        return 1;

    DBG("SESSION START tpmkey=%s bind=%s\n",
        session->tpmkey_uri ? session->tpmkey_uri : "(none)",
        session->bind_uri   ? session->bind_uri   : "(none)");

    /* Load tpmkey (salt-encryption key) if a URI was provided. */
    if (session->tpmkey_uri) {
        if (!tpm2_session_load_key(core, esys_lock, esys_ctx, capability,
                                   session->tpmkey_uri,
                                   &session->tpmkey, &session->tpmkey_flush))
            goto error;
    }

    /* Load bind key if a URI was provided. */
    if (session->bind_uri) {
        if (!tpm2_session_load_key(core, esys_lock, esys_ctx, capability,
                                   session->bind_uri,
                                   &session->bindkey, &session->bindkey_flush))
            goto error;

        /* Provide bind-key auth from environment (like TPM2OPENSSL_PARENT_AUTH). */
        bind_auth_str = getenv("TPM2OPENSSL_SESSION_BIND_AUTH");
        if (bind_auth_str) {
            TPM2B_DIGEST auth = { .size = 0 };
            size_t auth_len = strlen(bind_auth_str);

            if (auth_len > sizeof(auth.buffer)) {
                TPM2_ERROR_raise(core, TPM2_ERR_WRONG_DATA_LENGTH);
                goto error;
            }
            auth.size = (UINT16)auth_len;
            memcpy(auth.buffer, bind_auth_str, auth_len);

            if (!tpm2_semaphore_lock(esys_lock))
                goto error;
            r = Esys_TR_SetAuth(esys_ctx, session->bindkey, &auth);
            tpm2_semaphore_unlock(esys_lock);
            TPM2_CHECK_RC(core, r, TPM2_ERR_AUTHORIZATION_FAILURE, goto error);
        }
    }

    /* Start the HMAC session. */
    if (!tpm2_semaphore_lock(esys_lock))
        goto error;
    r = Esys_StartAuthSession(esys_ctx,
                              session->tpmkey,
                              session->bindkey,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC,
                              &symDef,
                              TPM2_ALG_SHA256,
                              &session->handle);
    if (!r) {
        TPMA_SESSION attrs = TPMA_SESSION_CONTINUESESSION |
                             TPMA_SESSION_DECRYPT |
                             TPMA_SESSION_ENCRYPT;
        r = Esys_TRSess_SetAttributes(esys_ctx, session->handle, attrs, 0xFF);
    }
    tpm2_semaphore_unlock(esys_lock);
    TPM2_CHECK_RC(core, r, TPM2_ERR_CANNOT_CONNECT, goto error);

    DBG("SESSION STARTED handle=0x%x\n", session->handle);
    return 1;

error:
    tpm2_session_end(esys_lock, esys_ctx, session);
    return 0;
}

void
tpm2_session_end(tpm2_semaphore_t esys_lock,
                 ESYS_CONTEXT *esys_ctx,
                 TPM2_SESSION *session)
{
    if (session->handle != ESYS_TR_NONE) {
        tpm2_esys_flush_context(esys_lock, esys_ctx, session->handle);
        session->handle = ESYS_TR_NONE;
    }
    if (session->tpmkey != ESYS_TR_NONE) {
        if (session->tpmkey_flush)
            tpm2_esys_flush_context(esys_lock, esys_ctx, session->tpmkey);
        else
            tpm2_esys_tr_close(esys_lock, esys_ctx, &session->tpmkey);
        session->tpmkey = ESYS_TR_NONE;
    }
    if (session->bindkey != ESYS_TR_NONE) {
        if (session->bindkey_flush)
            tpm2_esys_flush_context(esys_lock, esys_ctx, session->bindkey);
        else
            tpm2_esys_tr_close(esys_lock, esys_ctx, &session->bindkey);
        session->bindkey = ESYS_TR_NONE;
    }
}

void
tpm2_session_free(TPM2_SESSION *session)
{
    OPENSSL_free(session->tpmkey_uri);
    OPENSSL_free(session->bind_uri);
    session->tpmkey_uri = NULL;
    session->bind_uri   = NULL;
}

ESYS_TR
tpm2_session_handle(const TPM2_SESSION *session)
{
    return (session->handle != ESYS_TR_NONE) ? session->handle
                                             : ESYS_TR_PASSWORD;
}

int
tpm2_session_parse_propq(const char *propq, TPM2_SESSION *session)
{
    const char *p;
    const char *end;
    size_t      len;

    if (!propq)
        return 1;

    p = strstr(propq, "tpm2.session-tpmkey=");
    if (p) {
        p  += strlen("tpm2.session-tpmkey=");
        end = strchr(p, ',');
        len = end ? (size_t)(end - p) : strlen(p);
        OPENSSL_free(session->tpmkey_uri);
        if ((session->tpmkey_uri = OPENSSL_strndup(p, len)) == NULL)
            return 0;
    }

    p = strstr(propq, "tpm2.session-bind=");
    if (p) {
        p  += strlen("tpm2.session-bind=");
        end = strchr(p, ',');
        len = end ? (size_t)(end - p) : strlen(p);
        OPENSSL_free(session->bind_uri);
        if ((session->bind_uri = OPENSSL_strndup(p, len)) == NULL)
            return 0;
    }

    return 1;
}

int
tpm2_session_set_params(const OSSL_CORE_HANDLE *core,
                        const OSSL_PARAM params[],
                        TPM2_SESSION *session)
{
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_SESSION_TPMKEY);
    if (p != NULL) {
        char *value = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &value, 0))
            return 0;
        OPENSSL_free(session->tpmkey_uri);
        session->tpmkey_uri = value;
    }

    p = OSSL_PARAM_locate_const(params, TPM2_PKEY_PARAM_SESSION_BIND);
    if (p != NULL) {
        char *value = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &value, 0))
            return 0;
        OPENSSL_free(session->bind_uri);
        session->bind_uri = value;
    }

    return 1;
}
