/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_SESSION_H
#define TPM2_PROVIDER_SESSION_H

#include <openssl/params.h>

#include "tpm2-provider-pkey.h"

/*
 * TPM2_SESSION encapsulates a single HMAC session created via
 * Esys_StartAuthSession().  The tpmkey and bind key are specified as URI
 * strings; the actual ESYS_TR handles are populated when
 * tpm2_session_start() is called.
 *
 * URI formats accepted:
 *   handle:0xNNNNNNNN   – persistent / transient TPM handle
 *   object:FILE          – serialised ESYS_TR context (Esys_TR_Serialize)
 *   FILE                 – TSS2 PEM private-key file
 *
 * Bind-key authentication is taken from the environment variable
 * TPM2OPENSSL_SESSION_BIND_AUTH (analogous to TPM2OPENSSL_PARENT_AUTH).
 */
typedef struct {
    ESYS_TR handle;         /* session handle; ESYS_TR_NONE when not started */
    ESYS_TR tpmkey;         /* loaded tpmkey handle (for salt encryption) */
    ESYS_TR bindkey;        /* loaded bind-key handle */
    int     tpmkey_flush;   /* 1 = FlushContext, 0 = TR_Close */
    int     bindkey_flush;  /* 1 = FlushContext, 0 = TR_Close */
    char   *tpmkey_uri;     /* strdup'd URI for tpmkey, or NULL */
    char   *bind_uri;       /* strdup'd URI for bind key, or NULL */
} TPM2_SESSION;

/* Initialise a TPM2_SESSION to safe defaults (all handles = ESYS_TR_NONE). */
void
tpm2_session_init(TPM2_SESSION *session);

/*
 * Start an HMAC session using the URIs stored in *session.
 * If neither URI is set this is a no-op and returns 1.
 * If a session is already active it is ended before a new one is created.
 * Returns 1 on success, 0 on failure (TPM error already raised).
 */
int
tpm2_session_start(const OSSL_CORE_HANDLE *core,
                   tpm2_semaphore_t esys_lock,
                   ESYS_CONTEXT *esys_ctx,
                   const TPM2_CAPABILITY *capability,
                   TPM2_SESSION *session);

/*
 * Flush the session and unload any keys loaded by tpm2_session_start().
 * Safe to call when handle == ESYS_TR_NONE.
 */
void
tpm2_session_end(tpm2_semaphore_t esys_lock,
                 ESYS_CONTEXT *esys_ctx,
                 TPM2_SESSION *session);

/* Free URI strings; does NOT flush TPM handles (call tpm2_session_end first). */
void
tpm2_session_free(TPM2_SESSION *session);

/*
 * Return the session handle to pass as shandle1 to Esys_ operations.
 * Returns session->handle when a session is active, ESYS_TR_PASSWORD otherwise.
 */
ESYS_TR
tpm2_session_handle(const TPM2_SESSION *session);

/*
 * Parse "tpm2.session-tpmkey=VALUE" and/or "tpm2.session-bind=VALUE" from
 * a property-query string.  The extracted values are strdup'd into *session.
 * Returns 1 on success (even if no session params are found), 0 on alloc failure.
 */
int
tpm2_session_parse_propq(const char *propq, TPM2_SESSION *session);

/*
 * Extract TPM2_PKEY_PARAM_SESSION_TPMKEY and TPM2_PKEY_PARAM_SESSION_BIND
 * from an OSSL_PARAM array and store them in *session.
 * Returns 1 on success, 0 on error.
 */
int
tpm2_session_set_params(const OSSL_CORE_HANDLE *core,
                        const OSSL_PARAM params[],
                        TPM2_SESSION *session);

#endif /* TPM2_PROVIDER_SESSION_H */
