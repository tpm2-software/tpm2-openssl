/*******************************************************************************
 * Copyright 2017-2018, Fraunhofer SIT sponsored by Infineon Technologies AG
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of tpm2-tss-engine nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
#ifndef TPM2_TSS_ENGINE_H
#define TPM2_TSS_ENGINE_H

#include <openssl/core_dispatch.h>
#include <openssl/bio.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

typedef struct tpm2_provider_ctx_st TPM2_PROVIDER_CTX;

struct tpm2_provider_ctx_st {
    const OSSL_CORE_HANDLE *core;
    BIO_METHOD *corebiometh;
    ESYS_CONTEXT *esys_ctx;
};

typedef enum {
    KEY_TYPE_BLOB,
    KEY_TYPE_HANDLE
} KEY_TYPE;

typedef struct {
    int emptyAuth;
    TPM2B_DIGEST userauth;
    TPM2B_PUBLIC pub;
    TPM2_HANDLE parent;
    KEY_TYPE privatetype;
    union {
      TPM2B_PRIVATE priv;
      TPM2_HANDLE handle;
    };
} TPM2_DATA;

enum {
    TPM2TSS_R_GENERAL_FAILURE = 0,
    ERR_R_MALLOC_FAILURE,
    TPM2TSS_R_UNKNOWN_ALG,
    TPM2TSS_R_OWNER_AUTH_FAILED,
    TPM2TSS_R_TPM2DATA_READ_FAILED,
    TPM2TSS_R_DATA_CORRUPTED,
    TPM2TSS_R_CANNOT_MAKE_KEY
};


int
init_core_func_from_dispatch(const OSSL_DISPATCH *fns);

void
tpm2_new_error(const OSSL_CORE_HANDLE *handle,
               uint32_t reason, const char *fmt, ...);

void
tpm2_new_error_rc(const OSSL_CORE_HANDLE *handle,
                  uint32_t reason, TSS2_RC rc);

void
tpm2_set_error_debug(const OSSL_CORE_HANDLE *handle,
                     const char *file, int line, const char *func);

#define TPM2_ERROR_raise(ctx, reason) TPM2_ERROR_raise_text(ctx, reason, NULL)

#define TPM2_ERROR_raise_text(ctx, reason, ...) \
    (tpm2_new_error((ctx)->core, (reason), __VA_ARGS__), \
     TPM2_ERROR_set_debug(ctx))

#define TPM2_CHECK_RC(ctx, reason, rc, command) \
    if (rc) { \
        tpm2_new_error_rc((ctx)->core, (reason), (rc)); \
        TPM2_ERROR_set_debug(ctx); \
        command; \
    }

#ifdef NDEBUG
#define DBG(...) ((void) 0)
#define TPM2_ERROR_set_debug(ctx) ((void) 0)
#else
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#define TPM2_ERROR_set_debug(ctx) tpm2_set_error_debug((ctx)->core, OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC)
#endif

BIO_METHOD *
bio_prov_init_bio_method(void);

BIO *
bio_new_from_core_bio(const BIO_METHOD *corebiometh, OSSL_CORE_BIO *corebio);

#endif /* TPM2_TSS_ENGINE_H */
