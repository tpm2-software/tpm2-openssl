/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_H
#define TPM2_PROVIDER_H

#include <openssl/core_dispatch.h>
#include <openssl/bio.h>

#include <tss2/tss2_esys.h>

#define TPM2_PKEY_PARAM_PARENT      "parent"
#define TPM2_PKEY_PARAM_PARENT_AUTH "parent-auth"
#define TPM2_PKEY_PARAM_USER_AUTH   "user-auth"

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

/* serializable key data */
typedef struct {
    int emptyAuth;
    TPM2_HANDLE parent;
    TPM2B_PUBLIC pub;
    KEY_TYPE privatetype;
    union {
      TPM2B_PRIVATE priv;
      TPM2_HANDLE handle;
    };
} TPM2_KEYDATA;

/* key object */
typedef struct {
    TPM2_KEYDATA data;
    TPM2B_DIGEST userauth;
    const OSSL_CORE_HANDLE *core;
    ESYS_CONTEXT *esys_ctx;
    ESYS_TR object;
} TPM2_PKEY;

enum {
    TPM2TSS_R_GENERAL_FAILURE = 1,
    TPM2TSS_R_MALLOC_FAILURE,
    TPM2TSS_R_UNKNOWN_ALG,
    TPM2TSS_R_OWNER_AUTH_FAILED,
    TPM2TSS_R_TPM2DATA_READ_FAILED,
    TPM2TSS_R_DATA_CORRUPTED,
    TPM2TSS_R_CANNOT_MAKE_KEY
};

int
init_core_func_from_dispatch(const OSSL_DISPATCH *fns);

int
tpm2_core_get_params(const OSSL_CORE_HANDLE *prov, OSSL_PARAM params[]);

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

#define TPM2_CHECK_RC(ctx, rc, reason, command) \
    if ((rc)) { \
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

#endif /* TPM2_PROVIDER_H */
