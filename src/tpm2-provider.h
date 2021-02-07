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
    TPM2_ERR_MEMORY_FAILURE = 1,
    TPM2_ERR_AUTHORIZATION_FAILURE,
    TPM2_ERR_UNKNOWN_ALGORITHM,
    TPM2_ERR_INPUT_CORRUPTED,
    TPM2_ERR_CANNOT_CONNECT,
    TPM2_ERR_CANNOT_GET_CAPABILITY,
    TPM2_ERR_CANNOT_GET_RANDOM,
    TPM2_ERR_CANNOT_LOAD_PARENT,
    TPM2_ERR_CANNOT_CREATE_PRIMARY,
    TPM2_ERR_CANNOT_CREATE_KEY,
    TPM2_ERR_CANNOT_LOAD_KEY,
    TPM2_ERR_CANNOT_HASH,
    TPM2_ERR_CANNOT_SIGN,
    TPM2_ERR_CANNOT_ENCRYPT,
    TPM2_ERR_CANNOT_DECRYPT
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

void
tpm2_list_params(const char *text, const OSSL_PARAM params[]);

#define TPM2_ERROR_raise(core, reason) TPM2_ERROR_raise_text(core, reason, NULL)

#define TPM2_ERROR_raise_text(core, reason, ...) \
    (tpm2_new_error((core), (reason), __VA_ARGS__), \
     TPM2_ERROR_set_debug(core))

#define TPM2_CHECK_RC(core, rc, reason, command) \
    if ((rc)) { \
        tpm2_new_error_rc((core), (reason), (rc)); \
        TPM2_ERROR_set_debug(core); \
        command; \
    }

#ifdef NDEBUG
#define DBG(...) ((void) 0)
#define TRACE_PARAMS(...) ((void) 0)
#define TPM2_ERROR_set_debug(core) ((void) 0)
#else
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#define TRACE_PARAMS(text, params) tpm2_list_params((text), (params))
#define TPM2_ERROR_set_debug(core) tpm2_set_error_debug((core), OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC)
#endif

BIO_METHOD *
bio_prov_init_bio_method(void);

#endif /* TPM2_PROVIDER_H */
