/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef TPM2_PROVIDER_H
#define TPM2_PROVIDER_H

#include <openssl/core_dispatch.h>
#include <openssl/bio.h>

#include <tss2/tss2_esys.h>

#define TPM2_MAX_OSSL_NAME 50 /* OSSL_MAX_NAME_SIZE */

#define TPM2_PKEY_PARAM_PARENT      "parent"
#define TPM2_PKEY_PARAM_PARENT_AUTH "parent-auth"
#define TPM2_PKEY_PARAM_USER_AUTH   "user-auth"

typedef struct tpm2_provider_ctx_st TPM2_PROVIDER_CTX;

typedef struct {
    TPMS_CAPABILITY_DATA *properties;
    TPMS_CAPABILITY_DATA *algorithms;
    TPMS_CAPABILITY_DATA *commands;
} TPM2_CAPABILITY;

struct tpm2_provider_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;
    ESYS_CONTEXT *esys_ctx;
    TPM2_CAPABILITY capability;
};

typedef enum {
    KEY_TYPE_NONE = 0,
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
    TPM2_CAPABILITY capability;
    ESYS_TR object;
} TPM2_PKEY;

#define TPM2_PKEY_RSA_BITS(pkey) ((pkey)->data.pub.publicArea.parameters.rsaDetail.keyBits)
#define TPM2_PKEY_RSA_SCHEME(pkey) ((pkey)->data.pub.publicArea.parameters.rsaDetail.scheme.scheme)
#define TPM2_PKEY_RSA_HASH(pkey) ((pkey)->data.pub.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg)

#define TPM2_PKEY_EC_CURVE(pkey) ((pkey)->data.pub.publicArea.parameters.eccDetail.curveID)
#define TPM2_PKEY_EC_SCHEME(pkey) ((pkey)->data.pub.publicArea.parameters.eccDetail.scheme.scheme)
#define TPM2_PKEY_EC_HASH(pkey) ((pkey)->data.pub.publicArea.parameters.eccDetail.scheme.details.anySig.hashAlg)

enum {
    TPM2_ERR_MEMORY_FAILURE = 1,
    TPM2_ERR_AUTHORIZATION_FAILURE,
    TPM2_ERR_UNKNOWN_ALGORITHM,
    TPM2_ERR_INPUT_CORRUPTED,
    TPM2_ERR_WRONG_DATA_LENGTH,
    TPM2_ERR_CANNOT_CONNECT,
    TPM2_ERR_CANNOT_GET_CAPABILITY,
    TPM2_ERR_CANNOT_GET_RANDOM,
    TPM2_ERR_CANNOT_LOAD_PARENT,
    TPM2_ERR_CANNOT_CREATE_PRIMARY,
    TPM2_ERR_CANNOT_CREATE_KEY,
    TPM2_ERR_CANNOT_LOAD_KEY,
    TPM2_ERR_CANNOT_GENERATE,
    TPM2_ERR_CANNOT_HASH,
    TPM2_ERR_CANNOT_SIGN,
    TPM2_ERR_VERIFICATION_FAILED,
    TPM2_ERR_CANNOT_ENCRYPT,
    TPM2_ERR_CANNOT_DECRYPT,
    TPM2_ERR_CANNOT_DUPLICATE
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

int
tpm2_supports_algorithm(const TPMS_CAPABILITY_DATA *caps, TPM2_ALG_ID algorithm);

int
tpm2_supports_command(const TPMS_CAPABILITY_DATA *caps, TPM2_CC command);

uint16_t
tpm2_max_nvindex_buffer(const TPMS_CAPABILITY_DATA *caps);

typedef const OSSL_DISPATCH *(tpm2_dispatch_t)(const TPM2_CAPABILITY *);

#endif /* TPM2_PROVIDER_H */
