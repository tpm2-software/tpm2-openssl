/* SPDX-License-Identifier: BSD-3-Clause */

/* Partially based on openssl/providers/common/bio_prov.c */

#ifdef WITH_TSS2_RC
#include <tss2/tss2_rc.h>
#endif
#include "tpm2-provider.h"

static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

static OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;

int
init_core_func_from_dispatch(const OSSL_DISPATCH *fns)
{
    for (; fns->function_id != 0; fns++) {
        switch (fns->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            if (c_gettable_params == NULL)
                c_gettable_params = OSSL_FUNC_core_gettable_params(fns);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            if (c_get_params == NULL)
                c_get_params = OSSL_FUNC_core_get_params(fns);
            break;

        case OSSL_FUNC_CORE_NEW_ERROR:
            if (c_new_error == NULL)
                c_new_error = OSSL_FUNC_core_new_error(fns);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            if (c_set_error_debug == NULL)
                c_set_error_debug = OSSL_FUNC_core_set_error_debug(fns);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            if (c_vset_error == NULL)
                c_vset_error = OSSL_FUNC_core_vset_error(fns);
            break;
        }
    }

    return 1;
}

int
tpm2_core_get_params(const OSSL_CORE_HANDLE *prov, OSSL_PARAM params[])
{
    if (c_get_params == NULL)
        return 1;
    return c_get_params(prov, params);
}

void
tpm2_new_error(const OSSL_CORE_HANDLE *handle,
               uint32_t reason, const char *fmt, ...)
{
    if (c_new_error != NULL && c_vset_error != NULL) {
        va_list args;

        va_start(args, fmt);
        c_new_error(handle);
        c_vset_error(handle, reason, fmt, args);
        va_end(args);
    }
}

void
tpm2_new_error_rc(const OSSL_CORE_HANDLE *handle,
                  uint32_t reason, TSS2_RC rc)
{
#ifdef WITH_TSS2_RC
    tpm2_new_error(handle, reason, "%i %s", rc, Tss2_RC_Decode(rc));
#else
    tpm2_new_error(handle, reason, "%i", rc);
#endif
}

void
tpm2_set_error_debug(const OSSL_CORE_HANDLE *handle,
                     const char *file, int line, const char *func)
{
    if (c_set_error_debug != NULL)
        c_set_error_debug(handle, file, line, func);
}

void
tpm2_list_params(const char *text, const OSSL_PARAM params[])
{
    fprintf(stderr, "%s [", text);

    while (params->key != NULL) {
        fprintf(stderr, " %s", params->key);
        params++;
    }

    fprintf(stderr, " ]\n");
}

TSS2_RC
tpm2_esys_tr_close(tpm2_semaphore_t esys_lock, ESYS_CONTEXT *esys_ctx, ESYS_TR *object)
{
    TSS2_RC r;

    if (!tpm2_semaphore_lock(esys_lock))
        return TSS2_ESYS_RC_GENERAL_FAILURE;

    r = Esys_TR_Close(esys_ctx, object);

    tpm2_semaphore_unlock(esys_lock);
    return r;
}

TSS2_RC
tpm2_esys_flush_context(tpm2_semaphore_t esys_lock, ESYS_CONTEXT *esys_ctx, ESYS_TR flush_handle)
{
    TSS2_RC r;

    if (!tpm2_semaphore_lock(esys_lock))
        return TSS2_ESYS_RC_GENERAL_FAILURE;

    r = Esys_FlushContext(esys_ctx, flush_handle);

    tpm2_semaphore_unlock(esys_lock);
    return r;
}

int
tpm2_supports_algorithm(const TPMS_CAPABILITY_DATA *caps, TPM2_ALG_ID algorithm)
{
    UINT32 index;

    for (index = 0; index < caps->data.algorithms.count; index++) {
        if (caps->data.algorithms.algProperties[index].alg == algorithm)
            return 1;
    }

    return 0;
}

int
tpm2_supports_command(const TPMS_CAPABILITY_DATA *caps, TPM2_CC command)
{
    UINT32 index;

    for (index = 0; index < caps->data.command.count; index++) {
        if ((caps->data.command.commandAttributes[index] & TPMA_CC_COMMANDINDEX_MASK) == command)
            return 1;
    }

    return 0;
}

uint16_t
tpm2_max_nvindex_buffer(const TPMS_CAPABILITY_DATA *caps)
{
    UINT32 index;
    uint16_t max_nv_size = TPM2_MAX_NV_BUFFER_SIZE;

    for (index = 0; index < caps->data.tpmProperties.count; index++) {
        if (caps->data.tpmProperties.tpmProperty[index].property == TPM2_PT_NV_BUFFER_MAX)
            return caps->data.tpmProperties.tpmProperty[index].value;
    }

    return max_nv_size;
}

int
tpm2_create_salt_key(ESYS_CONTEXT *esys_ctx,
                     const TPMS_CAPABILITY_DATA *algorithms,
                     ESYS_TR *salt_key)
{
    TSS2_RC r;
    TPM2B_PUBLIC inPublic = { 0 };
    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = { .size = 0 },
            .data = { .size = 0 },
        },
    };
    TPM2B_DATA outsideInfo = { .size = 0 };
    TPML_PCR_SELECTION creationPCR = { .count = 0 };
    ESYS_TR objectHandle = ESYS_TR_NONE;

    inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
    inPublic.publicArea.objectAttributes =
        TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_DECRYPT |
        TPMA_OBJECT_NODA | TPMA_OBJECT_USERWITHAUTH;

    if (tpm2_supports_algorithm(algorithms, TPM2_ALG_ECC)) {
        inPublic.publicArea.type = TPM2_ALG_ECC;
        inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDH;
        inPublic.publicArea.parameters.eccDetail.scheme.details.ecdh.hashAlg = TPM2_ALG_SHA256;
        inPublic.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        inPublic.publicArea.unique.ecc.x.size = 0;
        inPublic.publicArea.unique.ecc.y.size = 0;
    } else {
        inPublic.publicArea.type = TPM2_ALG_RSA;
        inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_OAEP;
        inPublic.publicArea.parameters.rsaDetail.scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;
        inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic.publicArea.unique.rsa.size = 0;
    }

    r = Esys_CreatePrimary(esys_ctx,
                           ESYS_TR_RH_NULL,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitive, &inPublic,
                           &outsideInfo, &creationPCR,
                           &objectHandle,
                           NULL, NULL, NULL, NULL);
    if (r != TSS2_RC_SUCCESS) {
        *salt_key = ESYS_TR_NONE;
        return 0;
    }

    *salt_key = objectHandle;
    return 1;
}

int
tpm2_start_auth_session(ESYS_CONTEXT *esys_ctx, ESYS_TR salt_key,
                        ESYS_TR *session)
{
    TSS2_RC r;
    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = { .aes = TPM2_ALG_CFB },
    };

    r = Esys_StartAuthSession(esys_ctx,
                              salt_key,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC,
                              &symmetric,
                              TPM2_ALG_SHA256,
                              session);
    if (r != TSS2_RC_SUCCESS) {
        *session = ESYS_TR_NONE;
        return 0;
    }

    r = Esys_TRSess_SetAttributes(esys_ctx, *session,
                                  TPMA_SESSION_DECRYPT |
                                  TPMA_SESSION_ENCRYPT |
                                  TPMA_SESSION_CONTINUESESSION,
                                  TPMA_SESSION_DECRYPT |
                                  TPMA_SESSION_ENCRYPT |
                                  TPMA_SESSION_CONTINUESESSION);
    if (r != TSS2_RC_SUCCESS) {
        Esys_FlushContext(esys_ctx, *session);
        *session = ESYS_TR_NONE;
        return 0;
    }

    return 1;
}

void
tpm2_end_auth_session(ESYS_CONTEXT *esys_ctx, ESYS_TR *session)
{
    if (*session != ESYS_TR_NONE) {
        Esys_FlushContext(esys_ctx, *session);
        *session = ESYS_TR_NONE;
    }
}
