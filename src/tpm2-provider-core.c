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

static OSSL_FUNC_BIO_read_ex_fn *c_bio_read_ex = NULL;
static OSSL_FUNC_BIO_write_ex_fn *c_bio_write_ex = NULL;
static OSSL_FUNC_BIO_gets_fn *c_bio_gets = NULL;
static OSSL_FUNC_BIO_puts_fn *c_bio_puts = NULL;
static OSSL_FUNC_BIO_up_ref_fn *c_bio_up_ref = NULL;
static OSSL_FUNC_BIO_free_fn *c_bio_free = NULL;
static OSSL_FUNC_BIO_ctrl_fn *c_bio_ctrl = NULL;

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

        case OSSL_FUNC_BIO_READ_EX:
            if (c_bio_read_ex == NULL)
                c_bio_read_ex = OSSL_FUNC_BIO_read_ex(fns);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            if (c_bio_write_ex == NULL)
                c_bio_write_ex = OSSL_FUNC_BIO_write_ex(fns);
            break;
        case OSSL_FUNC_BIO_GETS:
            if (c_bio_gets == NULL)
                c_bio_gets = OSSL_FUNC_BIO_gets(fns);
            break;
        case OSSL_FUNC_BIO_PUTS:
            if (c_bio_puts == NULL)
                c_bio_puts = OSSL_FUNC_BIO_puts(fns);
            break;
        case OSSL_FUNC_BIO_UP_REF:
            if (c_bio_up_ref == NULL)
                c_bio_up_ref = OSSL_FUNC_BIO_up_ref(fns);
            break;
        case OSSL_FUNC_BIO_FREE:
            if (c_bio_free == NULL)
                c_bio_free = OSSL_FUNC_BIO_free(fns);
            break;
        case OSSL_FUNC_BIO_CTRL:
            if (c_bio_ctrl == NULL)
                c_bio_ctrl = OSSL_FUNC_BIO_ctrl(fns);
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

BIO *
bio_new_from_core_bio(const BIO_METHOD *corebiometh, OSSL_CORE_BIO *corebio)
{
    BIO *outbio = NULL;

    if (corebiometh == NULL || c_bio_up_ref == NULL)
        return NULL;

    if ((outbio = BIO_new(corebiometh)) != NULL) {
        c_bio_up_ref(corebio);
        BIO_set_data(outbio, corebio);
    }

    return outbio;
}

static int
bio_core_read_ex(BIO *bio, char *data, size_t data_len,
                 size_t *bytes_read)
{
    if (c_bio_read_ex == NULL)
        return 0;
    return c_bio_read_ex(BIO_get_data(bio), data, data_len, bytes_read);
}

static int
bio_core_write_ex(BIO *bio, const char *data, size_t data_len,
                  size_t *written)
{
    if (c_bio_write_ex == NULL)
        return 0;
    return c_bio_write_ex(BIO_get_data(bio), data, data_len, written);
}

static int
bio_core_gets(BIO *bio, char *buf, int size)
{
    if (c_bio_gets == NULL)
        return -1;
    return c_bio_gets(BIO_get_data(bio), buf, size);
}

static int
bio_core_puts(BIO *bio, const char *str)
{
    if (c_bio_puts == NULL)
        return -1;
    return c_bio_puts(BIO_get_data(bio), str);
}

static long
bio_core_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    if (c_bio_ctrl == NULL)
        return -1;
    return c_bio_ctrl(BIO_get_data(bio), cmd, num, ptr);
}

static int
bio_core_new(BIO *bio)
{
    BIO_set_init(bio, 1);

    return 1;
}

static int
bio_core_free(BIO *bio)
{
    BIO_set_init(bio, 0);
    if (c_bio_free != NULL)
        c_bio_free(BIO_get_data(bio));

    return 1;
}

BIO_METHOD *
bio_prov_init_bio_method(void)
{
    BIO_METHOD *corebiometh = NULL;

    corebiometh = BIO_meth_new(BIO_TYPE_CORE_TO_PROV, "BIO to Core filter");
    if (corebiometh == NULL
            || !BIO_meth_set_write_ex(corebiometh, bio_core_write_ex)
            || !BIO_meth_set_read_ex(corebiometh, bio_core_read_ex)
            || !BIO_meth_set_puts(corebiometh, bio_core_puts)
            || !BIO_meth_set_gets(corebiometh, bio_core_gets)
            || !BIO_meth_set_ctrl(corebiometh, bio_core_ctrl)
            || !BIO_meth_set_create(corebiometh, bio_core_new)
            || !BIO_meth_set_destroy(corebiometh, bio_core_free)) {
        BIO_meth_free(corebiometh);
        return NULL;
    }

    return corebiometh;
}

