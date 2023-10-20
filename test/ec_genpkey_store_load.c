/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/ui.h>

int generate_and_save(const char *filename, const char *password)
{
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *out = NULL;
    int ret = 1;

    if (!(pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=tpm2")))
        goto error;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    params[1] = OSSL_PARAM_construct_utf8_string("user-auth", (char *)password, 0);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(pctx) <= 0
            || EVP_PKEY_CTX_set_params(pctx, params) <= 0
            || EVP_PKEY_generate(pctx, &pkey) <= 0)
        goto error;

    // save the TPM2-protected private key as the "TSS2 PRIVATE KEY"
    if ((out = BIO_new_file(filename, "w")) == NULL
            || !PEM_write_bio_PrivateKey(out, pkey, 0, NULL, 0, 0, NULL))
        goto error;

    ret = 0;
error:
    BIO_free_all(out);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int provide_password(char *buf, int size, int rwflag, void *u)
{
    const char *password = (char *)u;

    size_t len = strlen(password);
    if (len > size)
        len = size;

    memcpy(buf, password, len);
    return len;
}

int sign_message(EVP_PKEY *pkey)
{
    EVP_MD_CTX *sctx = NULL;
    EVP_MD_CTX *vctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int ret = 1;

    const char* message = "Sabai Sabai";

    // sign
    if (!(sctx = EVP_MD_CTX_new()))
        goto error;

    if (!EVP_DigestSignInit_ex(sctx, NULL, "SHA-256", NULL, "provider=tpm2", pkey, NULL)
            || !EVP_DigestSign(sctx, NULL, &sig_len, message, strlen(message)))
        goto error;

    if (!(sig = OPENSSL_malloc(sig_len)))
        goto error;

    if (!EVP_DigestSign(sctx, sig, &sig_len, message, strlen(message)))
        goto error;

    // verify
    if (!(vctx = EVP_MD_CTX_new()))
        goto error;

    if (!EVP_DigestVerifyInit_ex(vctx, NULL, "SHA-256", NULL, "provider=tpm2", pkey, NULL)
            || EVP_DigestVerify(vctx, sig, sig_len, message, strlen(message)) != 1)
        goto error;

    ret = 0;
error:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(vctx);
    EVP_MD_CTX_free(sctx);
    return ret;
}

int load_and_sign(const char *filename, const char *password)
{
    OSSL_STORE_CTX *ctx;
    UI_METHOD *ui_method = NULL;
    int ret = 1;

    if (!(ui_method = UI_UTIL_wrap_read_pem_callback(provide_password, 0)))
        goto error;

    if (ctx = OSSL_STORE_open(filename, ui_method, (void *)password, NULL, NULL)) {
        while (OSSL_STORE_eof(ctx) == 0) {
            OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
            if (info && OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
                EVP_PKEY *pkey;

                if ((pkey = OSSL_STORE_INFO_get0_PKEY(info)))
                    ret = sign_message(pkey);
                OSSL_STORE_INFO_free(info);
            }
        }
    }

error:
    OSSL_STORE_close(ctx);
    UI_destroy_method(ui_method);
    return ret;
}

#define TEST_FILENAME "ec_genpkey_store_load.pem"
#define TEST_PASSWORD "secret"

int main()
{
    OSSL_PROVIDER *defprov = NULL, *tpm2prov = NULL;
    int ret = 1;

    if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL)
        goto error;

    if ((tpm2prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
        goto error;

    if (generate_and_save(TEST_FILENAME, TEST_PASSWORD)
            || load_and_sign(TEST_FILENAME, TEST_PASSWORD))
        goto error;

    ret = 0;
error:
    ERR_print_errors_fp(stderr);

    remove(TEST_FILENAME);
    OSSL_PROVIDER_unload(tpm2prov);
    OSSL_PROVIDER_unload(defprov);
    return ret;
}
