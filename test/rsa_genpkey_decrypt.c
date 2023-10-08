/* SPDX-License-Identifier: BSD-3-Clause */

#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

int main()
{
    OSSL_PROVIDER *defprov = NULL, *tpm2prov = NULL;
    EVP_PKEY *privkey = NULL, *pubkey = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *impctx = NULL, *encctx = NULL, *decctx = NULL;

    size_t enclen, declen;
    unsigned char *encout = NULL, *decout = NULL;
    int ret = 1;

    const char* message = "Sabai Sabai";

    if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL)
        goto error;

    if ((tpm2prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
        goto error;

    /* generate a RSA-2048 key using the TPM2 */
    if (!(privkey = EVP_PKEY_Q_keygen(NULL, "provider=tpm2", "RSA", 2048)))
        goto error;

    /* export the public key */
    if (EVP_PKEY_todata(privkey, EVP_PKEY_PUBLIC_KEY, &params) != 1)
        goto error;

    /* import the public key to the default provider */
    if (!(impctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default")))
        goto error;

    if (EVP_PKEY_fromdata_init(impctx) <= 0
            || EVP_PKEY_fromdata(impctx, &pubkey, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        goto error;

    /* encode the message using the default provider */
    if (!(encctx = EVP_PKEY_CTX_new_from_pkey(NULL, pubkey, NULL)))
        goto error;

    if (EVP_PKEY_encrypt_init(encctx) != 1)
        goto error;

    /* determine length */
    if (EVP_PKEY_encrypt(encctx, NULL, &enclen, (const unsigned char *)message, strlen(message)) <= 0)
        goto error;

    if (!(encout = OPENSSL_malloc(enclen)))
        goto error;

    if (EVP_PKEY_encrypt(encctx, encout, &enclen, (const unsigned char *)message, strlen(message)) <= 0)
        goto error;

    /* decode the message using the TPM2 library context */
    if (!(decctx = EVP_PKEY_CTX_new_from_pkey(NULL, privkey, "provider=tpm2")))
        goto error;

    if (EVP_PKEY_decrypt_init(decctx) != 1)
        goto error;

    /* determine length */
    if (EVP_PKEY_decrypt(decctx, NULL, &declen, encout, enclen) <= 0)
        goto error;

    if (!(decout = OPENSSL_malloc(declen)))
        goto error;

    if (EVP_PKEY_decrypt(decctx, decout, &declen, encout, enclen) <= 0)
        goto error;

    /* check the message was decoded correctly */
    if (declen == strlen(message) && memcmp(decout, message, declen) == 0)
        ret = 0; /* success */
    else
        fprintf(stderr, "Decoding failed");

error:
    ERR_print_errors_fp(stderr);

    OPENSSL_free(decout);
    OPENSSL_free(encout);
    EVP_PKEY_CTX_free(decctx);
    EVP_PKEY_CTX_free(encctx);

    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(impctx);
    EVP_PKEY_free(pubkey);

    EVP_PKEY_free(privkey);
    OSSL_PROVIDER_unload(tpm2prov);
    OSSL_PROVIDER_unload(defprov);
    return ret;
}
