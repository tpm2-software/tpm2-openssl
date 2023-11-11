/* SPDX-License-Identifier: BSD-3-Clause */

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509v3.h>

#define TEST_PASSWORD "secret"
#define TEST_CSR_FILENAME "ec_genpkey_x509_csr.pem"

int generate_csr(const char *password, const char *filename)
{
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    X509_REQ *x509 = NULL;
    X509_NAME *name;
    STACK_OF(X509_EXTENSION) *exts = NULL;
    X509_EXTENSION *ex;
    FILE *csr_file = NULL;
    int ret = 1;

    // generate new private key
    if (!(pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=tpm2")))
        goto error1;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    params[1] = OSSL_PARAM_construct_utf8_string("user-auth", (char *)password, 0);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_keygen_init(pctx) <= 0
            || EVP_PKEY_CTX_set_params(pctx, params) <= 0
            || EVP_PKEY_generate(pctx, &pkey) <= 0)
        goto error1;

    // prepare a certificate signing request
    if (!(x509 = X509_REQ_new())
            || X509_REQ_set_version(x509, X509_REQ_VERSION_1) != 1
            || X509_REQ_set_pubkey(x509, pkey) != 1)
        goto error1;

    name = X509_REQ_get_subject_name(x509);
    if (!X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (unsigned char *)"CZ", -1, -1, 0)
            || !X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (const unsigned char *)"www.example.com", -1, -1, 0))
        goto error1;

    // set requested extensions
    if (!(exts = sk_X509_EXTENSION_new_null()))
        goto error1;

    if (!(ex = X509V3_EXT_nconf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE"))
            || !sk_X509_EXTENSION_push(exts, ex))
        goto error1;
    if (!(ex = X509V3_EXT_nconf_nid(NULL, NULL, NID_key_usage, "nonRepudiation,digitalSignature,keyEncipherment"))
            || !sk_X509_EXTENSION_push(exts, ex))
        goto error1;

    if (X509_REQ_add_extensions(x509, exts) != 1)
        goto error1;

    // sign the request
    if (X509_REQ_sign(x509, pkey, EVP_sha256()) <= 0
            || X509_REQ_check_private_key(x509, pkey) != 1)
        goto error1;

    // save the result
    if (!(csr_file = fopen(filename, "w")))
        goto error1;
    if (PEM_write_X509_REQ(csr_file, x509) != 1)
        goto error2;

    ret = 0;
error2:
    fclose(csr_file);
error1:
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(x509);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int main()
{
    OSSL_PROVIDER *defprov = NULL, *tpm2prov = NULL;
    int ret = 1;

    if ((defprov = OSSL_PROVIDER_load(NULL, "default")) == NULL)
        goto error;

    if ((tpm2prov = OSSL_PROVIDER_load(NULL, "tpm2")) == NULL)
        goto error;

    if (generate_csr(TEST_PASSWORD, TEST_CSR_FILENAME))
        goto error;

    ret = 0;
error:
    ERR_print_errors_fp(stderr);

    remove(TEST_CSR_FILENAME);
    OSSL_PROVIDER_unload(tpm2prov);
    OSSL_PROVIDER_unload(defprov);
    return ret;
}
