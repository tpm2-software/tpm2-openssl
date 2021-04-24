[![Build and Check](https://github.com/tpm2-software/tpm2-openssl/workflows/build%20and%20check/badge.svg)](https://github.com/tpm2-software/tpm2-openssl/actions)
[![codecov](https://codecov.io/gh/tpm2-software/tpm2-openssl/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-openssl)
[![Coverity Scan](https://scan.coverity.com/projects/22739/badge.svg)](https://scan.coverity.com/projects/tpm2-openssl)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/tpm2-software/tpm2-openssl.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-openssl/alerts/)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/tpm2-software/tpm2-openssl.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tpm2-software/tpm2-openssl/context:cpp)

# Provider for integration of TPM 2.0 to OpenSSL 3.0

Makes the TPM 2.0 accessible via the standard OpenSSL API and command-line tools,
so one can add TPM support to (almost) any OpenSSL 3.0 based application.

The tpm2-openssl project

* Implements a
  [provider](https://www.openssl.org/docs/manmaster/man7/provider.html)
  that integrates the
  [Trusted Platform Module (TPM 2.0)](https://trustedcomputinggroup.org/work-groups/trusted-platform-module/)
  operations to the [OpenSSL 3.0](https://www.openssl.org/docs/OpenSSL300Design.html),
  which is the next version of OpenSSL after 1.1.1.

* Follows the new OpenSSL provider API and strictly avoids any legacy API.
  Therefore this implementation:
  - Is compatible with OpenSSL 3.0 and (hopefully) future OpenSSL versions.
  - Does **not** work with any previous version, including the current OpenSSL 1.1.

* Is based on a major refactoring of the
  [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine).
  The code is still there, but largely reshuffled to match the new OpenSSL API.
  Therefore this implementation:
  - Retains (almost) all functions of the tpm2-tss-engine, although the
    command-line interface and the API has changed.
  - Does not modify format of the `TSS2 PRIVATE KEY` file, so keys created by
    the previous version still work.
  - Respects the original license and copyright.

* Relies on the
  [Enhanced System API (ESAPI)](https://trustedcomputinggroup.org/wp-content/uploads/TSS_ESAPI_v1p0_r08_pub.pdf)
  from the Trusted Computing Groups (TCG)
  [TPM Software Stack (TSS 2.0)](https://trustedcomputinggroup.org/work-groups/software-stack/)
  and uses the
  [tpm2-tss](https://www.github.org/tpm2-software/tpm2-tss) software stack
  implementation, version 2.3.0 or later.


## Build and Installation Instructions

Instructions for building and installing the tpm2 provider are provided in the
[INSTALL.md](doc/INSTALL.md) file.

## Features and Documentation

The tpm2 provider functions can be used via the
[`openssl`](https://www.openssl.org/docs/manmaster/man1/openssl.html)
command-line tool,
or via the
[libcrypto](https://www.openssl.org/docs/manmaster/man7/crypto.html) API.

### [Initialization](doc/initialization.md)

Connect to the TPM2 using the
[`openssl -provider`](https://www.openssl.org/docs/manmaster/man1/openssl.html)
option,
or using the
[OSSL_PROVIDER](https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER.html)
API functions.
The `TPM2OPENSSL_TCTI` environment variable may be used to specify the
TPM Command Transmission Interface (TCTI).

The
[OSSL_PROVIDER_self_test](https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER_self_test.html)
API may be used to invoke the TPM self-test operation.

### [Symmetric Operations](doc/symmetric.md)

Provides encryption (TPM2_EncryptDecrypt) using the
[`openssl enc`](https://www.openssl.org/docs/manmaster/man1/openssl-enc.html)
or the
[EVP_Cipher](https://www.openssl.org/docs/manmaster/man3/EVP_Cipher.html) API.
The AES-128, AES-192, AES-256, CAMELLIA-128, CAMELLIA-192 and CAMELLIA-256
algorithm in the ECB, CBC, OFB, CFB or CTR mode is supported.

Provides digest calculation (TPM2_Hash) using the
[`openssl dgst`](https://www.openssl.org/docs/manmaster/man1/openssl-dgst.html)
or the
[EVP_Digest](https://www.openssl.org/docs/manmaster/man3/EVP_Digest.html) API.
The SHA-1, SHA-256, SHA-384 and SHA-512 algorithm is supported.

### [Random Number Generation](doc/rng.md)

Provides a random number generation (TPM2_GetRandom) using the
[`openssl rand`](https://www.openssl.org/docs/manmaster/man1/openssl-rand.html)
or the
[EVP_RAND](https://www.openssl.org/docs/manmaster/man3/EVP_RAND.html) API.

### [Key Operations](doc/keys.md)

Provides key generation (TPM2_Create) using the
[`openssl genpkey`](https://www.openssl.org/docs/manmaster/man1/openssl-genpkey.html)
or the
[EVP_PKEY](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_gen.html) API
for the
[RSA](https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-RSA.html) and
RSA-PSS keys, as well as the
[EC](https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-EC.html) keys
with a NIST curve P-192, P-224, P-256, P-384 or P-521.
The private key gets stored as a PEM (`TSS2 PRIVATE KEY`) or DER file.

For example, to generate a RSA key using TPM:
```
openssl genpkey -provider tpm2 -algorithm RSA -out testkey.priv
```

Provides
[OSSL_STORE](https://www.openssl.org/docs/manmaster/man3/OSSL_STORE_CTX.html)
and
[OSSL_DECODER](https://www.openssl.org/docs/manmaster/man3/OSSL_DECODER.html) API
to load (TPM2_Load) a private key from a previously generated file, as well as
persistent keys generated with the
[tpm2-tools](https://github.com/tpm2-software/tpm2-tools). Both the hexadecimal
key `handle` as well as the serialized `object` file may be used. These URI
prefixes may be used with any openssl command.

The corresponding public key can be stored using the
[`openssl pkey`](https://www.openssl.org/docs/manmaster/man1/openssl-pkey.html)
or the
[OSSL_ENCODER](https://www.openssl.org/docs/manmaster/man3/OSSL_ENCODER.html) API.
The SubjectPublicKeyInfo (`PUBLIC KEY`) and PKCS1 (`RSA PUBLIC KEY`) form,
either PEM or DER is supported.

For example, to load a persistent key and export its public portion:
```
openssl pkey -provider tpm2 -in handle:0x81000000 -pubout -out testkey.pub
```

### [Asymmetric Operations](doc/asymmetric.md)

Provides asymmetric signature (TPM2_Sign) using the
[`openssl pkeyutl -sign`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
or the
[EVP_DigestSign](https://www.openssl.org/docs/manmaster/man3/EVP_DigestSign.html) API.
The PKCS1 (rsassa) and PSS (rsapss) padding (signing scheme) is supported.

For example, to sign arbitrary data:
```
openssl pkeyutl -provider tpm2 -inkey handle:0x81000000 -sign -rawin -in testdata -out testdata.sig
```

Signing using a restricted signing key is possible, e.g. one can sign arbitrary
data using the TPM attestation key (AK) created by `tpm2_createak`.
Such keys are compatible with e.g. the [strongSwan](https://www.strongswan.org/)
[TPM Plugin](https://wiki.strongswan.org/projects/strongswan/wiki/TpmPlugin).
Therefore, OpenSSL could be used to create and deploy VPN keys/certificates.

Provides RSA decryption (TPM2_RSA_Decrypt) using the
[`openssl pkeyutl -encrypt`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
or the
[EVP_PKEY_decrypt](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt.html) API.

Provides ECDH shared secret derivation (TPM2_ECDH_ZGen) using the
[`openssl pkeyutl -derive`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
or the
[EVP_PKEY_derive](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_derive.html) API.

### [Identity Certificates](doc/certificates.md)

Provides all operations required for certificate signing using
[`openssl req`](https://www.openssl.org/docs/manmaster/man1/openssl-req.html).

Provides all operations required for TLS authentication based on a
TPM2-based key.


## Help

You can ask a question via an GitHub
[Issue](https://github.com/tpm2-software/tpm2-openssl/issues/new), or send
an email to the TPM2
[mailing list](https://lists.01.org/postorius/lists/tpm2.lists.01.org/).


## License

tpm2-openssl is distributed under the [BSD 3 Clause License](LICENSE).
