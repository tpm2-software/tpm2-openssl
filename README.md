[![Build Status](https://github.com/tpm2-software/tpm2-openssl/workflows/gcc-distcheck/badge.svg)](https://github.com/tpm2-software/tpm2-openssl/actions)
[![FreeBSD Build Status](https://api.cirrus-ci.com/github/tpm2-software/tpm2-openssl.svg?branch=master)](https://cirrus-ci.com/github/tpm2-software/tpm2-openssl)
[![codecov](https://codecov.io/gh/tpm2-software/tpm2-openssl/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-openssl)
[![Coverity Scan](https://scan.coverity.com/projects/22739/badge.svg)](https://scan.coverity.com/projects/tpm2-openssl)
[![CodeQL](https://github.com/tpm2-software/tpm2-openssl/workflows/CodeQL/badge.svg)](https://github.com/tpm2-software/tpm2-openssl/actions/workflows/codeql.yml)

# Provider for integration of TPM 2.0 to OpenSSL 3.x

Makes the TPM 2.0 accessible via the standard OpenSSL API and command-line tools,
so one can add TPM support to (almost) any OpenSSL 3.x based application.

The tpm2-openssl project

* Implements a
  [provider](https://www.openssl.org/docs/manmaster/man7/provider.html)
  that integrates the
  [Trusted Platform Module (TPM 2.0)](https://trustedcomputinggroup.org/work-groups/trusted-platform-module/)
  operations to the [OpenSSL 3.x](https://www.openssl.org/docs/OpenSSL300Design.html),
  which is the next version of OpenSSL after 1.1.1.

* Follows the new OpenSSL provider API and strictly avoids any legacy API.
  Therefore this implementation:
  - Is compatible with OpenSSL 3.x and (hopefully) future OpenSSL versions.
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
  implementation, version 3.2.0 or later.


## Build and Installation Instructions

[Several distributions](https://repology.org/project/tpm2-openssl/versions)
include a `tpm2-openssl` package. For example, on Debian 12 or Ubuntu 22.04
just run:
```bash
apt install tpm2-openssl tpm2-tools tpm2-abrmd libtss2-tcti-tabrmd0
```

The in-kernel resource manager is **not** sufficient for complex scenarios such
as SSL or X.509 operations. The [tpm2-abrmd](https://github.com/tpm2-software/tpm2-abrmd)
must be used instead.

Instructions for building and installing the tpm2 provider on other systems are
provided in the [INSTALL.md](docs/INSTALL.md) file.

Instructions for how releases are conducted, please see the
[RELEASE.md](docs/RELEASE.md) file.

## Features and Documentation

The tpm2 provider functions can be used via the
[`openssl`](https://www.openssl.org/docs/manmaster/man1/openssl.html)
command-line tool, or via the
[libcrypto](https://www.openssl.org/docs/manmaster/man7/crypto.html) API.

No TPM-specific API calls are needed: the applications may be completely unaware
that the keys being used are stored within TPM.
However, the application has to:
 - Load the tpm2 provider with the TPM-based operations,
 - When needed, load the
   [base](https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-base.html)
   or [default](https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-default.html)
   provider with operations for file read/write, standard encoders/decoders,
   symmetric ciphers, and hashes.

For further documentation see [latest github docs](docs).

### [Initialization](docs/initialization.md)

Connect to the TPM2 using the
[`openssl -provider`](https://www.openssl.org/docs/manmaster/man1/openssl.html)
option, or using the
[OSSL_PROVIDER](https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER.html)
API functions.
The `TPM2OPENSSL_TCTI` environment variable may be used to specify the
TPM Command Transmission Interface (TCTI).

The
[OSSL_PROVIDER_self_test](https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER_self_test.html)
API may be used to invoke the TPM self-test operation.

### [Symmetric Operations](docs/symmetric.md)

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

These operations are disabled by default. The `default` provider is much faster
and should be used instead.

### [Random Number Generation](docs/rng.md)

Provides a random number generation (TPM2_GetRandom) using the
[`openssl rand`](https://www.openssl.org/docs/manmaster/man1/openssl-rand.html)
or the
[EVP_RAND](https://www.openssl.org/docs/manmaster/man3/EVP_RAND.html) API.

### [Key Operations](docs/keys.md)

Provides key generation (TPM2_Create) using the
[`openssl genpkey`](https://www.openssl.org/docs/manmaster/man1/openssl-genpkey.html)
or the
[EVP_PKEY](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY.html) API
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

### [Asymmetric Operations](docs/asymmetric.md)

Provides asymmetric signature (TPM2_Sign) using the
[`openssl pkeyutl -sign`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
or the
[EVP_DigestSign](https://www.openssl.org/docs/manmaster/man3/EVP_DigestSign.html) API.
The PKCS1 (rsassa) and PSS (rsapss) padding (signing scheme) is supported.

For example, to sign arbitrary data:
```
openssl pkeyutl -provider tpm2 -inkey handle:0x81000000 \
                -sign -rawin -in testdata -out testdata.sig
```

Signing using a restricted signing key is possible, e.g. one can sign arbitrary
data using the TPM attestation key (AK) created by `tpm2_createak`.
Such keys are compatible with e.g. the [strongSwan](https://www.strongswan.org/)
[TPM Plugin](https://wiki.strongswan.org/projects/strongswan/wiki/TpmPlugin).
Therefore, OpenSSL could be used to create and deploy VPN keys/certificates.

Provides RSA decryption (TPM2_RSA_Decrypt) using the
[`openssl pkeyutl -decrypt`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
or the
[EVP_PKEY_decrypt](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt.html) API.

Provides ECDH shared secret derivation (TPM2_ECDH_ZGen) using the
[`openssl pkeyutl -derive`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
or the
[EVP_PKEY_derive](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_derive.html) API.

### [Identity Certificates](docs/certificates.md)

Provides all operations required to use a TPM2-based key for:
 - Certificate signing with
   [`openssl req`](https://www.openssl.org/docs/manmaster/man1/openssl-req.html),
 - Certificate Authority (CA) using
   [`openssl ca`](https://www.openssl.org/docs/manmaster/man1/openssl-ca.html),
 - Certificate Management Protocol (CMP) client using
   [`openssl cmp`](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html),
 - Cryptographic Message Standard (S/MIME) processing using
   [`openssl cms`](https://www.openssl.org/docs/manmaster/man1/openssl-cms.html),
 - TLS authentication.


## TPM Limitations

### Limited Resources

Please mind the limited number of transient key and sequence objects that can
be concurrently loaded in the TPM. The number of ongoing digest operations and
the number of loaded private keys is limited. The in-kernel resource manager
(`/dev/tpmrm`) is also memory constrained.

Complex scenarios such as SSL or X.509 operations require creation of a large
number of transient objects. The in-kernel resource manager is often not
sufficient and
the [user-space resource manager](https://github.com/tpm2-software/tpm2-abrmd)
must be used with a sufficiently large `--max-transients` argument.

### Limited Performance

The TPM is a cryptographic processor with a secure key storage. It is **not**
an accelerator. Many operations are slower than a pure software implementation.

For user convenience the tpm2 provider implements also
[Symmetric Operations](docs/symmetric.md) that do not use the secure storage,
but we recommend using the OpenSSL's
[default provider](docs/initialization.md#loading-multiple-providers)
instead in performance critical applications.

### Limited Set of Algorithms

Not every OpenSSL operation will work with the TPM: some are not specified by
the TCG TPM specification, some might not be implemented by your TPM chip.

The list of algorithms supported by the tpm2 provider on your actual TPM can be
retrieved using the [openssl list](https://www.openssl.org/docs/manmaster/man1/openssl-list.html)
commands.

Algorithms that do not require the TPM hardware, such as public key operations,
hashes or symmetric ciphers, can be fetched from the OpenSSL's
[default provider](docs/initialization.md#loading-multiple-providers).


## Help

When you get stuck, remember:
[Read-Search-Ask](https://www.freecodecamp.org/forum/t/how-to-get-help-when-you-are-stuck-coding/19514).
 1. Read the error message and the [documentation](docs)
 2. Search Google
 3. Ask for help

The [test scripts](test) provide examples for each implemented functionality. Each
test is simple and well-documented.

You can ask a question via an GitHub
[Issue](https://github.com/tpm2-software/tpm2-openssl/issues/new), or send
an email to the TPM2
[mailing list](https://lists.linuxfoundation.org/mailman/listinfo/tpm2).


## License

tpm2-openssl is distributed under the [BSD 3 Clause License](LICENSE).
