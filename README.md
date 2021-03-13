[![Build and Check](https://github.com/tpm2-software/tpm2-openssl/workflows/build%20and%20check/badge.svg)](https://github.com/tpm2-software/tpm2-openssl/actions)
[![codecov](https://codecov.io/gh/tpm2-software/tpm2-openssl/branch/master/graph/badge.svg)](https://codecov.io/gh/tpm2-software/tpm2-openssl)
[![Coverity Scan](https://scan.coverity.com/projects/22739/badge.svg)](https://scan.coverity.com/projects/tpm2-openssl)

# Provider for integration of TPM 2.0 to OpenSSL 3.0

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


The original [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine)
will continue to work even with OpenSSL 3.0, however migration to the refactored
tpm2-openssl has the following advantages:

* Standard openssl commands for key generation (`openssl genrsa` or
  `openssl genpkey`) can be used. The tpm2tss-genkey is replaced by:
```
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out testkey.priv
```

* Handles to persistent keys created by standard tpm2 tools can be used for
  any operation in OpenSSL command-line tools and any other
  [EVP API](https://www.openssl.org/docs/manmaster/man7/evp.html)
  based applications.
```
openssl pkeyutl -provider tpm2 -inkey handle:0x81000000 -sign -rawin -in testdata -out testdata.sig
```

* Signing using a restricted signing key is possible, e.g. one can sign
  arbitrary data using the TPM attestation key (AK) created by `tpm2_createak`.
  Such keys are compatible with e.g. the
  [strongSwan](https://www.strongswan.org/)
  [TPM Plugin](https://wiki.strongswan.org/projects/strongswan/wiki/TpmPlugin).
  Therefore, OpenSSL could be used to create and deploy VPN keys/certificates.


**Warning!** This is work in progress. It's main purpose is to validate the
OpenSSL API and obtain community feedback.
Nothing will be stable until the final OpenSSL 3.0 is released.

(At least) the following features are not yet implemented:
* ECDSA keys


## Integration with OpenSSL

### Loading the Provider

In OpenSSL terms,
[provider](https://www.openssl.org/docs/manmaster/man7/provider.html) is a unit
of code that provides one or more implementations for various operations for
diverse algorithms.

List of active providers can be obtained from:
```
openssl list -providers
```

OpenSSL comes with a
[**default** provider](https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-default.html),
which supplies the standard algorithm implementations.

This project implements a **tpm2** provider that re-implements some algorithms
using the TPM 2.0. It does not replace the default provider though-- some
operations still need the default provider.

Instructions to build and install the provider are available in the
[INSTALL](INSTALL.md) file. When successfully installed, you can load the
provider using the `-provider tpm2` argument. For example, you should see the
provider listed when you do:
```
openssl list -providers -provider tpm2
```

You may use other
[openssl list](https://www.openssl.org/docs/manmaster/man1/openssl-list.html)
commands to inspect the various algorithms provided, such as the list of encoders,
by:
```
openssl list -encoders -provider tpm2
```

### Loading Multiple Providers

You can load several providers and combine their operations. When providers
implementing identical operations are loaded, you need to specify a
[property query clause](https://www.openssl.org/docs/manmaster/man7/property.html)
to advise which of the two implementations shall be used.

For example, to use tpm2 operations when available and the default operations
otherwise, specify:
```
-provider tpm2 -provider default -propquery ?provider=tpm2
```

You can also avoid one or more TPM2 operations. This is useful for resolving
conflicts between various implementations. For example, to use TPM2 for all
available operations except OSSL_OP_DIGEST, specify:
```
-provider tpm2 -provider default -propquery ?provider=tpm2,tpm2.digest!=yes
```

### TPM Command Transmission Interface (TCTI)

By default the provider will access the `/dev/tpm0` device. The TPM Command
Transmission Interface (TCTI) can be modified either using the
`TPM2OPENSSL_TCTI` environment variable or using the `tcti`
[config](https://www.openssl.org/docs/manmaster/man5/config.html)
option.

For example, to use the
[TPM2 Resource Manager](https://github.com/tpm2-software/tpm2-abrmd)
set:
```
export TPM2OPENSSL_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
```

The provider operations can be invoked either via the `openssl` command line
tool, or via the
[EVP library](https://www.openssl.org/docs/manmaster/man7/evp.html) functions
from any custom application.


## Message Digest (Hash) Generation

The tpm2 provider implements a
[OSSL_OP_DIGEST](https://www.openssl.org/docs/manmaster/man7/provider-digest.html)
operation, which calculates message digests using the TPM. It is made available
to applications via the
[EVP_Digest](https://www.openssl.org/docs/manmaster/man3/EVP_Digest.html) API
function and the
[`openssl dgst`](https://www.openssl.org/docs/manmaster/man1/openssl-dgst.html)
command.

The following algorithms are supported by the tpm2 provider, although your
TPM may support only a subset of these:

| openssl | tpm2             |
| ------- | ---------------- |
| sha1    | TPM2_ALG_SHA1    |
| sha256  | TPM2_ALG_SHA256  |
| sha384  | TPM2_ALG_SHA384  |
| sha512  | TPM2_ALG_SHA512  |
| sm3     | TPM2_ALG_SM3_256 |

For example, to calculate SHA-256 hash of the `data.txt` file:
```
openssl dgst -provider tpm2 -sha256 data.txt
```

Please note that TPM2 does not allow replication of hash sequences, so the
`EVP_MD_CTX_copy` function cannot be supported. This causes inconveniences e.g.
to the TLS Handshake implementation.


## Symmetric Ciphers

The tpm2 provider implements a
[OSSL_OP_CIPHER](https://www.openssl.org/docs/manmaster/man7/provider-cipher.html)
operation, which encrypts and decrypts messages using the TPM ciphers. It is made
available to applications via the
[EVP_Cipher](https://www.openssl.org/docs/manmaster/man3/EVP_Cipher.html) API
function and the
[`openssl enc`](https://www.openssl.org/docs/manmaster/man1/openssl-enc.html)
command.

The AES-128-CBC (`aes128`), AES-192-CBC (`aes192`) and AES-256-CBC (`aes256`)
are supported by the tpm2 provider, although your TPM may support only a subset
of these.

For example, to encrypt the `data.txt` file using AES-128-CBC and a given key
and initialization vector (IV):
```
openssl enc -provider tpm2 -aes128 -e -K $KEY -iv $IV -in data.txt -out data.enc
```

The key (`-K`) used for the operation will be imported into a temporary object
in the NULL hierarchy. The object will be removed after `EVP_CIPHER_CTX_free`.


## Random Number Generation

The tpm2 provider implements a
[OSSL_OP_RAND](https://www.openssl.org/docs/manmaster/man7/provider-rand.html)
operation, which retrieves random bytes from the TPM. It is made available to
applications via the
[EVP_RAND](https://www.openssl.org/docs/manmaster/man3/EVP_RAND.html) API function
and the
[`openssl rand`](https://www.openssl.org/docs/manmaster/man1/openssl-rand.html)
command.

For example, to generate 10 bytes:
```
openssl rand -provider tpm2 -hex 10
```

This is similar to:
```
tpm2_getrandom --hex 10
```

Note: For compatibility reasons is the number generator named **CTR-DRBG**,
although the TPM uses a completely different mechanism.

Gettable parameters (API only):
 * `max_request` (size_t) defines maximal size of a single request.


## Key Management

The tpm2 provider implements a
[OSSL_OP_KEYMGMT](https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html)
operation for creation and manipulation of TPM-based
[RSA](https://www.openssl.org/docs/manmaster/man7/RSA.html) and
[RSA-PSS](https://www.openssl.org/docs/manmaster/man7/RSA-PSS.html) keys.
These can be used via the
[EVP_PKEY](https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-RSA.html)
API functions and the
[`openssl genpkey`](https://www.openssl.org/docs/manmaster/man1/openssl-genpkey.html)
command.

### Key Generation

The following public key algorithms are supported:

| openssl | X.509         |
| ------- | ------------- |
| RSA     | rsaEncryption |
| RSA-PSS | id-RSASSA-PSS |

The RSA-PSS key is a restricted version of RSA which only supports signing,
verification and key generation using the PSS padding scheme.

Settable key generation parameters (`-pkeyopt`):
 * `bits` (size_t) defines a desired size of the key.
 * `e` (integer) defines a public exponent, by default 65537 (0x10001).
 * `digest` (utf8_string) associates the key with a specific hash.
 * `user-auth` (utf8_string) defines a password, which will be used to authorize
   private key operations.
 * `parent` (uint32) defines parent of the key (as a hex number),
   by default 0x40000001 (TPM2_RH_OWNER).
 * `parent-auth` (utf8_string) defines an (optional) parent password.

For example, to define a 1024-bit RSA key without authorization under
TPM2_RH_OWNER:
```
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv
```

Or, to define a 2048-bit RSA key with password `abc`:
```
openssl genpkey -provider tpm2 -algorithm RSA \
    -pkeyopt bits:2048 -pkeyopt user-auth:abc -out testkey.priv
```

You may also generate the key using standard TPM2 tools and then make the key
persistent under a given handle using `tpm2_evictcontrol`. For example to create
a new key Attestation Key (AK) with a handle 0x81000000:
```
tpm2_createek -G rsa -c ek_rsa.ctx
tpm2_createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -c ak_rsa.ctx
tpm2_evictcontrol -c ak_rsa.ctx 0x81000000
```

Keys restricted to `rsapss` will be handled as RSA-PSS, all other keys as RSA.

### Key Parameter Retrieval

The following parameters of the generated EVP_PKEY can be retrieved (via API
only):
 * `bits` (integer), size of the key
 * `max-size` (integer) of the signature

In addition to that, the following public key parameters can be exported from
the EVP_PKEY:
 * `n` (integer), the RSA modulus
 * `e` (integer), the RSA exponent

The modulus can be displayed using:
```
openssl rsa -provider tpm2 -in testkey.priv -modulus -noout
```

Naturally, parameters of the private key cannot be retrieved.


## Storing the Private or a Public Key

The tpm2 provider implements several
[OSSL_OP_ENCODER](https://www.openssl.org/docs/manmaster/man7/provider-encoder.html)
operations for converting the generated (or loaded) key to various formats.
These can be used via the
[OSSL_ENCODER](https://www.openssl.org/docs/manmaster/man3/OSSL_ENCODER.html)
API functions and the
[`openssl pkey`](https://www.openssl.org/docs/manmaster/man1/openssl-genpkey.html)
command.

The following encoders are supported:

| structure            | type                     | openssl arguments
| -------------------- | ------------------------ | -------------------------------- |
| PKCS8                | PEM (`TSS2 PRIVATE KEY`) | (default)                        |
| PKCS8                | DER                      | `-outform der`                   |
| SubjectPublicKeyInfo | PEM (`PUBLIC KEY`)       | `-pubout`                        |
| SubjectPublicKeyInfo | DER                      | `-pubout -outform der`           |
| PKCS1                | PEM (`RSA PUBLIC KEY`)   | `-RSAPublicKey_out`              |
| PKCS1                | DER                      | `-RSAPublicKey_out -outform der` |
| (null)               | text                     | `-text -noout`                   |

For example, to export the X.509 SubjectPublicKeyInfo in PEM (`PUBLIC KEY`),
which is the most common public key format, do:
```
openssl pkey -provider tpm2 -in testkey.priv -pubout -out testkey.pub
```

To print private key attributes you can use the `-text` argument:
```
openssl rsa -provider tpm2 -in testkey.priv -text -noout
```

Note: if the private key usage requires authorization you will be asked for a
password although exporting a public key does not require it. You may set
an empty password or anything else.


## Loading a Private Key

The tpm2 provider implements two
[OSSL_OP_STORE](https://www.openssl.org/docs/manmaster/man7/provider-storemgmt.html)
operations:
 * **file** (default), which can be used to load the PEM file (`TSS2 PRIVATE KEY`);
 * **handle**, which can be used to load persistent keys.

These are used by the
[OSSL_STORE](https://www.openssl.org/docs/manmaster/man7/ossl_store.html)
API functions and all `openssl` commands that require a private key.

Note the tpm2 provider does not implement public key operations. Use the default
openssl provider for these.
For example, to print out the value of the modulus of the public key simply do:
```
openssl rsa -modulus -noout -in testkey.pub
```

### Using PEM File

To load a TPM-based private key, simply specify a name of a PEM file
(`TSS2 PRIVATE KEY`), possibly with the optional `file:` prefix.
For example, to print out the value of the modulus of the private key:
```
openssl rsa -provider tpm2 -modulus -noout -in file:testkey.priv
```

The password may be supplied using the standard OpenSSL mechanism. You can use
the `-passin`
[option](https://www.openssl.org/docs/manmaster/man1/openssl-passphrase-options.html),
or (since the file contains an indicator whether an authorization is required)
an interactive password prompt appears.
For example, to use the password `abc`:
```
openssl rsa -provider tpm2 -modulus -noout -in testkey.priv -passin pass:abc
```

### Using Key Handle

To load a persistent key using its handle, specify the prefix `handle:` and
then a hexadecimal number, e.g. `handle:0x81000000`. This works with any OpenSSL
operation.

For example, to print out the value of the modulus of the persistent key:
```
openssl rsa -provider tpm2 -modulus -noout -in handle:0x81000000
```

An authorization may be required to use the key. To supply a password you need
first to append `?pass` to the URI, e.g. `handle:0x81000000?pass`.
This activates the `pem_password_cb` callback.

To supply a password via the command-line tool, use then the standard
[`-passin` option](https://www.openssl.org/docs/manmaster/man1/openssl-passphrase-options.html).
All argument types (`pass:`, `env:`, `file:`, `fd:`, `stdin`) may be used.
For example, to supply a password from an evironment variable $PASSWORD:
```
openssl rsa -provider tpm2 -modulus -noout -in handle:0x81000000?pass -passin env:PASSWORD
```

### Using a Serialized Object

The `tpm2_evictcontrol` command can optionally output a serialized object
representing the persistent handle:
```
tpm2_evictcontrol -c ak_rsa.ctx -o ak_rsa.obj
```

To load a persistent key using the serialized object, specify the prefix
`object:` and then a file name:
```
openssl rsa -provider tpm2 -modulus -noout -in object:ak_rsa.obj
```


## Signature

The tpm2 provider implements a
[OSSL_OP_SIGNATURE](https://www.openssl.org/docs/manmaster/man7/provider-signature.html)
operation that is made available via the
[EVP_DigestSign](https://www.openssl.org/docs/manmaster/man3/EVP_DigestSign.html)
API function and the
[`openssl pkeyutl -sign`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
command.

The optional `-rawin` argument ensures the digest is calculated by the TPM
itself and thus restricted signing keys, such as the Attestation Key (from
tpm2_createak) can be used. Without `-rawin`, the key cannot be restricted and
the input data length must correspond to the digest length.

For example, to sign the "testdata" file using the Attestation Key 0x81000000
(restricted signing key, associated with a specific algorithm and hash):
```
openssl pkeyutl -provider tpm2 -inkey handle:0x81000000 -sign -rawin -in testdata -out testdata.sig
```

The digest (hash) algorithm is selected as follows:
 * The hash algorithm associated with the private key is used.
 * When `null`, the algorithm may be set using the `-digest XXX` argument. The
   `sha1`, `sha256`, `sha384` and `sha512` may be used.
 * If not set, the sha256 algorithm is used as a default.

The sign scheme is selected as follows:
 * The sign scheme associated with the private key is used.
 * When `null`, the scheme may be set using the `-pkeyopt pad-mode:XXX` argument.
   The values follow the OpenSSL terminology:

   | openssl | tpm2           | algorithm |
   | ------- | -------------- | --------- |
   | pkcs1   | TPM_ALG_RSASSA | per RFC8017, Section 8.2. RSASSA-PKCS1-v1_5 |
   | pss     | TPM_ALG_RSAPSS | per RFC8017, Section 8.1. RSASSA-PSS |

 * If not set, the pkcs1 (TPM_ALG_RSASSA) algorithm is used as a default.

For example, to sign using sha512 and pss:
```
openssl pkeyutl -provider tpm2 -sign -inkey testkey.priv -rawin -in testdata \
    -digest sha512 -pkeyopt pad-mode:pss -out testdata.sig
```

Signature verification using the public key is then done using the default
provider and the public key:
```
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
    -digest sha512 -pkeyopt pad-mode:pss -sigfile testdata.sig
```


## Decryption

Data encryption is done using the default provider and the public key.
For example, to encrypt the "testdata" file:
```
openssl pkeyutl -encrypt -pubin -inkey testkey.pub -in testdata -out testdata.crypt
```

The tpm2 provider implements a
[OSSL_OP_ASYM_CIPHER](https://www.openssl.org/docs/manmaster/man7/provider-asym_cipher.html)
operation that is made available via the
[EVP_PKEY_decrypt](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt.html)
API function and the
[`openssl pkeyutl -decrypt`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
command.

For example, to decrypt the "testdata" file using a decryption private key:
```
openssl pkeyutl -provider tpm2 -inkey testkey.priv -decrypt -in testdata.crypt -out testdata
```


## Certificate Signing

The tpm2 provider implements all operations required for certificate signing.
Therefore, the
[`openssl req`](https://www.openssl.org/docs/manmaster/man1/openssl-req.html)
commands work as usual.

For example, to generate a new TPM-based key and a self-signed certificate:
```
openssl req -provider tpm2 -x509 -subj "/C=GB/CN=foo" -keyout testkey.pem -out testcert.pem
```

Or, to create a Certificate Signing Request (CSR) based on a persistent
Attestation Key at a given handle, previously created with `tpm2_createak` and
`tpm2_evictcontrol`:
```
openssl req -provider tpm2 -new -subj "/C=GB/CN=foo" -key handle:0x81000000 -out testcsr.pem
```

If the key is not associated with any specific algorithm you may define the
hash algorithm using the `-digest` parameter and the padding scheme using the
`-sigopt pad-mode:` parameter.


## TLS Handshake

The tpm2 provider also implements all operations required for establishing a
TLS (e.g. HTTPS) connection authenticated using a TPM-based private key.
To perform the TLS handshake you need to:
 * Load the tpm2 provider to get support of TPM-based private keys.
 * Load the default provider to get a faster and wider set of symmetric ciphers.
 * Exclude TPM2 hashes, which are incompatible with the TLS implementation.

When using a restricted signing key, which is associated with a specific hash
algorithm, you also need to limit the signature algorithms (using `-sigalgs`
or `SSL_CTX_set1_sigalgs`) to those supported by the key.

To start a test server using the key and X.509 certificate created in the
previous section do:
```
openssl s_server -provider tpm2 -provider default -propquery ?provider=tpm2,tpm2.digest!=yes \
                 -accept 4443 -www -key testkey.pem -cert testcert.pem -sigalgs "RSA+SHA256"
```

You can then access it using the standard `curl`:
```
curl --cacert testcert.pem https://localhost:4443/
```

You can also use a persistent key at a given handle, but the key can only be
associated with the `rsapss` sign scheme, which is preferred by the TLS standard.
