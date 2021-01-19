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
  [tpm2-tss](https://www.github.org/tpm2-software/tpm2-tss) software stack implementation.


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
  arbitrary data using the TPM attestation key (AK) created by `tpm2 createak`.
  Such keys are compatible with e.g. the
  [strongSwan](https://www.strongswan.org/)
  [TPM Plugin](https://wiki.strongswan.org/projects/strongswan/wiki/TpmPlugin).
  Therefore, OpenSSL could be used to create and deploy VPN keys/certificates.


**Warning!** This is work in progress. It's main purpose is to validate the
OpenSSL API and obtain community feedback.
Not all code has been migrated, not every feature has been implemented.
Nothing will be stable until the final OpenSSL 3.0 is released.

(At least) the following features are not yet implemented:
* Various parameters for key generation and usage
* Signing ASN.1, i.e. certificate signing
* ECDSA keys
* TPM simulator integration


## Integration with OpenSSL

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

The tpm2 provider comes as a single `tpm2.so` module, which needs to be installed
to OpenSSL's `lib/ossl-modules`. When successfully installed, you should see the
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

The provider operations can be invoked either via the `openssl` command line
tool, or via the
[EVP library](https://www.openssl.org/docs/manmaster/man7/evp.html) functions
from any custom application.


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
tpm2 getrandom --hex 10
```

Note: For compatibility reasons is the number generator named **CTR-DRBG**,
although the TPM uses a completely different mechanism.

Gettable parameters (API only):
 * "max_request" (size_t) defines maximal size of a single request.


## Key Management

The tpm2 provider implements a
[OSSL_OP_KEYMGMT](https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html)
operation for creation and manipulation of TPM-based **RSA** keys.
These can be used via the
[EVP_PKEY](https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-RSA.html)
API functions and the
[`openssl genpkey`](https://www.openssl.org/docs/manmaster/man1/openssl-genpkey.html)
and
[`openssl pkey`](https://www.openssl.org/docs/manmaster/man1/openssl-pkey.html)
commands.

### Key Generation

Settable key generation parameters (`-pkeyopt`):
 * "bits" (size_t) defines a desired size of the key.
 * "e" (bignum) defines a public exponent, by default 65537 (0x10001).
 * "user-auth" (utf8_string) defines a password, which will be used to authorize
   private key operations.

TODO: Missing owner. Missing key flags and key algs.

For example, to define a 1024-bit RSA key without authorization:
```
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv
```

Or, to define a 2048-bit RSA key with password `abc`:
```
openssl genpkey -provider tpm2 -algorithm RSA \
    -pkeyopt bits:2048 -pkeyopt user-auth:abc -out testkey.priv
```

You may also generate the key using standard TPM2 tools and then make the key
persistent under a given handle using `tpm2 evictcontrol`. For example to create
a new key Attestation Key (AK) with a handle 0x81000000:
```
tpm2 createek -G rsa -c ek_rsa.ctx
tpm2 createak -C ek_rsa.ctx -G rsa -g sha256 -s rsassa -c ak_rsa.ctx
tpm2 evictcontrol -c ak_rsa.ctx 0x81000000
```

### Exporting a Public Key

To export the X.509 SubjectPublicKeyInfo in PEM (`BEGIN PUBLIC KEY`), which
is the most common public key format, do:
```
openssl pkey -provider tpm2 -in testkey.priv -pubout -out testkey.pub
```

Note: if the private key usage requires authorization you will be asked for a
password although exporting a public key does not require it. You may set
an empty password, or anything else.

TODO: Export RSA one-liner for SSH client. Export textual information.


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

To load a private key, simply specify a name of a PEM file (`TSS2 PRIVATE KEY`),
possibly with the optional `file:` prefix.
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

To supply a password via the command-line tool, use then the standard `-passin`
[option](https://www.openssl.org/docs/manmaster/man1/openssl-passphrase-options.html).
All argument types (`pass:`, `env:`, `file:`, `fd:`, `stdin`) may be used.
For example, to supply a password from an evironment variable $PASSWORD:
```
openssl rsa -provider tpm2 -modulus -noout -in handle:0x81000000?pass -passin env:PASSWORD
```


## Signature

The tpm2 provider implements a
[OSSL_OP_SIGNATURE](https://www.openssl.org/docs/manmaster/man7/provider-signature.html)
operation that is made available via the
[EVP_DigestSign](https://www.openssl.org/docs/manmaster/man3/EVP_DigestSign.html)
API function and the
[`openssl pkeyutl -sign -rawin`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
command.

The `-rawin` argument ensures the digest is calculated by the TPM itself and thus
restricted signing keys, such as the Attestation Key (from tpm2 createak) can be
used.

For example, to sign the "testdata" file using the Attestation Key 0x81000000
(restricted signing key, associated with a specific algorithm and hash):
```
openssl pkeyutl -provider tpm2 -inkey handle:0x81000000 -sign -rawin -in testdata -out testdata.sig
```

Settable parameters (`-pkeyopt`):
 * "pad-mode" (utf8_string) defines algorithm to be used. The values follow the
   OpenSSL terminology:

   | openssl | tpm2           | algorithm |
   | ------- | -------------- | --------- |
   | pkcs1   | TPM_ALG_RSASSA | per RFC8017, Section 8.2. RSASSA-PKCS1-v1_5 |

 * "digest" (utf8_string) defines digest to be used. The following values are
   allowed:

   | openssl | tpm2           | algorithm |
   | ------- | -------------- | --------- |
   | sha256  | TPM_ALG_SHA256 | per ISO/IEC 10118-3 |

If the key is not associated with any algorithm, the `pad-mode` and `digest`
must be specified. For example, to sign using sha256 and rsassa:
```
openssl pkeyutl -provider tpm2 -inkey testkey.priv -sign -rawin -in testdata \
    -pkeyopt pad-mode:pkcs1 -pkeyopt digest:sha256 -out testdata.sig
```

Signature verification using the public key is then done using the default
provider and the public key:
```
openssl pkeyutl -verify -pubin -inkey testkey.pub -sigfile testdata.sig -rawin -in testdata
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
