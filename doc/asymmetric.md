# Asymmetric Operations

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

The sign scheme of an RSA key is selected as follows:
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
openssl pkeyutl -provider tpm2 -provider base -sign -inkey testkey.priv -rawin -in testdata \
    -digest sha512 -pkeyopt pad-mode:pss -out testdata.sig
```

The sign scheme of an EC key is always TPM_ALG_ECDSA.

Signature verification using the public key is then done using the default
provider and the public key:
```
openssl pkeyutl -verify -pubin -inkey testkey.pub -rawin -in testdata \
    -digest sha512 -pkeyopt pad-mode:pss -sigfile testdata.sig
```

**Subject to TPM resource limits.** Every ongoing digest operation maintains a
transient sequence object within the TPM memory. The resource manager will not
allow creation of more concurrent objects than `TPM_PT_HR_TRANSIENT_MIN`.


## Decryption

Data encryption is done using the default provider and the public key.
For example, to encrypt the "testdata" file:
```
openssl pkeyutl -encrypt -pubin -inkey testkey.pub -in testdata -out testdata.crypt
```

The tpm2 provider implements a
[OSSL_OP_ASYM_CIPHER](https://www.openssl.org/docs/manmaster/man7/provider-asym_cipher.html)
operation for RSA keys that is made available via the
[EVP_PKEY_decrypt](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_decrypt.html)
API function and the
[`openssl pkeyutl -decrypt`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
command.

For example, to decrypt the "testdata" file using a decryption private key:
```
openssl pkeyutl -provider tpm2 -provider base -inkey testkey.priv -decrypt -in testdata.crypt -out testdata
```

The EC keys cannot be used for encryption. You need to derive a shared secret
first using ECDH and then use a symmetric cipher.


## Shared Secret Derivation

The tpm2 provider implements a
[OSSL_OP_KEYEXCH](https://www.openssl.org/docs/manmaster/man7/provider-keyexch.html)
operation for EC keys (ECDH) that is made available via the
[EVP_PKEY_derive](https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_derive.html)
API function and the
[`openssl pkeyutl -derive`](https://www.openssl.org/docs/manmaster/man1/openssl-pkeyutl.html)
command.

For example, to derive a shared `secret.key` from a (TPM-based) private key
`testkey1.priv` and a peer public key `testkey2.pub`:
```
openssl pkeyutl -provider tpm2 -provider base -derive -inkey testkey1.priv -peerkey testkey2.pub -out secret.key
```
