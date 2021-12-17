# Symmetric Operations

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

| digest  | tpm2             |
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

**Subject to TPM resource limits.** Every ongoing digest operation maintains a
transient sequence object within the TPM memory. The resource manager will not
allow creation of more concurrent objects than `TPM_PT_HR_TRANSIENT_MIN`.


## Symmetric Ciphers

The tpm2 provider implements a
[OSSL_OP_CIPHER](https://www.openssl.org/docs/manmaster/man7/provider-cipher.html)
operation, which encrypts and decrypts messages using the TPM ciphers. It is made
available to applications via the
[EVP_Cipher](https://www.openssl.org/docs/manmaster/man3/EVP_Cipher.html) API
function and the
[`openssl enc`](https://www.openssl.org/docs/manmaster/man1/openssl-enc.html)
command.

To use a cipher you need to specify the cipher name, desired key size and
a mode of operation. Although your TPM may implement only a limited subset,
the tpm2 provider supports any combination of:
 * `AES` and `CAMELLIA` cipher
 * Key size `128`, `192` and `256`
 * `ECB`, `CBC` (default), `OFB`, `CFB` and `CTR` modes of operation

For example, to encrypt the `data.txt` file using AES-128-CBC and a given key
and initialization vector (IV):
```
openssl enc -provider tpm2 -aes-128-cbc -e -K $KEY -iv $IV -in data.txt -out data.enc
```

The key (`-K`) used for the operation will be imported into a temporary object
in the NULL hierarchy. The object will be removed after `EVP_CIPHER_CTX_free`.
