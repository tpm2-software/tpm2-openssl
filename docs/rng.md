# Random Number Generation

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
