# Identity Certificates

## Certificate Signing

The tpm2 provider implements all operations required for certificate signing.
Therefore, the
[`openssl req`](https://www.openssl.org/docs/manmaster/man1/openssl-req.html),
[`openssl ca`](https://www.openssl.org/docs/manmaster/man1/openssl-ca.html) and
[`openssl x509`](https://www.openssl.org/docs/manmaster/man1/openssl-x509.html)
commands work as usual.

For example, to generate a new TPM-based key and a self-signed certificate:
```
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
            -x509 -subj "/C=GB/CN=foo" -keyout testkey.pem \
            -out testcert.pem
```

Or, to create a Certificate Signing Request (CSR) based on a persistent
Attestation Key at a given handle:
```
tpm2_createek -G ecc -c ek_ecc.ctx
tpm2_createak -C ek_ecc.ctx -G ecc -g sha256 -s ecdsa -c ak_ecc.ctx
tpm2_evictcontrol -c ak_ecc.ctx 0x81000000

openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' \
            -new -subj "/C=GB/CN=foo" -key handle:0x81000000 \
            -out testcsr.pem
```

If the key is not associated with any specific algorithm you may define the
hash algorithm using the `-digest` parameter and the padding scheme using the
`-sigopt pad-mode:` parameter.

For more details on PKI related openssl commands see the
[OpenSSL PKI Tutorial](https://pki-tutorial.readthedocs.io).

Please note that the `openssl pkcs12` tool doesn't work for TPM-based keys as
there is no PKCS#12 file format for TPM keys.

## Certificate Authority (CA)

The [OpenSSL PKI Tutorial](https://pki-tutorial.readthedocs.io/en/latest/simple/index.html)
introduces a simple CA operation. The test [rsa_pki.sh](../test/rsa_pki/rsa_pki.sh)
rewrites this example for a TPM-based CA.

Another example is provided by the blog
[ECC Certificates and mTLS with Nginx](https://andrew.dunn.dev/posts/ecc-certificates-and-mtls-with-nginx/).
The test [ec_pki.sh](../test/ec_pki/ec_pki.sh) rewrites this for a TPM-based CA.

## Certificate Management Protocol

The Certificate Management Protocol (CMP) can be used for obtaining X.509
certificates in a public key infrastructure. The
[`openssl cmp`](https://www.openssl.org/docs/manmaster/man1/openssl-cmp.html)
command works as usual.

The CMP uses a password-based MAC that is calculated using a high-number of
digest operations. This calculation is very slow when calculated using the TPM
hardware. You should configure **without** `--enable-op-digest`, or use the
`-propquery ?tpm2.digest!=yes` to explicitly disable the TPM-based digest operations.

For example, to perform a CMP Key Update Request do:
```
openssl cmp -provider tpm2 -provider default -propquery ?tpm2.digest!=yes \
            -cmd kur -server localhost:80/pkix/ -srvcert server-cert.pem \
            -key client-key.pem -cert client-cert.pem \
            -newkey new-client-key.pem -certout new-client-cert.pem
```

## Cryptographic Message Standard (S/MIME)

The Cryptographic Message Standard (CMS) is used e.g. by S/MIME v3.1 email
messages. The
[`openssl cms`](https://www.openssl.org/docs/manmaster/man1/openssl-cms.html)
command works as usual.

For example, to sign data do:
```
openssl cms -sign -provider tpm2 -provider default -propquery '?provider=tpm2' \
            -nodetach -md sha256 -inkey testkey.pem -signer testcert.pem \
            -in testdata -text -out testdata.sig
```

And to decrypt data do:
```
openssl cms -decrypt -provider tpm2 -provider default -propquery '?provider=tpm2' \
            -inkey testkey.pem -recip testcert.pem -in testdata.enc -out testdata
```

## TLS Handshake

The tpm2 provider implements all operations required for establishing a
TLS (e.g. HTTPS) connection authenticated using a TPM-based private key.
To perform the TLS handshake you need to:
 * Load the tpm2 provider to get support of TPM-based private keys.
 * Load the default provider to get a faster and wider set of symmetric ciphers.

When using a restricted signing key, which is associated with a specific hash
algorithm, you may need to limit the signature algorithms (using `-sigalgs`
or `SSL_CTX_set1_sigalgs`) to those supported by the key. The argument should
be a colon separated list of TLSv1.3 algorithm names in order of decreasing
preference.

The following TLSv1.2 and TLSv1.3 signature algorithms are supported:

| key      | pad-mode | digest | TLSv1.3 name           |
| -------- | -------- | ------ | ---------------------- |
| RSA      | pkcs1    | sha1   | rsa_pkcs1_sha1         |
| RSA      | pkcs1    | sha256 | rsa_pkcs1_sha256       |
| RSA      | pkcs1    | sha384 | rsa_pkcs1_sha384       |
| RSA      | pkcs1    | sha512 | rsa_pkcs1_sha512       |
| RSA      | pss      | sha256 | rsa_pss_rsae_sha256    |
| RSA      | pss      | sha384 | rsa_pss_rsae_sha384    |
| RSA      | pss      | sha512 | rsa_pss_rsae_sha512    |
| RSA-PSS  | pss      | sha256 | rsa_pss_pss_sha256     |
| RSA-PSS  | pss      | sha384 | rsa_pss_pss_sha384     |
| RSA-PSS  | pss      | sha512 | rsa_pss_pss_sha512     |
| EC P-256 | ecdsa    | sha256 | ecdsa_secp256r1_sha256 |
| EC P-384 | ecdsa    | sha384 | ecdsa_secp384r1_sha384 |
| EC P-512 | ecdsa    | sha512 | ecdsa_secp521r1_sha512 |

Please note that the **pkcs1** pad-modes are ignored in TLSv1.3 and will not be
negotiated.

To start a test server using the key and X.509 certificate created in the
previous section do:
```
openssl s_server -provider tpm2 -provider default  -propquery '?provider=tpm2' \
                 -accept 4443 -www -key testkey.pem -cert testcert.pem
```

For a mTLS connection, on client side:
```bash
openssl s_client -provider tpm2 -provider default  -propquery '?provider=tpm2' \
                 -connect 192.168.251.2:8443 -CAfile ec-cacert.pem \
                 -cert client.crt -key handle:0x81000000 -state -debug
```

The `-key` can be also specified using a persistent key handle.

Once the server is started you can access it using the standard `curl`:
```
curl --cacert testcert.pem https://localhost:4443/
```
