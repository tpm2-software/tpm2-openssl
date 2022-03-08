# Key Operations

## Key Management

The tpm2 provider implements a
[OSSL_OP_KEYMGMT](https://www.openssl.org/docs/manmaster/man7/provider-keymgmt.html)
operation for creation and manipulation of TPM-based
[RSA](https://www.openssl.org/docs/manmaster/man7/RSA.html),
[RSA-PSS](https://www.openssl.org/docs/manmaster/man7/RSA-PSS.html)
or EC keys.
These can be used via the EVP_PKEY
[RSA](https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-RSA.html) or
[EC](https://www.openssl.org/docs/manmaster/man7/EVP_PKEY-EC.html)
API functions and the
[`openssl genpkey`](https://www.openssl.org/docs/manmaster/man1/openssl-genpkey.html)
command.

**Subject to TPM resource limits.** Every private EVP_PKEY maintains a transient
sequence object within the TPM memory. The resource manager will not allow
creation of more concurrent objects than `TPM_PT_HR_TRANSIENT_MIN`.

### Key Generation

The following public key algorithms are supported:

| key     | X.509 OID      |
| ------- | -------------- |
| RSA     | rsaEncryption  |
| RSA-PSS | id-RSASSA-PSS  |
| EC      | id-ecPublicKey |

The RSA-PSS key is a restricted version of RSA which only supports signing,
verification and key generation using the PSS padding scheme.

Settable key generation parameters (`-pkeyopt`):
 * `digest` (utf8_string) associates the key with a specific hash.
 * `user-auth` (utf8_string) defines a password, which will be used to authorize
   private key operations.
 * `parent` (uint32) defines parent of the key (as a hex number),
   by default 0x40000001 (TPM2_RH_OWNER).
 * `parent-auth` (utf8_string) defines an (optional) parent password. **Note** That in
    instances where the invoking command flow does not support `-pkeyopt` an environment
    variable `TPM2OPENSSL_PARENT_AUTH` may be used. The `-pkeyopt` `parent-auth`
    overrides the environment variable in instances where they are both set.

The RSA or RSA-PSS keys support also:
 * `bits` (size_t) defines a desired size of the key.
 * `e` (integer) defines a public exponent, by default 65537 (0x10001).

For example, to define a 1024-bit RSA key without authorization under
TPM2_RH_OWNER:
```
openssl genpkey -provider tpm2 -algorithm RSA -pkeyopt bits:1024 -out testkey.priv
```

The EC keys support the following key generation parameters:
 * `group` (utf8_string) specifies the curve to be used. You may use either the
   NIST names or the short OID names:

   | NIST    | OID name   | TPM2               |
   | ------- | ---------- | ------------------ |
   | P-192   | prime192v1 | TPM2_ECC_NIST_P192 |
   | P-224   | secp224r1  | TPM2_ECC_NIST_P224 |
   | P-256   | prime256v1 | TPM2_ECC_NIST_P256 |
   | P-384   | secp384r1  | TPM2_ECC_NIST_P384 |
   | P-521   | secp521r1  | TPM2_ECC_NIST_P521 |

To create an EC key with the P-256 curve, protected by the password `abc`:
```
openssl genpkey -provider tpm2 -algorithm EC -pkeyopt group:P-256 \
    -pkeyopt user-auth:abc -out testkey.priv
```

You may use the `EC PARAMETERS` file, but only the curve name is allowed:
```
openssl ecparam -name prime256v1 -out testparam.pem
openssl genpkey -provider tpm2 -paramfile testparam.pem -out testkey.priv
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

The following parameters of the generated EVP_PKEY can be retrieved from an
RSA or RSA-PSS key (via API only):
 * `bits` (integer), size of the key
 * `max-size` (integer) of the signature
 * `n` (integer), the RSA modulus
 * `e` (integer), the RSA exponent

The modulus can be displayed using:
```
openssl rsa -provider tpm2 -provider base -in testkey.priv -modulus -noout
```

Similarly, the following parameters can be retrieved from an EC key:
 * `group` (utf8_string) short OID name of the curve used
 * `bits` (integer), size of one key coordinate
 * `max-size` (integer) of the signature
 * `pub` (octet_string) public key with both x and y encoded
 * `x` and `y` (integer) individual components of the public key

The EC key also supports retrieval of the entire curve definition:
 * `p` (integer) defines the finite field
 * `a` and `b` (integer) define the elliptic curve
 * `generator` (octet_string) is the (encoded) base point G
 * `order` (integer) of G
 * `cofactor` (integer)

Naturally, parameters of the private key cannot be retrieved from any key.


## Storing the Private or a Public Key

The tpm2 provider implements several
[OSSL_OP_ENCODER](https://www.openssl.org/docs/manmaster/man7/provider-encoder.html)
operations for converting the generated (or loaded) key to various formats.
These can be used via the
[OSSL_ENCODER](https://www.openssl.org/docs/manmaster/man3/OSSL_ENCODER.html)
API functions and the
[`openssl pkey`](https://www.openssl.org/docs/manmaster/man1/openssl-pkey.html)
command.

The following encoders are supported:

| structure            | type                     | openssl arguments
| -------------------- | ------------------------ | -------------------------------- |
| PrivateKeyInfo       | PEM (`TSS2 PRIVATE KEY`) | (default)                        |
| PrivateKeyInfo       | DER                      | `-outform der`                   |
| SubjectPublicKeyInfo | PEM (`PUBLIC KEY`)       | `-pubout`                        |
| SubjectPublicKeyInfo | DER                      | `-pubout -outform der`           |
| PKCS1                | PEM (`RSA PUBLIC KEY`)   | `-RSAPublicKey_out`              |
| PKCS1                | DER                      | `-RSAPublicKey_out -outform der` |
| (null)               | text                     | `-text -noout`                   |

For example, to export the X.509 SubjectPublicKeyInfo in PEM (`PUBLIC KEY`),
which is the most common public key format, do:
```
openssl pkey -provider tpm2 -provider base -in testkey.priv -pubout -out testkey.pub
```

To print private key attributes you can use the `-text` argument:
```
openssl rsa -provider tpm2 -provider base -in testkey.priv -text -noout
```

Note: if the private key usage requires authorization you will be asked for a
password although exporting a public key does not require it. You may set
an empty password or anything else.


## Loading a Private Key

The tpm2 provider implements three
[OSSL_OP_STORE](https://www.openssl.org/docs/manmaster/man7/provider-storemgmt.html)
loaders:
 * **file** (default), to load the PEM file (`TSS2 PRIVATE KEY`);
 * **handle**, to load persistent keys, or data (public keys or certificates)
   from NV indices;
 * **object**, to load serialized object representing a persistent handle.

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
(`TSS2 PRIVATE KEY`), possibly with the optional `file:` prefix and a full path.
For example, to print out the value of the modulus of the private key:
```
openssl rsa -provider tpm2 -provider base -modulus -noout -in file:/etc/ssl/testkey.priv
```

The password may be supplied using the standard OpenSSL mechanism. You can use
the `-passin`
[option](https://www.openssl.org/docs/manmaster/man1/openssl-passphrase-options.html),
or (since the file contains an indicator whether an authorization is required)
an interactive password prompt appears.
For example, to use the password `abc`:
```
openssl rsa -provider tpm2 -provider base -modulus -noout -in testkey.priv -passin pass:abc
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

### Using NV Index

Public keys or certificates may be stored in the NV Index. To load data from
NV Index, specify the prefix `handle:` and then a hexadecimal number, e.g.
`handle:0x1000010`.

For example, to derive a shared secret from a persistent private key and a peer
key that is stored in an NV Index:
```
openssl pkeyutl -provider tpm2 -provider base -derive -inkey handle:0x81000000 -peerkey handle:0x1000010 -out secret.key
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
