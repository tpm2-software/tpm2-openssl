# Initialization

## Loading the Provider

In OpenSSL terms,
[provider](https://www.openssl.org/docs/manmaster/man7/provider.html) is a unit
of code that provides one or more implementations for various operations for
diverse algorithms.

List of active providers can be obtained from:
```
openssl list -providers
```

Instructions to build and install the provider are available in the
[INSTALL](INSTALL.md) file. When successfully installed, you can load the
provider using the `-provider tpm2` argument. For example, you should see the
provider listed when you do:
```
openssl list -providers -provider tpm2
```

You may use other
[openssl list](https://www.openssl.org/docs/manmaster/man1/openssl-list.html)
commands to list algorithms supported by the tpm2 provider on your actual TPM
hardware, such as the list of supported public key algorithms, by:
```
openssl list -public-key-algorithms -provider tpm2
```

The **tpm2** provider supplies TPM 2.0 crypto algorithms, random number generator,
retrieval of persistent keys and other data (public keys and certificates) from
the non-volatile RAM and an encoder/decoder for the `TSS2 PRIVATE KEY` file format.

### Loading Multiple Providers

For some operations the **tpm2** provider needs to be combined with other
OpenSSL providers:
 * [**base** provider](https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-base.html)
   supplies retrieval of keys from a file and standard public key file formats;
 * [**default** provider](https://www.openssl.org/docs/manmaster/man7/OSSL_PROVIDER-default.html)
   supplies the standard crypto algorithms (non-TPM) and the **base** provider
   functions.

It is quite common to combine the **tpm2** provider with other providers, e.g.
when loading `TSS2 PRIVATE KEY` from a file.
```
-provider tpm2 -provider base
```

To use additional crypto algorithms that are not available in the TPM you need
to combine the **tpm2** provider with the **default** provider.

When providers implementing identical operations are loaded, you need to specify a
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


## Self-Testing

The provider supports the
[OSSL_PROVIDER_self_test](https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER_self_test.html)
API function to invoke the TPM self-test operation.
See the [test/selftest.c](../test/selftest.c).

There is no command for invoking the self-test from the command-line.
