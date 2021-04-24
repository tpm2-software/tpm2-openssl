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


## Self-Testing

The provider supports the
[OSSL_PROVIDER_self_test](https://www.openssl.org/docs/manmaster/man3/OSSL_PROVIDER_self_test.html)
API function to invoke the TPM self-test operation.
See the [test/selftest.c](../test/selftest.c).

There is no command for invoking the self-test from the command-line.
