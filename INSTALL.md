This file contains instructions to build and install the tpm2-openssl provider.

# Dependencies
To build and install the tpm2-openssl software the following software packages
are required:

 * pkg-config
 * GNU Autotools (Autoconf, Automake, Libtool)
 * [GNU Autoconf Archive](https://www.gnu.org/software/autoconf-archive/),
   version >= 2017.03.21
 * C compiler and C library
 * [TPM2.0 TSS ESAPI library](https://github.com/tpm2-software/tpm2-tss)
   (tss2-esys) and header files
 * [OpenSSL](https://www.openssl.org/) >= 3.0
   development libraries and header files

The OpenSSL 3.0 is not released yet. You need to download the latest Alfa version
and build it from sources.

To run the tests you will also need:

 * [TPM2.0 Tools](https://github.com/tpm2-software/tpm2-tools)
 * [TPM2 Access Broker & Resource Manager](https://github.com/tpm2-software/tpm2-abrmd)
 * [IBM's Software TPM 2.0 Simulator](https://sourceforge.net/projects/ibmswtpm2/files)
 * D-Bus message bus daemon


# Building From Source

Run the bootstrap script to generate the configure script:
```
./bootstrap
```

Then run the configure script, which generates the makefiles:
```
./configure
```

You may `--enable-debug` or specify a custom `PKG_CONFIG_PATH` where to search
for the OpenSSL libraries and header files.
```
./configure --enable-debug PKG_CONFIG_PATH=/home/foo/.local/lib/pkgconfig
```

Build the sources
```
make
```

The tpm2 provider comes as a single `tpm2.so` module, which needs to be
installed to OpenSSL's `lib/ossl-modules`.


# Using With the TPM2 Simulator

## System-Wide

Run the the
[Microsoft/IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2):
```
./tpm_server
```

Then run the Access Broker & Resource Manager using the simulator's TCTI. By
default it must be started as the user `tss`:
```
sudo -u tss tpm2-abrmd --tcti mssim:host=localhost,port=2321
```

Finally, export the `TPM2OPENSSL_TCTI` environment variable with the Resource
Manager's TCTI:
```
export TPM2OPENSSL_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd"
```

If you use the TPM2 Tools you need to export also `TPM2TOOLS_TCTI` with the
same value.

## Local Session

Alternatively, to avoid using the `tss` user you can start `tpm2-abrmd` with
a local D-Bus session:
```
export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
tpm2-abrmd --session --tcti mssim:host=localhost,port=2321
```

The `TPM2OPENSSL_TCTI` environment variable must then include `bus_type=session`:
```
export TPM2OPENSSL_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
```

