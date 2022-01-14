# Building the Provider
This file contains instructions to build and install the tpm2-openssl provider.

## Dependencies
To build and install the tpm2-openssl software the following software packages
are required:

 * pkg-config
 * GNU Autotools (Autoconf, Automake, Libtool)
 * [GNU Autoconf Archive](https://www.gnu.org/software/autoconf-archive/),
   version >= 2017.03.21
 * C compiler and C library
 * [TPM2.0 TSS ESAPI library](https://github.com/tpm2-software/tpm2-tss)
   (libtss2-esys) >= 3.2.0 with header files
 * [OpenSSL](https://www.openssl.org/) >= 3.0.0 with header files

Although the software can run with the in-kernel resource manager (`/dev/tpmrm`)
we recommend using the user-space resource manager, which is less memory
constrained and thus enables creation of a larger number of transient objects.
You will need:

 * [TPM2 Access Broker & Resource Manager](https://github.com/tpm2-software/tpm2-abrmd),
   started with a sufficiently large `--max-transients` argument
 * D-Bus message bus daemon

To run the tests (see next Section) you will also need:

 * [TPM2.0 Tools](https://github.com/tpm2-software/tpm2-tools) >= 5.2
 * [IBM's Software TPM 2.0 Simulator](https://sourceforge.net/projects/ibmswtpm2/files)
 * curl >= 7.52.0

Note the absolute minimum is libtss2-esys >= 2.3.0 and tpm2-tools >= 4.0. Since
these cannot be built against OpenSSL 3.x you need in such case to install both
1.1.x and 3.x.


## Building From Source

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
installed to OpenSSL's `lib/ossl-modules` using:
```
make install
```

By default, the ossl-modules directory is auto-detected using pkg-config. To
install the provider to another directory call configure `--with-modulesdir`
and specify a full patch.


# Testing the Provider
To test the Provider you need a working TPM2 chip or a TPM2 simulator.


## Using With the TPM2 Simulator

### System-Wide

Run the the
[Microsoft/IBM TPM2 simulator](https://sourceforge.net/projects/ibmswtpm2):
```
./tpm_server
```

The simulator stores persistent information to the `NVChip` file in the current
directory. Remove this file before starting the simulator if you want a clean
state.

After starting the TPM2 simulator run the
[Access Broker & Resource Manager](https://github.com/tpm2-software/tpm2-abrmd)
 using the simulator's TCTI. By default it must be started as the user `tss`:
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

### Session Instance

Alternatively, to avoid using the `tss` user you can start `tpm2-abrmd` with
a session D-Bus instance, which is limited to the current login session:
```
export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --session --print-address --fork`
tpm2-abrmd --session --tcti mssim:host=localhost,port=2321 &
```

The `TPM2OPENSSL_TCTI` environment variable must then include `bus_type=session`:
```
export TPM2OPENSSL_TCTI="tabrmd:bus_name=com.intel.tss2.Tabrmd,bus_type=session"
```

Please note you need to start openssl in the same login session. Use the
system-wide D-Bus instance described above if you need to share the `tpm2-abrmd`
across sessions.


## Running Tests

To run the tests simply do
```
make check
```

If you enable test coverage calculation by `./configure --enable-code-coverage`
you can do
```
make check-code-coverage
```

This will run the test suite (`make check`) and build a code coverage report
detailing the code which was touched.

