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
  arbitrary data using the TPM attestation key (AK) created by `tpm2_createak`.
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
