# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)

## [1.3.0] - 2023-xx-yy
### Added
- Added support for RSA-OAEP decryption

## [1.2.0] - 2023-10-14
### Added
- Added support for ECDH with a KDF, which is used by ECC-based CMS (S/MIME).
- Added retrieval of OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY for EC keys and
  retrieval of TLS-GROUP provider capabilities to enable mTLS authentication
  (thanks to @rshearman).
- Added mTLS example to documentation (thanks to @hoinmic).
- Added missing RAND parameters: 'state' and 'strength' (thanks to @mccarey).
- Added ability to run tests in a container (thanks to @afreof).
- Added Visual Studio properties to simplify the Windows build (thanks to
  @philippun1).
### Changed
- Symmetric operations are disabled by default. In most situations these
  are not needed and cause a huge performance penalty.
  To enable, configure with `--enable-op-digest` or `--enable-op-cipher`.
### Removed
- Removed unofficial support for tpm2-tss < 3.2.0, which do not support
  the openssl 3.x.
### Fixed
- Fixed key export: the private keys are not exportable, which shall fix
  some TPM-based sign operations (thanks to @fhars).
- Fixed handle related operations on 32b machines (thanks to @dezgeg).
- Fixed OSSL_FUNC_KEYMGMT_HAS operations with NULL keys.
- Fixed a heap exception on some machines (thanks to @philippun1).
- Fixed build warnings when building on the Fedora Linux.
- In documentation and tests applied a correct order of providers
  (thanks to @hoinmic).
- Modified documentation: the user-space resource manager (abrmd) is almost
  mandatory for complex scenarios such as SSL or X.509 operations.

## [1.1.1] - 2022-10-09
### Fixed
- Support older TPM chips that do not support the CreateLoaded operation.
- Loading of NV index objects larger than TPM2_PT_NV_BUFFER_MAX.
- Loading of PEM certificates from the NV index.
- Support for the 'openssl cms' command for RSA keys.
- Support for PKCS1 padding in some parameters (thanks to @wxleong).
- Building of tpm2-openssl on Windows (thanks to @mhummels).
- Ability to run autoreconf on the release tarball.

## [1.1.0] - 2022-03-22
### Fixed
- Fixed segmentation fault when a signature algorithm is beging initialized
  without a private key.

### Added
- Added support for the `TPM2OPENSSL_PARENT_AUTH` environment variable.
- Added the Code of Conduct and Contributing guidelines.

## [1.0.1] - 2022-01-23
### Fixed
- Fixed RSA/EC key equality checks. Works with OpenSSL 3.0.1.
- Modified documentation to recommend the user-space resource manager.

## [1.0.0] - 2021-09-29
### Added
- Initial release of the provider.
