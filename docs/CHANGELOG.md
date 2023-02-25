# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)

## [1.2.0] - 2023-03-xx
### Added
- Added support for ECDH with a KDF, which is used by ECC-based CMS (S/MIME).
### Changed
- Symmetric operations are disabled by default. In most situations these
  are not needed and cause a huge performance penalty.
  To enable configure with `--enable-op-digest` or `--enable-op-cipher`.
### Removed
- Removed unofficial support for tpm2-tss < 3.2.0, which do not support
  the openssl 3.x.
### Fixed
- Fixed OSSL_FUNC_KEYMGMT_HAS operations with NULL keys
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
