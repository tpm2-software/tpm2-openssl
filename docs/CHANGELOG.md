# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)

## [1.0.2] - next
### Fixed
- Fixed segmentation fault when a signature algorithm is beging initialized
  without a private key.

## [1.0.1] - 2022-01-23
### Fixed
- Fixed RSA/EC key equality checks. Works with OpenSSL 3.0.1.
- Modified documentation to recommend the user-space resource manager.

## [1.0.0] - 2021-09-29
### Added
- Initial release of the provider.
