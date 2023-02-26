# Release Information

This document describes the general process that maintainers must follow when
making a release of the `tpm2-openssl` provider.


## Development Lifecycle

The majority of development will occur on **master** with tagged release numbers
following semver.org recommendations. The master branch will always be the
*next* release, and bugfix only releases can be branched off of *master* as
needed. These patch level branches will be supported on an as needed bases,
since we don't have dedicated stable maintainers.

This page explicitly does not formalize an LTS support timeline, and that is
intentional. The release schedules and required features are driven by community
involvement and needs. However, milestones may be created to outline the goals,
bugs, issues and timelines of the next release.


## Version Numbers

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Given a version number MAJOR.MINOR.PATCH, we increment the:
1. MAJOR version after doing incompatible changes,
2. MINOR version after adding functionality in a backwards-compatible manner, and
3. PATCH version after doing bug fixes, without adding new functionality.


## Release Candidates

The maintainers may create tags to identify progress toward the release. In these
cases we will append a string to the release number to indicate progress using
the abbreviation `rc` for 'release candidate'. This string will take the form of
`-rcX` with an incremental digit `X`, starting from `-rc0`.

Release candidates will be announced on the
[mailing list](https://lists.linuxfoundation.org/mailman/listinfo/tpm2). When a
RC has gone 1 week without new substantive changes, a release will be conducted.
Substantive changes are changes to the man-pages, code or tests.


## Release Checklist

The steps, in order, required to make a release.

- Ensure current HEAD is pointing to the last commit in the release branch.

- Ensure [all workflows](https://github.com/tpm2-software/tpm2-openssl/actions)
  have conducted a passing build of HEAD.

- Update version and date information in [CHANGELOG.md](CHANGELOG.md) **and** commit.

- Create a signed tag for the release. Use the version number as the title line
  in the tag commit message and use the [CHANGELOG.md](CHANGELOG.md) contents for
  that release as the body.
  ```bash
  git tag -s <tag-name>
  ```

- Build a tarball for the release and check the dist tarball. **Note**: The file
  name of the tarball should include a match for the git tag name.
  ```bash
  make distcheck
  ```

- Generate a detached signature for the tarball.
  ```bash
  gpg --armor --detach-sign <tarball>
  ```

- Push **both** the current git HEAD (should be the CHANGELOG edit) and tag to
  the release branch.
  ```bash
  git push origin HEAD:<release-branch>
  git push origin <tag-name>
  ```

- Create a release on [GitHub](https://github.com/tpm2-software/tpm2-openssl/releases),
  using the `<release-tag>` uploaded.
  - Use the [CHANGELOG.md](CHANGELOG.md) contents for that release as the message.
  - If it is a release candidate, ensure you check the "pre-release" box on the GitHub UI.
  - Add the dist tarball and signature file to the release.

- Send announcement on [mailing list](https://lists.linuxfoundation.org/mailman/listinfo/tpm2).
  This announcement should be accompanied by a link to the release page on GitHub
  as well as a link to the CHANGELOG.md accompanying the release.


## Verifying Signatures

Verifying the signature on a release tarball requires the project maintainers
public keys be installed in the GPG keyring of the verifier. With both the
release tarball and signature file in the same directory the following command
will verify the signature:
```
$ gpg --verify tpm2-openssl-X.Y.Z.tar.gz.asc
```
