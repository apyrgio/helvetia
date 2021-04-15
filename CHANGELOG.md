# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog], and this project adheres to [Semantic
Versioning].

## [Unreleased]

## [0.2.0] - 2021-04-15

### Fixed

- Fix a broken link in the API docs.

### Changed

- Update the `caves` dependency to `v0.2`, meaning that RocksDB support is now
  optional. This should help with the (re)build times of this project.

## [0.1.1] - 2020-06-22

### Changed

- Update the CI tests to always run inside a temporary directory.
- Make the CI tests that run a Helvetia server more reliable.

## [0.1.0] - 2020-06-21

Initial release.

[Keep a Changelog]: https://keepachangelog.com/en/1.0.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

[Unreleased]: https://github.com/apyrgio/helvetia/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/apyrgio/helvetia/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/apyrgio/helvetia/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/apyrgio/helvetia/releases/tag/v0.1.0
