# Changes
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-03-27
### Added
- Custom key support: pass a `key` parameter to `EncryptedField` for per-field keys.
- Per-instance key support: set `instance._encryption_key` for interactive/dynamic keys.
- Manual `encrypt(data, key=...)` and `decrypt(data, key=...)` with arbitrary keys.
- `deconstruct()` method for proper Django migration serialization.
- Key resolution order: per-instance key > field-level key > settings key.
### Changed
- Updated Django compatibility (4.2, 5.0, 5.1, 5.2).
- Updated Python classifiers (3.9–3.13).
- Used `getattr` for optional settings access to avoid crashes.
- Replaced `get_db_prep_save` with `pre_save` to support per-instance keys.
- Invalid key format now raises `InvalidKeyFormatException` instead of `InvalidKeyLengthException`.

## [1.0.4] - 2022-01-02
### Changed
- Improved typing to define return values in several places.

## [1.0.3] - 2021-12-29
### Added
- Repaired some wrong texts in README.

## [1.0.2] - 2021-12-29
### Added
- Cleaned some repeated code.
- Added specific exceptions.

## [1.0.1] - 2021-12-28
### Added
- Solved some typos.

## [1.0.0] - 2021-12-28
### Added
- Some minor changes.
- Tests.
- Build instructions to create pip package.

## [0.0.9] - 2021-12-28
### Added
- Full working package with support for several algorithms.

## [0.0.1] - 2021-12-27
### Added
- Added CHANGES.md and several other reference files.
- Initial field logic.

## [Unreleased]
