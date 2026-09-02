# Changes
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-09-02
### Fixed
- Packaging: the wheel and sdist shipped the test-suite as a top-level `tests`
  package (`tests/__init__.py`, `tests/settings.py`, `tests/models.py`, and its
  migrations). Installing 1.1.0 or 1.1.1 dropped that package into
  `site-packages`, where it collided with the `tests` package of any project
  depending on this library and broke their test runs. `find_packages()` now
  excludes `tests`; the suite is still included in the sdist, but never
  installed.

## [1.1.1] - 2026-09-01
### Fixed
- `pre_save()` no longer writes the encrypted value back into the model instance.
  Django only requires `pre_save()` to return the value to persist; mutating the
  instance left ciphertext in the attribute after `save()`/`bulk_create()` and
  caused double encryption (data corruption) on a second `save()`.
  On Django 6.0, where `pre_save()` may be called more than once per
  `save()`, this corrupted data on the very first `save()`. `pre_save()` is now
  idempotent and side-effect free, as Django 6.0 requires.
- `QuerySet.update()` and `QuerySet.bulk_update()` stored plaintext in the
  database since 1.1.0 because they bypass `pre_save()`. `get_db_prep_save()` is
  back and encrypts any plain string reaching the database exactly once (values
  already encrypted by `pre_save()` are tagged and passed through).
- `decrypt()` crashed with `AttributeError` when `DEBUG=False` and the stored
  value was not a JSON envelope (plaintext, corrupted or legacy data). It now
  returns `None` consistently, as it already did with `DEBUG=True`.
### Added
- Regression tests for the issues above, including `pre_save()` idempotency.
- Django 6.0 classifier (test suite runs on 4.2, 5.2 and 6.0).

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
