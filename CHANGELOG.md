# Changelog

## 0.4.1 (TBD)
* Backport all non-protocol-breaking changes from versions 0.5+
  * Fixes Rust 1.81+ compatibility, compatible with 0.4.0 (draft 11), incompatible with 0.5+ (final RFC)
* Updated dependencies

## 0.4.0 (September 15, 2022)
* Updated to be in sync with draft-irtf-cfrg-voprf-11, with
  the addition of the POPRF mode
* Adds the evaluate() function to the servers to calculate the output of the OPRF
  directly
* Renames the former evaluate() function to blind_evaluate to match the spec
* Fixes the order of parameters for PoprfClient::blind to align it with the
  other clients
* Exposes the derive_key function under the "danger" feature
* Added support for running the API without performing allocations
* Revamped the way the Group trait was used, so as to be more easily
  extendable to other groups
* Added common traits for each public-facing struct, including serde
  support

## 0.3.0 (October 25, 2021)

* Updated to be in sync with draft-irtf-cfrg-voprf-08

## 0.2.0 (October 18, 2021)

* Removed the CipherSuite interface
* Added the "danger" feature for exposing internal functions
* General improvements to the group interface

## 0.1.0 (September 29, 2021)

* Initial release
