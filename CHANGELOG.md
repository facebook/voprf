# Changelog

## 0.4.0-pre.4 (July 9, 2022)
* Updated to be in sync with draft-irtf-cfrg-voprf-11
* Adds the evaluate() function to the servers to calculate the output of the OPRF
  directly
* Renames the former evaluate() function to blind_evaluate to match the spec
* Fixes the order of parameters for PoprfClient::blind to align it with the
  other clients

## 0.4.0-pre.3 (July 1, 2022)
* Updated to be in sync with draft-irtf-cfrg-voprf-10, with
  the only difference from -09 being a constant string change

## 0.4.0-pre.2 (April 21, 2022)
* Exposes the derive_key function under the "danger" feature

## 0.4.0-pre.1 (April 1, 2022)
* Updated to be in sync with draft-irtf-cfrg-voprf-09, with
  the addition of the POPRF mode
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
