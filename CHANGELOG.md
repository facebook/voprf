# Changelog

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
