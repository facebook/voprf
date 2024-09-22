# voprf ![Build Status](https://github.com/facebook/voprf/workflows/Rust%20CI/badge.svg)
An implementation of a (verifiable) oblivious pseudorandom function (VOPRF)

A VOPRF is a verifiable oblivious pseudorandom function, a protocol between a client and a server. The regular (non-verifiable) OPRF is also supported in this implementation.

This implementation is based on the [Internet Draft for VOPRF](https://github.com/cfrg/draft-irtf-cfrg-voprf).

Documentation
-------------

The API can be found [here](https://docs.rs/voprf/) along with an example for usage.

Installation
------------

Add the following line to the dependencies of your `Cargo.toml`:

```
voprf = "0.4.1"
```

### Minimum Supported Rust Version

Rust **1.65** or higher.

Contributors
------------

The author of this code is Kevin Lewi ([@kevinlewi](https://github.com/kevinlewi)).
To learn more about contributing to this project, [see this document](./CONTRIBUTING.md).

License
-------

This project is dual-licensed under either the [MIT license](./LICENSE-MIT)
or the [Apache License, Version 2.0](./LICENSE-APACHE).
You may select, at your option, one of the above-listed licenses.
