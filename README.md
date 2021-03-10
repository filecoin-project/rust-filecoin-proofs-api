# Filecoin Proofs API

This library is meant to be the official public API into the proofs library.

[![CircleCI](https://circleci.com/gh/filecoin-project/rust-filecoin-proofs-api/tree/master.svg?style=svg)](https://circleci.com/gh/filecoin-project/rust-filecoin-proofs-api/tree/master)

> The main API to interact with the proofs system in [Filecoin](https://filecoin.io).

## Default build options

The build options enabled by default are `pairing` and `gpu`.  Alternatives that can be used for testing are `blst` and `gpu2`.  The `pairing` and `blst` options specify which bls12-381 pairing library to use.  The `gpu` and `gpu2` options specify between using `neptune`'s default GPU backend, or an opencl based implementation.

## License

MIT or Apache 2.0
