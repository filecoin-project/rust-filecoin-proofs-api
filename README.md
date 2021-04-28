# Filecoin Proofs API

This library is meant to be the official public API into the proofs library.

[![CircleCI](https://circleci.com/gh/filecoin-project/rust-filecoin-proofs-api/tree/master.svg?style=svg)](https://circleci.com/gh/filecoin-project/rust-filecoin-proofs-api/tree/master)

> The main API to interact with the proofs system in [Filecoin](https://filecoin.io).

## Default build options

The build options enabled by default are `pairing` and `gpu`.  An alternative backend that can be used is `blst`.  The `pairing` and `blst` options specify which bls12-381 pairing library to use..

## Running the tests

Running the tests with the default features can be done like this:

```
cargo test --release --all
```

Running with the `blst` and `gpu` features can be done like this:

```
cargo test --no-default-features --features blst,gpu --release --all
```

Running with `pairing` and without the `gpu` feature can be done like this:

```
cargo test --no-default-features --features pairing --release --all
```

## License

MIT or Apache 2.0
