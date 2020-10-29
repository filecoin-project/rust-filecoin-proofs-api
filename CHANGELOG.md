# Changelog

All notable changes to filecoin-proofs-api will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://book.async.rs/overview/stability-guarantees.html).

## [Unreleased]

## [5.3.0] - 2020-10-29

- Upgrade filecoin_proofs dependency to v5.3.0
- Integrate blst backend [#46](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/46)
- Create SECURITY.md [#45](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/45)

## [5.2.0] - 2020-09-28

- Update rustc to 1.46.0 [#44](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/44)
- Expose distributed PoSt API from proofs [#41](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/41)

## [5.1.1] - 2020-09-08

- Export storage proofs errors [#40](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/40)
- Replace unwrap usage with expect [#39](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/39)

## [5.1.0] - 2020-08-13

- Upgrade filecoin_proofs dependency to v5.1.1 [#38](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/38)

## [5.0.0] - 2020-08-11

- Upgrade filecoin_proofs dependency to v5.0.0 (v28 parameters) [#37](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/37)

## [4.0.4] - 2020-07-28

- Add fauxrep2 API [#35](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/35)
- Don't start a new dev version after a release [#34](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/34)

## [4.0.3] - 2020-07-06

- Use correct fauxrep shape type parameters per sector size [#32](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/32)

## [4.0.2] - 2020-07-01

- Upgrade filecoin_proofs dependency to v4.0.3
- Support fauxrep API [#30](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/30)

## [4.0.1] - 2020-06-25

- Upgrade filecoin_proofs dependency to v4.0.2
- Add some tests to ensure param and vk methods work [#28](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/28)

## [4.0.0] - 2020-06-15

- Upgrade filecoin_proofs dependency to v4.0.0

## [3.0.0] - 2020-06-08

- Upgrade filecoin_proofs dependency to v3.0.0
- Construct porep_id per RegisteredSealProof [#24](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/24)
- Update toolchain to use rust stable [#20](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/20)

## [2.0.0] - 2020-05-27

- Add public access to unseal_range method
- Upgrade filecoin_proofs dependency to v2.0.0

## [1.0.0] - 2020-05-19

- Initial stable release

[Unreleased]: https://github.com/filecoin-project/rust-filecoin-proofs-api/compare/v5.3.0...HEAD
[5.3.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v5.3.0
[5.2.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v5.2.0
[5.1.1]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v5.1.1
[5.1.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v5.1.0
[5.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v5.0.0
[4.0.4]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v4.0.4
[4.0.3]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v4.0.3
[4.0.2]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v4.0.2
[4.0.1]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v4.0.1
[3.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v3.0.0
[2.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v2.0.0
[1.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v1.0.0
