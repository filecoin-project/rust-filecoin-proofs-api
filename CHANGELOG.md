# Changelog

All notable changes to filecoin-proofs-api will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://book.async.rs/overview/stability-guarantees.html).

## [Unreleased]

## [11.0.0] - 2022-01-10

- Add API calls required for empty sector update proofs [#64](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/64)

## [10.1.0] - 2021-10-25

- Add new Window PoSt per partition API calls [#66](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/66)

## [10.0.0] - 2021-10-01

- Update all dependencies to use proofs v10.0.0 [#63](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/63)
- Update XCode to 12.5.0 as 10.0.0 is deprecated on CI [#62](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/62)

## [9.0.0] - 2021-08-12

- Swap pairing for blst and update to latest proofs [#58](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/58)

## [8.0.1] - 2021-06-09

- Updates for finalizing snarkpack support [#57](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/57)

## [8.0.0] - 2021-06-01

- Integrate Proof Aggregation API [#51](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/51)

## [7.0.0] - 2021-04-28

- Improve RAM usage during unseal [#56](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/56)
- Update rust-toolchain to 1.51.0 [#55](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/55)

## [6.1.0] - 2021-03-11

- Update docs and changelog for release [#53](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/53)
- Improve docs and update to latest Proofs [#52](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/52)

## [6.0.0] - 2020-12-01

- Add support for updated proofs api_versioning [#49](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/49)

## [5.4.1] - 2020-11-02

- Upgrade bellperson to required version [#48](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/48)

## [5.4.0] - 2020-11-02

- Upgrade filecoin_proofs dependency to v5.4.0
- Add new v1_1 RegisteredSealProofs to increment porep_id [#47](https://github.com/filecoin-project/rust-filecoin-proofs-api/pull/47)

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

[Unreleased]: https://github.com/filecoin-project/rust-filecoin-proofs-api/compare/v11.0.0...HEAD
[11.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v11.0.0
[10.1.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v10.1.0
[10.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v10.0.0
[9.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v9.0.0
[8.0.1]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v8.0.1
[8.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v8.0.0
[7.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v7.0.0
[6.1.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v6.1.0
[6.0.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v6.0.0
[5.4.1]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v5.4.1
[5.4.0]: https://github.com/filecoin-project/rust-filecoin-proofs-api/tree/v5.4.0
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
