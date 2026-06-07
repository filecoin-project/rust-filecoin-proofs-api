# Releasing

## Prepare

To propose a new release, ensure the "Unreleased" section in the [`CHANGELOG.md`](https://github.com/filecoin-project/rust-filecoin-proofs-api/blob/master/CHANGELOG.md) is up-to-date.

## Release

Once the release is prepared, a repo owner will:

1. Trigger the `Release` GitHub Action workflow with appropriate level (`patch`, `minor`, `major`).
2. The **Release** GitHub Action workflow will automatically:
   * Create the git tag (`vX.Y.Z`).
   * Update the CHANGELOG.md, create a git commit and push it to the repository.
   * Publish the crate to [crates.io](https://crates.io) using `cargo publish`.
     - Note: This repository uses **trusted publishing** via OIDC. No `CARGO_REGISTRY_TOKEN` secret is required, but the repository must be configured as a trusted publisher on crates.io.

3. Verify the releases on crates.io:
   https://crates.io/crates/filecoin-proofs-api/versions
