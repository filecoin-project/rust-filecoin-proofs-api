# Releasing

## Prepare

To propose a new release, open a pull request with the following changes:

1. Update the version in [`Cargo.toml`](https://github.com/filecoin-project/rust-filecoin-proofs-api/blob/master/Cargo.toml): `package→version`.
2. Update the [`CHANGELOG.md`](https://github.com/filecoin-project/rust-filecoin-proofs-api/blob/master/CHANGELOG.md) file, set the release date & version, and add a new "Unreleased" section.

When a release PR is opened or updated, the **Release Checker** GitHub Action will:
* Verify that the version bump is correct.
* Perform a dry-run publish (`cargo publish --dry-run`) to ensure the crate is in a valid state for release.
* Create a draft GitHub Release and comment on the PR with a summary.

## Review and Release

Once the release is prepared, it'll go through a review:

1. Make sure that we're _ready_ to release.
2. Make sure that we're correctly following semver.
3. Make sure that we're not missing anything in the changelogs.
4. Verify that the **Release Checker** action has passed, including the "Dry-run publish" step.

Finally, a repo owner will:

1. Merge the release PR to master.
2. The **Releaser** GitHub Action will automatically:
   * Create the git tag (`vX.Y.Z`).
   * Publish the draft GitHub Release.
   * Publish the crate to [crates.io](https://crates.io) using `cargo publish`.
     - Note: This repository uses **trusted publishing** via OIDC. No `CARGO_REGISTRY_TOKEN` secret is required, but the repository must be configured as a trusted publisher on crates.io.

3. Verify the releases on crates.io:
   https://crates.io/crates/filecoin-proofs-api/versions
