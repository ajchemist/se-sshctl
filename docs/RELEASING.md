# Release automation

Stable `vMAJOR.MINOR.PATCH` tags are the only inputs to Homebrew distribution.
The release workflow builds and tests the tag, creates its GitHub Release, then
sends a `se-sshctl-release` repository dispatch to `ajchemist/homebrew-tap`.
The tap independently downloads the immutable tag archive, computes its SHA-256,
and opens a tested Formula update PR.

## One-time GitHub setup

Create a GitHub App installed only on `ajchemist/homebrew-tap` with:

- Contents: read and write;
- Pull requests: read and write.

Set these in both repositories:

- repository variable `HOMEBREW_APP_ID`;
- repository secret `HOMEBREW_APP_PRIVATE_KEY`.

Set `HOMEBREW_LICENSE` in `ajchemist/se-sshctl` to the chosen SPDX identifier and
commit the matching `LICENSE` file before the first release. The workflow refuses
to publish without both values.

Protect the tap's `master` branch with the `test-formula` check and enable auto
merge. The App-created update PR will then merge only after Homebrew builds and
tests the Formula.

## Release

```sh
git tag v0.1.0
git push origin v0.1.0
```

If dispatch needs to be retried after the Release already exists, run the
`Release` workflow manually with the existing tag. The workflow is idempotent and
does not recreate an existing GitHub Release.
