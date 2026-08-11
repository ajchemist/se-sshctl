# Release automation

Stable `vMAJOR.MINOR.PATCH` tags are the only inputs to Homebrew distribution.
The release workflow builds and tests the tag, creates its GitHub Release, then
sends a `se-sshctl-release` repository dispatch to `ajchemist/homebrew-tap`.
The tap independently downloads the immutable tag archive, computes its SHA-256,
and opens a tested Formula update PR.

## Why a GitHub App

The repository-scoped `GITHUB_TOKEN` from `se-sshctl` cannot dispatch to
`ajchemist/homebrew-tap`. The tap also uses an App token when opening its update
PR so that the Formula test workflow runs for the resulting event. A private
GitHub App avoids a long-lived personal access token and limits the installation
to one repository with only the required permissions.

## GitHub App configuration

`se-sshctl Homebrew Release` (App ID `4556534`) is installed only on
`ajchemist/homebrew-tap` with:

- Contents: read and write;
- Pull requests: read and write.

Metadata read access is mandatory for GitHub Apps. Webhooks and event
subscriptions are disabled.

Both repositories contain:

- repository variable `HOMEBREW_APP_ID`;
- repository secret `HOMEBREW_APP_PRIVATE_KEY`.

The PEM is not stored in either repository or retained locally. To rotate it,
generate a new App private key, update both secrets, verify token issuance, then
delete the old key in the App settings.

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
