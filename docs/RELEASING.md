# Release automation

Stable `vMAJOR.MINOR.PATCH` tags are the only release input. The release workflow
builds and tests the tag and creates its GitHub Release. It publishes nothing
else.

## Scope

The originating handoff specification excluded release publishing from this
project: *"do not sign, notarize, install, publish, commit, or push releases."*
An earlier revision dispatched a `se-sshctl-release` event to
`ajchemist/homebrew-tap`, which drove a Formula update PR and a bottle publish.
That automation has been removed as a breaking change; see Beads decision
`se-sshctl-9jy`.

Distribution is now an explicit, operator-driven step outside this repository. A
tap may still consume the published GitHub Release and its immutable tag archive,
but nothing in this repository initiates it, and no cross-repository credential
is configured here.

## Removed configuration

These are no longer read by any workflow and can be deleted from the repository
once no other consumer depends on them:

- repository variable `HOMEBREW_APP_ID`;
- repository variable `HOMEBREW_LICENSE`;
- repository secret `HOMEBREW_APP_PRIVATE_KEY`.

Revoke the `se-sshctl Homebrew Release` GitHub App installation for this
repository when removing them. `LICENSE` is still required and still verified by
the workflow.

## Release

```sh
git tag v0.1.0
git push origin v0.1.0
```

To retry after a failure, run the `Release` workflow manually with the existing
tag. The workflow is idempotent and does not recreate an existing GitHub Release.
