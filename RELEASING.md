# Releasing Onyx

End-to-end release flow, including automated Homebrew tap updates.

## Required GitHub secrets

Set in `shervin9/onyx` → Settings → Secrets and variables → Actions:

| Secret | Purpose | Scope |
|---|---|---|
| `HOMEBREW_TAP_TOKEN` | Fine-grained PAT used to push the formula bump and dispatch the validation workflow in `shervin9/homebrew-onyx`. | **Repository access:** `shervin9/homebrew-onyx` only. **Permissions:** `Contents: Read and write` and `Metadata: Read-only`. |

The default `GITHUB_TOKEN` is intentionally **not** used for cross-repo pushes
— it cannot reach the tap repository.

## Release flow

1. Bump `version` in `Cargo.toml` (or your release notes draft) and merge to
   `main`.
2. Tag and push:

   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. The `Release` workflow (`.github/workflows/release.yml`) runs three jobs in
   order:

   1. **build** — cross-compiles client + server for all targets.
   2. **release** — downloads artifacts, generates `onyx-sha256sums.txt`,
      publishes the GitHub Release, and exposes the
      `onyx-macos-arm64` SHA256 as a job output.
   3. **bump-homebrew-formula** — checks out
      `shervin9/homebrew-onyx` with the PAT, rewrites `version` and
      `sha256` in `Formula/onyx.rb`, commits, pushes, and fires a
      `repository_dispatch` (`event_type=onyx-formula-bumped`).

4. The tap repo's validation workflow runs on push and on the dispatch.

## Expected release artifacts

Attached to the GitHub release:

- `onyx-linux-x86_64`
- `onyx-linux-arm64`
- `onyx-macos-arm64`
- `onyx-server-linux-x86_64`
- `onyx-server-linux-arm64`
- `onyx-sha256sums.txt`

These exact names are what `install.sh` and the Homebrew formula expect — do
not rename without updating both.

## After automation: install commands

```bash
# Homebrew (macOS Apple Silicon)
brew install shervin9/onyx/onyx

# Shell installer (Linux + macOS)
curl -fsSL https://useonyx.dev/install.sh | sh
```

## Recovery: formula bump failed

If `bump-homebrew-formula` fails after the release was published, the GitHub
Release is fine — only the tap is stale. To recover:

1. Inspect the failed workflow run for the cause (most common: expired PAT,
   tap-repo permissions changed, formula file moved).
2. Fix the underlying issue.
3. Re-run **just** the `bump-homebrew-formula` job from the Actions UI
   ("Re-run failed jobs"). The job is idempotent: if the formula already
   matches, it exits cleanly without an empty commit.
4. If you need to bump manually instead, in `shervin9/homebrew-onyx`:

   ```bash
   VERSION=0.1.0
   SHA256=$(curl -fsSL https://github.com/shervin9/onyx/releases/download/v${VERSION}/onyx-sha256sums.txt \
     | awk '$2 == "onyx-macos-arm64" {print $1}')
   sed -i -E "s|^([[:space:]]*)version \"[^\"]*\"|\\1version \"${VERSION}\"|" Formula/onyx.rb
   sed -i -E "s|^([[:space:]]*)sha256 \"[a-f0-9]+\"|\\1sha256 \"${SHA256}\"|" Formula/onyx.rb
   git commit -am "onyx v${VERSION}: bump formula"
   git push
   ```

## Tap repo validation workflow

Drop this into `shervin9/homebrew-onyx` at
`.github/workflows/validate.yml`. It runs on every push to `main`, on PRs
that touch the formula, and on the `onyx-formula-bumped` dispatch fired by
the main repo:

```yaml
name: Validate formula
on:
  push:
    branches: [main]
    paths: ['Formula/**']
  pull_request:
    paths: ['Formula/**']
  repository_dispatch:
    types: [onyx-formula-bumped]
  workflow_dispatch:

jobs:
  audit:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4

      - name: Audit formula
        run: |
          set -euo pipefail
          tap_dir="$(brew --repo)/Library/Taps/shervin9/homebrew-onyx"
          mkdir -p "$tap_dir"
          cp -R . "$tap_dir/"
          brew audit --strict --formula shervin9/onyx/onyx

      - name: Install and smoke test
        run: |
          brew install --formula shervin9/onyx/onyx
          onyx --version
```

The install step pulls the binary the formula now points at, so it
implicitly verifies that the new `url` + `sha256` are valid before any
user runs `brew install`.
