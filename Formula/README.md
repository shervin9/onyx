# Homebrew formula

This directory contains the Homebrew formula for the Onyx client and the
packaged companion server binaries used for remote bootstrap.

## Status

The formula currently targets **macOS Apple Silicon** only. Linux users
should install via `curl -fsSL https://useonyx.dev/install.sh | sh`. Linux
bottles will be added once release artifacts stabilise.

## How to publish as a tap

Homebrew taps live in a separate repository whose name starts with
`homebrew-`. To make `brew install shervin9/onyx/onyx` work:

1. Create the repo **`shervin9/homebrew-onyx`** on GitHub.
2. Copy `onyx.rb` from this directory into the tap repo's `Formula/`
   directory.
3. Update the `sha256` fields to match the values for `onyx-macos-arm64`,
   `onyx-server-linux-x86_64`, and `onyx-server-linux-arm64` listed in the
   corresponding release's `onyx-sha256sums.txt`.
4. Bump `version` to match the release tag.

Users can then run:

```bash
brew install shervin9/onyx/onyx
```

which is shorthand for tapping `shervin9/homebrew-onyx` and installing the
`onyx` formula from it.

## Local install without a tap

You can also install straight from this file for local testing:

```bash
brew install --formula ./Formula/onyx.rb
```

This requires the referenced release artifacts and correct `sha256` values.
