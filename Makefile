# onyx — development workflow
#
# On the Linux server:  make build / make release / make run-server
# On Mac:               make mac   (sync from server + rebuild client)

# ── Config (override via env) ────────────────────────────────────────────────
REMOTE     ?= my-server
REMOTE_SRC  = $(REMOTE):~/workspace/experiments/sheri

# ── Server-side ──────────────────────────────────────────────────────────────

.PHONY: build release run-server

build:
	cargo build

release:
	cargo build --release

## Run onyx-server locally (for local testing)
run-server:
	cargo run -p server

# ── Mac-side (run from your local onyx directory on Mac) ────────────────────

.PHONY: mac sync

## Pull all source changes from $(REMOTE) and rebuild the Mac client binary.
## Run this on your Mac:  make mac
mac: sync
	cargo build -p client

## Sync source only, no build.
sync:
	rsync -av --exclude target --exclude .git $(REMOTE_SRC)/ .
