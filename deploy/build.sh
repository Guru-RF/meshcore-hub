#!/usr/bin/env bash
# Build release binaries for the hub VM (Debian 13, x86_64) inside a Debian 13
# Rust container, so they link against the VM's glibc. Output: dist/.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${RUST_IMAGE:-rust:1-trixie}
mkdir -p dist target/debian
docker run --rm \
	-u "$(id -u):$(id -g)" \
	-e CARGO_HOME=/src/target/debian/cargo-home \
	-v "$PWD":/src -w /src \
	"$IMAGE" \
	cargo build --release --locked -p meshcore-hubd -p meshcore-portal --target-dir target/debian
cp target/debian/release/meshcore-hubd target/debian/release/meshcore-portal dist/
ls -l dist/
