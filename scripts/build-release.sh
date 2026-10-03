#!/bin/bash
# binare de release statice (musl) pentru linux, folosite la deploy pe VM
#   scripts/build-release.sh              aarch64 (VM-urile ARM din OCI) + x86_64
#   scripts/build-release.sh aarch64      doar una
#
# cere: rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
#       cargo install cargo-zigbuild + zig (https://ziglang.org/download)
#
# musl + static: binarul nu depinde de glibc-ul de pe server (Ubuntu 22.04 pe VM are
# o glibc mai veche decat masina pe care se compileaza, un binar dinamic n-ar porni)

set -euo pipefail
cd "$(dirname "$0")/.."

ARCHES=${*:-aarch64 x86_64}
TARGET_DIR=${CARGO_TARGET_DIR:-target}
OUT=dist
mkdir -p "$OUT"

for arch in $ARCHES; do
    target="$arch-unknown-linux-musl"
    echo "== $target"
    cargo zigbuild --release --target "$target" -p vpn-server -p vpn-client
    for bin in vpn-server vpn-client; do
        cp "$TARGET_DIR/$target/release/$bin" "$OUT/$bin-$arch"
    done
done

echo
ls -l "$OUT"
file "$OUT"/* 2> /dev/null || true
# sumele de control, pentru verificare dupa copiere pe server
(cd "$OUT" && sha256sum vpn-* > SHA256SUMS && cat SHA256SUMS)
