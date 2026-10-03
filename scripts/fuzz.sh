#!/bin/bash
# ruleaza pe rand toate tintele de fuzzing, fiecare $1 secunde (implicit 60)
# cere linux + nightly + cargo-fuzz:
#   rustup toolchain install nightly && cargo install cargo-fuzz
#   scripts/fuzz.sh 300

set -u
SECS=${1:-60}
# build-ul in afara repo-ului (mai rapid in WSL decat pe /mnt)
TARGET_DIR=${FUZZ_TARGET_DIR:-$HOME/vpn-fuzz-target}

cd "$(dirname "$0")/.."

# logurile langa build, nu in /tmp (in WSL /tmp se goleste la oprirea VM-ului)
LOGS="$TARGET_DIR/logs"
mkdir -p "$LOGS"

# build o data, inainte de rulare: o eroare de compilare nu trebuie confundata cu un crash
cargo +nightly fuzz build --target-dir "$TARGET_DIR" || { echo "build esuat"; exit 2; }

TARGETS=$(cargo +nightly fuzz list)
FAILED=()

for t in $TARGETS; do
    echo "== $t (${SECS}s)"
    log="$LOGS/$t.log"
    if cargo +nightly fuzz run "$t" --target-dir "$TARGET_DIR" -- -max_total_time="$SECS" 2> "$log"; then
        # ultima linie de statistica: cate executii si cata acoperire
        grep -E "^#[0-9]+.*(DONE|pulse)" "$log" | tail -n 1
    else
        echo "  CRASH - detalii in $log, input in fuzz/artifacts/$t/"
        FAILED+=("$t")
    fi
done

echo
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "nicio problema gasita"
else
    echo "probleme in: ${FAILED[*]}"
    exit 1
fi
