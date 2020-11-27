#!/usr/bin/bash

set -e

TARGET="x86_64-unknown-linux-gnu"

echo "Testing with Address SANitizer (ASAN):"
export RUSTFLAGS="-Zsanitizer=address"
cargo test -Zbuild-std --target $TARGET

# expected to produce false positives with uninstrumented code
#echo "Testing with memory sanitizer (MSAN):"
#export RUSTFLAGS="-Zsanitizer=memory"
#cargo test -Zbuild-std --target $TARGET

echo "Testing with Leak SANitizer (LSAN):"
export RUSTFLAGS="-Zsanitizer=leak"
cargo test -Zbuild-std --target $TARGET

echo "Testing with Thread SANitizer (TSAN):" 
export RUSTFLAGS="-Zsanitizer=thread"
# TSAN *can* show false positives for uninstrumented code
cargo test -Zbuild-std --target $TARGET

