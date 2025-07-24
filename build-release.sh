#!/bin/sh

cargo build -r --target=x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/ocsfs .
objcopy --compress-debug-sections ocsfs
