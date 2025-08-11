#!/bin/sh

cargo build -r --target=x86_64-unknown-linux-musl
mkdir -p deploy
cp target/x86_64-unknown-linux-musl/release/octoka deploy/octoka
objcopy --compress-debug-sections deploy/octoka
./deploy/octoka gen-config-template --out deploy/config.toml
