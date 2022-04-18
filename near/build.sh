#!/bin/bash
set -e

RUSTFLAGS='-C link-arg=-s' cargo build --manifest-path ./contracts/Cargo.toml --target wasm32-unknown-unknown --release
cp ./**/target/wasm32-unknown-unknown/release/*.wasm ./res/

