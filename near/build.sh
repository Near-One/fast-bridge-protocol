#!/bin/bash
set -e

mkdir -p res
cd contracts
RUSTFLAGS='-C link-arg=-s' cargo build --target wasm32-unknown-unknown --release
cp ./target/wasm32-unknown-unknown/release/*.wasm ../res/

