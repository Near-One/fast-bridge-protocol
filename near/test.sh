#!/bin/bash
set -e

cd contracts
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release

RUST_BACKTRACE=1 cargo test --jobs 8
