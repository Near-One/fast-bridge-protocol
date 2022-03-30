#!/bin/bash
set -e

RUSTFLAGS='-C link-arg=-s' cargo clean --manifest-path ./contracts/Cargo.toml
