#!/bin/bash
set -e

cd contracts
cargo test --no-default-features -- --nocapture
