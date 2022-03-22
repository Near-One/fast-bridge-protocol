#!/bin/bash
set -e

cargo test --manifest-path ./contracts/Cargo.toml -- --nocapture
