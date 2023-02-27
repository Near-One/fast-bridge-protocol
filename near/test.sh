#!/bin/bash
set -e

cd contracts
cargo test -- --nocapture
