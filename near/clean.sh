#!/bin/bash
set -e

cd contracts
RUSTFLAGS='-C link-arg=-s' cargo clean
