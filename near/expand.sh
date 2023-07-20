RUST_VERSION=1.69.0
rustup install $RUST_VERSION
cargo +$RUST_VERSION install cargo-expand --version 1.0.56
rustup target add wasm32-unknown-unknown --toolchain $RUST_VERSION
cargo +$RUST_VERSION expand --manifest-path ./contracts/bridge/Cargo.toml --target wasm32-unknown-unknown > res/fastbridge_expand.rs
