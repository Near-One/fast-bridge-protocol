cargo install cargo-expand
rustup target add wasm32-unknown-unknown --toolchain nightly-2023-01-10
cargo +nightly-2023-01-10 expand --manifest-path ./contracts/bridge/Cargo.toml --target wasm32-unknown-unknown > res/fastbridge_expand.rs
