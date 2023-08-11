CARGO = cargo

test-aurora-fast-bridge:
	cd aurora && \
	yarn && \
	cd integration-tests && \
	rustup target add wasm32-unknown-unknown && \
	export RUSTFLAGS='-C link-arg=-s' && \
	$(CARGO) build --target wasm32-unknown-unknown --release --manifest-path ../../near/contracts/Cargo.toml && \
	cargo test --all --jobs 4 -- --test-threads 4
