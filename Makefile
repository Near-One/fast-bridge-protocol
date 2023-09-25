test-aurora-fast-bridge:
	cd aurora && \
	yarn && \
	yarn dev:prettier && \
	cd ../near && \
	./build_for_tests.sh && \
	cd ../aurora/integration-tests && \
	cargo test --all --jobs 4 -- --test-threads 4
