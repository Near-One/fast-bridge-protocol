test-aurora-fast-bridge:
	cd aurora && \
	yarn && \
	cd ../near && \
	./build_for_tests.sh && \
	cd ../aurora/integration-tests && \
	cargo test --all --jobs 4 -- --test-threads 4
