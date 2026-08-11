# Tracefuse developer targets
.PHONY: demo test scan-demo scan-demo-clean build release clippy fmt clean

CARGO ?= cargo
BIN := ./target/release/tracefuse
DEMO_VULN := examples/demo-vulnerable
DEMO_CLEAN := examples/demo-clean

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test --all

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

demo: release
	@./scripts/demo.sh

scan-demo: release
	@# Vulnerable fixtures are expected to trip --fail-on high (exit 1)
	@$(BIN) scan $(DEMO_VULN) --fail-on high; \
	code=$$?; \
	if [ $$code -eq 1 ]; then exit 0; fi; \
	exit $$code

scan-demo-clean: release
	$(BIN) scan $(DEMO_CLEAN) --fail-on high

clean:
	$(CARGO) clean
