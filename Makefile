.PHONY: test lint

# Unit tests (no VM spun up). Requires bats-core: brew install bats-core
test:
	bats test/

# Static analysis (optional; requires shellcheck)
lint:
	@command -v shellcheck >/dev/null 2>&1 \
		&& shellcheck bin/devbox proxy/run.sh \
		|| echo "shellcheck not installed — skipped"
