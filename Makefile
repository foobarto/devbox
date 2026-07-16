.PHONY: test lint hooks

# Enable the repository-managed checks for this checkout.
hooks:
	git config core.hooksPath .githooks

# Unit tests (no VM spun up). Requires bats-core: brew install bats-core
test:
	bats test/
	python3 -m unittest discover -s test -p '*_test.py'

# Static analysis (optional; requires shellcheck)
lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck bin/devbox proxy/run.sh; \
	else \
		echo "shellcheck not installed — skipped"; \
	fi
