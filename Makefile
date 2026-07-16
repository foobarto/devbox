.PHONY: test e2e lint hooks

# Enable the repository-managed checks for this checkout.
hooks:
	git config core.hooksPath .githooks

# Unit tests (no VM spun up). Requires bats-core: brew install bats-core
test:
	bats test/
	python3 -m unittest discover -s test -p '*_test.py'

# Destructive VM/OAuth integration suite. Explicitly opt in because it creates
# real Lima instances and intentionally exercises --with-creds in a temporary VM.
e2e:
	DEVBOX_E2E=1 DEVBOX_E2E_WITH_CREDS=1 test/e2e.sh

# Static analysis (optional; requires shellcheck)
lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck bin/devbox proxy/run.sh test/e2e.sh; \
	else \
		echo "shellcheck not installed — skipped"; \
	fi
