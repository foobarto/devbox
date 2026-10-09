.PHONY: test e2e lint hooks

# Install reviewed repository checks outside the branch-controlled worktree.
hooks:
	@set -eu; \
	git_common_dir="$$(git rev-parse --git-common-dir)"; \
	git_common_dir="$$(cd "$$git_common_dir" && pwd -P)"; \
	hook_dir="$$git_common_dir/devbox-hooks"; \
	hook_config="$$hook_dir/config"; \
	mkdir -p "$$hook_dir"; \
	install -m 0755 .githooks/pre-commit "$$hook_dir/pre-commit"; \
	git config --file "$$hook_config" --replace-all core.hooksPath "$$hook_dir"; \
	pattern="$$(printf '%s' "$$git_common_dir" | sed 's/[][*?\\]/\\&/g')"; \
	exact_include="includeIf.gitdir:$$pattern.path"; \
	worktree_include="includeIf.gitdir:$$pattern/.path"; \
	git config --local --unset-all "$$exact_include" || [ "$$?" -eq 5 ]; \
	git config --local --unset-all "$$worktree_include" || [ "$$?" -eq 5 ]; \
	git config --local --add "$$exact_include" "$$hook_config"; \
	git config --local --add "$$worktree_include" "$$hook_config"; \
	previous="$$(git config --local --get core.hooksPath || true)"; \
	if [ -n "$$previous" ] && [ "$$previous" != .githooks ]; then \
		printf '%s\n' "hooks: replacing local core.hooksPath '$$previous'" >&2; \
	fi; \
	git config --local --unset-all core.hooksPath || [ "$$?" -eq 5 ]; \
	configured="$$(git config --get core.hooksPath || true)"; \
	if [ "$$configured" != "$$hook_dir" ]; then \
		printf '%s\n' "hooks: effective core.hooksPath is '$$configured', expected '$$hook_dir'" >&2; \
		exit 1; \
	fi; \
	printf '%s\n' "Installed reviewed hooks in $$hook_dir"

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
