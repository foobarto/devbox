#!/usr/bin/env bats

setup() {
  REPO="$BATS_TEST_TMPDIR/repo with spaces"
  mkdir -p "$REPO/.githooks"
  cp "$BATS_TEST_DIRNAME/../Makefile" "$REPO/Makefile"
  cp "$BATS_TEST_DIRNAME/../.githooks/pre-commit" "$REPO/.githooks/pre-commit"
  chmod 0755 "$REPO/.githooks/pre-commit"

  git -C "$REPO" init -q
  git -C "$REPO" config user.name Test
  git -C "$REPO" config user.email test@example.invalid
  git -C "$REPO" config commit.gpgsign false
  git config --file "$REPO/.repo-gitconfig" test.safe true
  git -C "$REPO" add Makefile .githooks/pre-commit .repo-gitconfig
  git -C "$REPO" -c core.hooksPath=/dev/null commit -qm initial
  BASE_BRANCH="$(git -C "$REPO" branch --show-current)"

  # Simulate a checkout that used the former unsafe installer.
  git -C "$REPO" config core.hooksPath .githooks
  git -C "$REPO" config --add include.path ../.repo-gitconfig
}

@test "hooks use an installed clone-private copy without breaking the guard" {
  run make -s -C "$REPO" hooks
  [ "$status" -eq 0 ]

  common_dir="$(git -C "$REPO" rev-parse --git-common-dir)"
  case "$common_dir" in
    /*) ;;
    *) common_dir="$(cd "$REPO/$common_dir" && pwd -P)" ;;
  esac
  configured="$(git -C "$REPO" config --get core.hooksPath)"
  [[ "$configured" = /* ]]
  [ "$configured" = "$common_dir/devbox-hooks" ]
  [ -x "$configured/pre-commit" ]
  cmp "$REPO/.githooks/pre-commit" "$configured/pre-commit"

  # Replacing a tracked hook or adding another one must not affect Git.
  cp /bin/false "$REPO/.githooks/pre-commit"
  cp /bin/false "$REPO/.githooks/post-checkout"
  chmod 0755 "$REPO/.githooks/pre-commit" "$REPO/.githooks/post-checkout"
  run git -C "$REPO" commit --allow-empty -m safe-from-replaced-hook
  [ "$status" -eq 0 ]
  run git -C "$REPO" checkout -qb safe-from-added-hook
  [ "$status" -eq 0 ]

  # The installed credential guard still rejects secrets.
  mkdir -p "$REPO/bin"
  printf '%s\n' 'ACCESS_TOKEN=not-a-real-token' >"$REPO/bin/example"
  git -C "$REPO" add bin/example
  run git -C "$REPO" commit -m blocked-secret
  [ "$status" -ne 0 ]
  [[ "$output" == *"inline OAuth/API credential detected"* ]]

  # Ordinary staged production code remains committable.
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" ok' >"$REPO/bin/example"
  git -C "$REPO" add bin/example
  run git -C "$REPO" commit -m allowed-code
  [ "$status" -eq 0 ]
}

@test "a tracked config include cannot restore the worktree hook path" {
  make -s -C "$REPO" hooks
  configured="$(git -C "$REPO" config --get core.hooksPath)"

  git -C "$REPO" checkout -qb attacker
  git config --file "$REPO/.repo-gitconfig" core.hooksPath .githooks
  cp /bin/false "$REPO/.githooks/pre-commit"
  cp /bin/false "$REPO/.githooks/post-checkout"
  chmod 0755 "$REPO/.githooks/pre-commit" "$REPO/.githooks/post-checkout"
  git -C "$REPO" add .repo-gitconfig .githooks
  git -C "$REPO" -c core.hooksPath=/dev/null commit -qm attacker-hooks
  git -C "$REPO" checkout -q "$BASE_BRANCH"

  run git -C "$REPO" checkout -q attacker
  [ "$status" -eq 0 ]
  [ "$(git -C "$REPO" config --get core.hooksPath)" = "$configured" ]
  run git -C "$REPO" commit --allow-empty -m safe-from-included-config
  [ "$status" -eq 0 ]
}

@test "linked worktrees share hooks from the clone's common Git directory" {
  linked="$BATS_TEST_TMPDIR/linked worktree"
  git -C "$REPO" worktree add -qb linked "$linked"

  run make -s -C "$linked" hooks
  [ "$status" -eq 0 ]

  common_dir="$(cd "$REPO/.git" && pwd -P)"
  configured="$(git -C "$linked" config --get core.hooksPath)"
  [ "$configured" = "$common_dir/devbox-hooks" ]
  [ -x "$configured/pre-commit" ]

  cp /bin/false "$linked/.githooks/pre-commit"
  chmod 0755 "$linked/.githooks/pre-commit"
  run git -C "$linked" commit --allow-empty -m safe-in-linked-worktree
  [ "$status" -eq 0 ]
}

@test "rerunning after moving a checkout restores the absolute hook path" {
  make -s -C "$REPO" hooks
  moved="$BATS_TEST_TMPDIR/moved checkout"
  mv "$REPO" "$moved"

  run make -s -C "$moved" hooks
  [ "$status" -eq 0 ]
  configured="$(git -C "$moved" config --get core.hooksPath)"
  [[ "$configured" == "$moved/"* ]]

  mkdir -p "$moved/bin"
  printf '%s\n' 'ACCESS_TOKEN=not-a-real-token' >"$moved/bin/example"
  git -C "$moved" add bin/example
  run git -C "$moved" commit -m blocked-after-move
  [ "$status" -ne 0 ]
  [[ "$output" == *"inline OAuth/API credential detected"* ]]
}
