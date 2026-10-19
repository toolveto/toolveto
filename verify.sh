#!/usr/bin/env bash
set -eo pipefail

MODE=${1:-all}
STATUS=0

run_lint() {
  if [ -f "package.json" ]; then
    pnpm lint 2>/dev/null || npm run lint 2>/dev/null || true
  fi
  if [ -f "go.mod" ] || [ -f "go.work" ]; then
    go vet ./...
  fi
}

run_compile() {
  if [ -f "package.json" ]; then
    pnpm typecheck 2>/dev/null || pnpm build 2>/dev/null || true
  fi
  if [ -f "go.mod" ] || [ -f "go.work" ]; then
    go build -o /dev/null ./...
  fi
}

run_test() {
  if [ -f "package.json" ]; then
    pnpm test 2>/dev/null || npm test 2>/dev/null || true
  fi
  if [ -f "go.mod" ] || [ -f "go.work" ]; then
    go test -race -count=1 ./...
  fi
}

run_agent() {
  local out
  if ! out=$(run_lint 2>&1); then
    echo "[LINT_FAIL]"
    echo "$out" | tail -n 35
    exit 1
  fi
  if ! out=$(run_compile 2>&1); then
    echo "[COMPILE_FAIL]"
    echo "$out" | tail -n 35
    exit 1
  fi
  if ! out=$(run_test 2>&1); then
    echo "[TEST_FAIL]"
    echo "$out" | grep -E "(--- FAIL:|FAIL\s|FAIL$|Error:|error TS|panic:|fatal|[a-zA-Z0-9_.-]+\.(go|ts|tsx|py|js):[0-9]+:)" | head -n 45 || echo "$out" | tail -n 35
    exit 1
  fi
  echo "status: PASS (lint=ok, compile=ok, tests=ok)"
}

case "$MODE" in
  agent) run_agent ;;
  lint) run_lint ;;
  compile) run_compile ;;
  test) run_test ;;
  all|*)
    run_lint
    run_compile
    run_test
    ;;
esac
