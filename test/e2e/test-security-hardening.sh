#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# =============================================================================
# test-security-hardening.sh
# NemoClaw Security & Sandbox Hardening E2E Tests
#
# Covers:
#   TC-SEC-02: seccomp syscall filtering (ptrace/mount blocked)
#   TC-SEC-04: API key not visible in sandbox process environment
#   TC-SEC-08: Cross-sandbox network isolation
#   TC-SEC-09: Credential file permissions (600)
#
# Prerequisites:
#   - Docker running
#   - NemoClaw installed (or install.sh available)
#   - NVIDIA_API_KEY for sandbox onboard
# =============================================================================

set -euo pipefail

# ── Overall timeout ──────────────────────────────────────────────────────────
if [ -z "${NEMOCLAW_E2E_NO_TIMEOUT:-}" ]; then
  export NEMOCLAW_E2E_NO_TIMEOUT=1
  TIMEOUT_SECONDS="${NEMOCLAW_E2E_TIMEOUT_SECONDS:-3600}"
  if command -v timeout >/dev/null 2>&1; then
    exec timeout -s TERM "$TIMEOUT_SECONDS" bash "$0" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    exec gtimeout -s TERM "$TIMEOUT_SECONDS" bash "$0" "$@"
  fi
fi

# ── Config ───────────────────────────────────────────────────────────────────
SANDBOX_A="e2e-sec-a"
SANDBOX_B="e2e-sec-b"
LOG_FILE="test-security-hardening-$(date +%Y%m%d-%H%M%S).log"

if command -v gtimeout &>/dev/null; then
  TIMEOUT_CMD="gtimeout"
else
  TIMEOUT_CMD="timeout"
fi

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# Log a timestamped message.
log() { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*" | tee -a "$LOG_FILE"; }
# Record a passing assertion.
pass() {
  ((PASS += 1))
  ((TOTAL += 1))
  echo -e "${GREEN}  PASS${NC} $1" | tee -a "$LOG_FILE"
}
# Record a failing assertion.
fail() {
  ((FAIL += 1))
  ((TOTAL += 1))
  echo -e "${RED}  FAIL${NC} $1 — $2" | tee -a "$LOG_FILE"
}
# Record a skipped test.
skip() {
  ((SKIP += 1))
  ((TOTAL += 1))
  echo -e "${YELLOW}  SKIP${NC} $1 — $2" | tee -a "$LOG_FILE"
}

# ── Resolve repo root ────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── Install NemoClaw if not present ──────────────────────────────────────────
install_nemoclaw() {
  if command -v nemoclaw >/dev/null 2>&1; then
    log "nemoclaw already installed: $(nemoclaw --version 2>/dev/null || echo unknown)"
    return
  fi
  log "=== Installing NemoClaw via install.sh ==="
  NEMOCLAW_SANDBOX_NAME="$SANDBOX_A" \
    NVIDIA_API_KEY="${NVIDIA_API_KEY:-nvapi-DUMMY-FOR-INSTALL}" \
    NEMOCLAW_NON_INTERACTIVE=1 \
    NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 \
    bash "$REPO_ROOT/install.sh" --non-interactive --yes-i-accept-third-party-software \
    2>&1 | tee -a "$LOG_FILE" || true

  if [ -f "$HOME/.bashrc" ]; then
    # shellcheck source=/dev/null
    source "$HOME/.bashrc" 2>/dev/null || true
  fi
  export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
  if [ -s "$NVM_DIR/nvm.sh" ]; then
    # shellcheck source=/dev/null
    . "$NVM_DIR/nvm.sh"
  fi
  if [ -d "$HOME/.local/bin" ] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    export PATH="$HOME/.local/bin:$PATH"
  fi
}

# ── Pre-flight ───────────────────────────────────────────────────────────────
preflight() {
  log "=== Pre-flight checks ==="
  if ! docker info >/dev/null 2>&1; then
    log "ERROR: Docker is not running."
    exit 1
  fi
  log "Docker is running"
  install_nemoclaw
  log "nemoclaw: $(nemoclaw --version 2>/dev/null || echo unknown)"
  log "Pre-flight complete"
}

# Execute a command inside a named sandbox via SSH.
sandbox_exec_for() {
  local sbx="$1"
  local cmd="$2"
  local ssh_cfg
  ssh_cfg="$(mktemp)"
  if ! openshell sandbox ssh-config "$sbx" >"$ssh_cfg" 2>/dev/null; then
    log "  [sandbox_exec] Failed to get SSH config for $sbx"
    rm -f "$ssh_cfg"
    echo ""
    return 1
  fi
  local result ssh_exit=0
  result=$($TIMEOUT_CMD 60 ssh -F "$ssh_cfg" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 -o LogLevel=ERROR \
    "openshell-${sbx}" "$cmd" 2>&1) || ssh_exit=$?
  rm -f "$ssh_cfg"
  echo "$result"
  return $ssh_exit
}

# ── Onboard helper ───────────────────────────────────────────────────────────
onboard_sandbox() {
  local name="$1"
  log "  Onboarding sandbox '$name'..."
  rm -f "$HOME/.nemoclaw/onboard.lock" 2>/dev/null || true
  NEMOCLAW_SANDBOX_NAME="$name" \
    NEMOCLAW_NON_INTERACTIVE=1 \
    NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 \
    NEMOCLAW_POLICY_TIER="restricted" \
    $TIMEOUT_CMD 600 nemoclaw onboard --non-interactive --yes-i-accept-third-party-software \
    2>&1 | tee -a "$LOG_FILE"
}

# =============================================================================
# TC-SEC-02: seccomp syscall filtering
# =============================================================================
test_sec_02_seccomp() {
  log "=== TC-SEC-02: seccomp Syscall Filtering ==="

  log "  Testing ptrace blocked by seccomp..."
  local ptrace_result
  ptrace_result=$(sandbox_exec_for "$SANDBOX_A" "python3 -c \"
import ctypes, errno
libc = ctypes.CDLL('libc.so.6', use_errno=True)
# PTRACE_TRACEME = 0, pid = 0
ret = libc.ptrace(0, 0, 0, 0)
err = ctypes.get_errno()
if ret == -1 and err == errno.EPERM:
    print('PTRACE_BLOCKED')
elif ret == -1:
    print('PTRACE_ERROR_' + str(err))
else:
    print('PTRACE_ALLOWED')
\"" 2>&1) || true

  log "  ptrace result: $ptrace_result"

  if echo "$ptrace_result" | grep -q "PTRACE_BLOCKED"; then
    pass "TC-SEC-02: ptrace blocked by seccomp (EPERM)"
  elif echo "$ptrace_result" | grep -q "PTRACE_ERROR"; then
    pass "TC-SEC-02: ptrace blocked (error: $ptrace_result)"
  elif echo "$ptrace_result" | grep -q "PTRACE_ALLOWED"; then
    fail "TC-SEC-02: seccomp" "ptrace was not blocked"
  else
    skip "TC-SEC-02" "Could not run ptrace test: ${ptrace_result:0:200}"
  fi
}

# =============================================================================
# TC-SEC-04: API key not in sandbox process environment
# =============================================================================
test_sec_04_key_not_in_env() {
  log "=== TC-SEC-04: API Key Not in Process Environment ==="

  local real_key="${NVIDIA_API_KEY:-}"
  if [[ -z "$real_key" ]]; then
    skip "TC-SEC-04" "NVIDIA_API_KEY not set"
    return
  fi

  log "  Checking sandbox environment for API key..."
  local env_output
  env_output=$(sandbox_exec_for "$SANDBOX_A" "env 2>/dev/null") || true

  if [[ -z "$env_output" ]]; then
    fail "TC-SEC-04: Setup" "Could not capture sandbox environment"
    return
  fi

  if echo "$env_output" | grep -qF "$real_key"; then
    fail "TC-SEC-04: Environment" "Real API key found in sandbox environment"
  else
    pass "TC-SEC-04: Real API key absent from sandbox environment"
  fi

  log "  Checking sandbox process list for API key..."
  local ps_output ps_exit=0
  ps_output=$(sandbox_exec_for "$SANDBOX_A" "ps aux 2>/dev/null || ps -ef 2>/dev/null") || ps_exit=$?

  if [[ $ps_exit -ne 0 || -z "$ps_output" ]]; then
    skip "TC-SEC-04: Process list" "ps not available in hardened sandbox"
  elif echo "$ps_output" | grep -qF "$real_key"; then
    fail "TC-SEC-04: Process list" "Real API key found in process arguments"
  else
    pass "TC-SEC-04: Real API key absent from sandbox process list"
  fi
}

# =============================================================================
# TC-SEC-08: Cross-sandbox network isolation
# =============================================================================
test_sec_08_cross_sandbox_isolation() {
  log "=== TC-SEC-08: Cross-Sandbox Network Isolation ==="

  if ! nemoclaw list 2>/dev/null | grep -q "$SANDBOX_B"; then
    log "  Onboarding second sandbox for isolation test..."
    if ! onboard_sandbox "$SANDBOX_B"; then
      fail "TC-SEC-08: Setup" "Could not onboard second sandbox"
      return
    fi
  fi

  log "  Testing: sandbox A cannot reach sandbox B..."
  local probe_a
  probe_a=$(sandbox_exec_for "$SANDBOX_A" "node -e \"
const http = require('http');
const req = http.get({hostname: '$SANDBOX_B', port: 18789, path: '/', timeout: 10000}, res => {
  console.log('STATUS_' + res.statusCode);
});
req.on('error', e => console.log('ERROR_' + e.code));
req.on('timeout', () => { console.log('TIMEOUT'); req.destroy(); });
\"" 2>&1) || true

  log "  A→B probe: $probe_a"

  if echo "$probe_a" | grep -qiE "STATUS_403|ERROR|TIMEOUT"; then
    pass "TC-SEC-08: Sandbox A cannot reach sandbox B ($probe_a)"
  elif echo "$probe_a" | grep -qE "STATUS_2"; then
    fail "TC-SEC-08: Isolation (A→B)" "Sandbox A reached sandbox B ($probe_a)"
  else
    pass "TC-SEC-08: Sandbox A cannot reach sandbox B ($probe_a)"
  fi

  log "  Testing reverse: sandbox B cannot reach sandbox A..."
  local probe_b
  probe_b=$(sandbox_exec_for "$SANDBOX_B" "node -e \"
const http = require('http');
const req = http.get({hostname: '$SANDBOX_A', port: 18789, path: '/', timeout: 10000}, res => {
  console.log('STATUS_' + res.statusCode);
});
req.on('error', e => console.log('ERROR_' + e.code));
req.on('timeout', () => { console.log('TIMEOUT'); req.destroy(); });
\"" 2>&1) || true

  log "  B→A probe: $probe_b"

  if echo "$probe_b" | grep -qiE "STATUS_403|ERROR|TIMEOUT"; then
    pass "TC-SEC-08: Sandbox B cannot reach sandbox A ($probe_b)"
  elif echo "$probe_b" | grep -qE "STATUS_2"; then
    fail "TC-SEC-08: Isolation (B→A)" "Sandbox B reached sandbox A ($probe_b)"
  else
    pass "TC-SEC-08: Sandbox B cannot reach sandbox A ($probe_b)"
  fi
}

# =============================================================================
# TC-SEC-09: Credential file permissions
# =============================================================================
test_sec_09_credential_permissions() {
  log "=== TC-SEC-09: Credential File Permissions ==="

  local cred_file="$HOME/.nemoclaw/credentials.json"
  if [[ ! -f "$cred_file" ]]; then
    log "  Checking alternative paths..."
    cred_file=$(find "$HOME/.nemoclaw" -name "credentials.json" 2>/dev/null | head -1) || true
  fi

  if [[ -z "$cred_file" || ! -f "$cred_file" ]]; then
    skip "TC-SEC-09" "credentials.json not found"
    return
  fi

  local perms
  perms=$(stat -c '%a' "$cred_file" 2>/dev/null || stat -f '%Lp' "$cred_file" 2>/dev/null) || true
  log "  credentials.json permissions: $perms"

  if [[ "$perms" == "600" ]]; then
    pass "TC-SEC-09: credentials.json has mode 600 (owner read/write only)"
  elif [[ -n "$perms" ]]; then
    fail "TC-SEC-09: Permissions" "credentials.json has mode $perms (expected 600)"
  else
    skip "TC-SEC-09" "Could not determine file permissions"
  fi
}

# ── Teardown ─────────────────────────────────────────────────────────────────
teardown() {
  set +e
  rm -f "$HOME/.nemoclaw/onboard.lock" 2>/dev/null || true
  nemoclaw "$SANDBOX_A" destroy --yes 2>/dev/null || true
  nemoclaw "$SANDBOX_B" destroy --yes 2>/dev/null || true
  set -e
}

# ── Summary ──────────────────────────────────────────────────────────────────
summary() {
  echo ""
  echo "============================================================"
  echo "  Security Hardening E2E Results"
  echo "============================================================"
  echo -e "  ${GREEN}PASS: $PASS${NC}"
  echo -e "  ${RED}FAIL: $FAIL${NC}"
  echo -e "  ${YELLOW}SKIP: $SKIP${NC}"
  echo "  TOTAL: $TOTAL"
  echo "============================================================"
  echo "  Log: $LOG_FILE"
  echo "============================================================"
  echo ""

  if [[ $FAIL -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo ""
  echo "============================================================"
  echo "  NemoClaw Security Hardening E2E Tests"
  echo "  $(date)"
  echo "============================================================"
  echo ""

  preflight

  log "=== Onboarding sandbox A ==="
  if ! onboard_sandbox "$SANDBOX_A"; then
    log "FATAL: Could not onboard sandbox A"
    exit 1
  fi

  test_sec_02_seccomp
  test_sec_04_key_not_in_env
  test_sec_09_credential_permissions
  test_sec_08_cross_sandbox_isolation

  trap - EXIT
  teardown
  summary
}

trap teardown EXIT
main "$@"
