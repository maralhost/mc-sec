#!/usr/bin/env bash
# Runs every MC-Sec test suite (PHP 8.3 with pdo_sqlite, mbstring, openssl).
#   bash tests/run.sh                 all suites
#   bash tests/run.sh flow_test.php   one suite
set -u
cd "$(dirname "$0")"
PHP=${PHP:-php}
SUITES=(core_test.php credits_test.php flow_test.php engines_test.php security_test.php pages_test.php)
if [ $# -gt 0 ]; then SUITES=("$@"); fi
FAILED=0
for t in "${SUITES[@]}"; do
  start=$(date +%s)
  out=$("$PHP" "$t" 2>&1)
  last=$(printf '%s\n' "$out" | grep -E "PASSED|FAILED|Fatal|Uncaught" | tail -1)
  printf '%-20s %-26s %ss\n' "$t" "${last:-no result}" "$(( $(date +%s) - start ))"
  if ! printf '%s' "$last" | grep -q PASSED || printf '%s' "$out" | grep -qE "PHP Warning|Deprecated|Notice"; then
    FAILED=$((FAILED + 1))
    printf '%s\n' "$out" | grep -E "FAIL|Fatal|Uncaught|Warning|Deprecated|Notice|Error" | head -20 | sed 's/^/    /'
  fi
done
echo
if [ $FAILED -eq 0 ]; then echo "ALL GREEN"; else echo "$FAILED suite(s) failed"; fi
exit $FAILED
