#!/bin/bash
# Mutation Testing Progress Monitor
# Usage: ./scripts/mutmut-monitor.sh [delay_seconds]

set -e

DELAY=${1:-120}
TOTAL=2774

cd /workspaces/sliver-nxc-module

echo "Waiting ${DELAY}s for mutation testing to generate results..."
sleep "$DELAY"

echo "=== Mutation Testing Progress ==="
KILLED=$(poetry run mutmut results --all=true 2>&1 | grep -c ': killed' || echo 0)
SURVIVED=$(poetry run mutmut results --all=true 2>&1 | grep -c ': survived' || echo 0)
NOTESTS=$(poetry run mutmut results --all=true 2>&1 | grep -c ': no tests' || echo 0)
NOTCHECKED=$(poetry run mutmut results --all=true 2>&1 | grep -c ': not checked' || echo 0)

echo "Killed:      $KILLED"
echo "Survived:    $SURVIVED"
echo "No tests:    $NOTESTS"
echo "Not checked: $NOTCHECKED"
echo "Total:       $TOTAL"
echo "Kill Rate:   $(awk "BEGIN {printf \"%.2f\", $KILLED * 100 / $TOTAL}")%"
echo "Checked:     $(awk "BEGIN {printf \"%.2f\", ($KILLED + $SURVIVED + $NOTESTS) * 100 / $TOTAL}")%"

if [ "$NOTCHECKED" -eq 0 ]; then
  echo "=== COMPLETE ==="
fi
