#!/bin/bash
# The VM's entry point: run the smoke test, print a sentinel the host can read
# off the serial console, then power down.
#
# It must never leave the VM running, or the host would only learn anything
# when its timeout expired.

readonly RESULT_MARKER="SMOKE-RESULT"

echo "=================== conntrack-exporter package smoke test ==================="

python3 /opt/smoke/vm_smoke.py
status=$?

if [ ${status} -eq 0 ]; then
    echo "${RESULT_MARKER}: PASS"
else
    echo "${RESULT_MARKER}: FAIL (exit ${status})"
    # Whatever the assertions did not already print.
    journalctl -u conntrack-exporter.service --no-pager -n 100 2>/dev/null
fi

echo "============================================================================"

# Flush the console before the kernel stops scheduling us.
sync
sleep 1
systemctl poweroff --no-block 2>/dev/null || poweroff -f
