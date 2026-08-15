#!/usr/bin/env bash
# Confirm TEST_TOKEN was injected; never print the value.
set -euo pipefail
if [ -z "${TEST_TOKEN:-}" ]; then
    echo 'TEST_TOKEN received: no'
    exit 1
fi
echo 'TEST_TOKEN received: yes'
