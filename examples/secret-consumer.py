#!/usr/bin/env python3
"""Confirm TEST_TOKEN was injected; never print the value."""

import os
import sys

if not os.environ.get("TEST_TOKEN"):
    print("TEST_TOKEN received: no")
    sys.exit(1)
print("TEST_TOKEN received: yes")
