#!/usr/bin/env node
// Confirm TEST_TOKEN was injected; never print the value.
if (!process.env.TEST_TOKEN) {
  console.log("TEST_TOKEN received: no");
  process.exit(1);
}
console.log("TEST_TOKEN received: yes");
