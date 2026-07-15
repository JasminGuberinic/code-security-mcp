// A deliberately insecure TypeScript file for demonstrating TS security_scan.
// No real secrets — only a pattern eslint-plugin-security flags.

import cp from "node:child_process";

export function run(userInput: string): void {
  // User input in a shell command → command injection.
  cp.exec("ls " + userInput); // security/detect-child-process
}
