// A deliberately insecure JavaScript file used to demonstrate JS security_scan.
// It contains NO real secrets — only patterns eslint-plugin-security flags.

import cp from "node:child_process";

export function run(userInput) {
  // Passing user input to a shell command invites command injection.
  cp.exec("ls " + userInput); // security/detect-child-process

  // eval on a dynamic expression executes arbitrary code.
  eval(userInput); // security/detect-eval-with-expression
}
