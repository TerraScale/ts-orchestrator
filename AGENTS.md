AI IS NOT ALLOWED TO EDIT THIS FILE ONLY HUMANS CAN!

# Orchestrator
- This is a tailor made kubernetes alternative specially made for TerraScale
- It needs to manage all of its regions Oracle Cloud resources
- Each region will have its own orchestrator/nats cluster
- Let's use embedded NATS
- Each regions MUST auto form cluster automagically
- The orchestrator MUST scale terrabase up and down as neeeded

# Rules
- Never add AI attribution to commits, PR titles, or PR descriptions: no `Co-Authored-By:` trailers, no `🤖 Generated with [Claude Code]` or similar generated-by notices.
- This project MUST to use GO
- This MUST to be deployed as a single binary to be easy to deployed and updated
- Commit and push often after every major change automatically
- The project must follow a feature sliced design so it is well organized and similar or dependant files and services are kept together

# Libraries
- We should use nats for ts-orchestrator <-> ts-orchestrator comunnication

## Local CPU Priority

- When building or testing locally, run every build, test, lint, and benchmark
  command at low CPU priority by prefixing it with `nice -n 19` (for example
  `nice -n 19 make test-fast`). Local dev servers and watchers count too.
- In CI (`CI=true`) use full CPU priority: do nothing. Never add `nice` or
  `renice` to CI workflows, Makefiles, scripts, or Containerfiles; the low
  priority is applied by whoever runs the command locally.
