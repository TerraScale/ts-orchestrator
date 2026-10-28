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

## Cloudflare: use the `cf` CLI
The Cloudflare CLI `cf` (npm package `cf`, v1.0.0-beta.10, installed through the mise Node toolchain) is installed and logged in on all 3 T3 hosts (delta, beta, mariogk-dev) as `mariogk01@gmail.com`, whose account owns the `terrascale.tech` zone.
- Use `cf` for Cloudflare work: DNS records, zones, origin CA / client certificates, SSL/TLS and cache settings, rules, analytics, API tokens. Workers deploys keep using `wrangler`.
- Before you start, run `cf auth whoami`. It must show `"authenticated": true`.
- Never print tokens or the config file. Print the plan before you change anything. Deleting zones, production DNS records or Workers needs the user's confirmation. Record changed Cloudflare object IDs (not secrets) in the PR or runbook.

## Zero configuration (user decision 2026-10-09, do not revert)

- Every feature is always on. No feature flags, on/off variables, opt-in settings, boolean enabled configuration keys, deploy toggles or kill switches in code, config or CI. Delete switches and their guarded paths.
- Every region always serves. NetBird network membership admits a node automatically; it discovers every region, infers its own region from where it runs and starts serving without a per-region enable step.
- OCI Vault automatically creates, delivers and configures every first-party production secret. Vendor-issued keys (such as Stripe and Cloudflare) are stored once in Vault and picked up automatically; nobody copies secrets by hand.
- Values have one correct setting in code. Expose no tuning knobs. Fakes, demo stores and skip-auth belong only in test code and test binaries.
- CI rejects new switch-style configuration. Only unavoidable third-party names may have a narrow allowance with a one-line reason.

Discover NetBird members, regions, placement and releases automatically; create and deliver each service's production credentials through OCI Vault.
