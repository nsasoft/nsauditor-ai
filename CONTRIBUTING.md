# Contributing to NSAuditor AI

All contributions to this repository are licensed under the MIT license
(Developer Certificate of Origin — DCO).

## How to Contribute

1. Fork the repo and create a feature branch
2. Add a `Signed-off-by` line to your commits: `git commit -s`
3. Include tests for any new or changed behavior (Node.js `--test` runner)
4. Submit a PR

## Plugin Contributions

Follow the plugin interface in `plugins/` — each plugin exports:
- `default` object with `id`, `name`, `priority`, `requirements`, `run()`
- `conclude({ result, host })` adapter for Result Concluder
- Optional `authoritativePorts` Set

## What We Won't Accept

- Code that transmits scan data externally (violates Zero Data Exfiltration)
- Phone-home, analytics, or usage tracking
- Dependencies that weaken the offline-first guarantee
