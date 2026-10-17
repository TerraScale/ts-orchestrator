# CI executable-input qualification

Exact 083b609c2 passed ten local Python test methods (19.360 seconds) with Go and GitHub commands stubbed and real local Git. Four shell scripts passed shellcheck; the zero-configuration guard and diff check passed. Eleven source files remained byte-identical before and after the checks. The exact source patch is adopted on the feature branch separately from main.

The change compares executable inputs against the newest complete retained qualified main-ancestor release and validates retained tool bytes before use. Scheduled runs and changed image inputs build the current source. Computed CI decisions add no user configuration switch.

No actual GitHub Actions, API, deployment, network or real Go/crypto integration ran. Actionlint was unavailable. Main remains unchanged; prior main CI results do not qualify this feature.
