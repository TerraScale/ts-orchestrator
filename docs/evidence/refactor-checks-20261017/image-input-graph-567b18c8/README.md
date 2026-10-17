# Image input graph detector

The image rebuild detector now follows imported source and embedded assets for Linux amd64 and arm64, pinned file inputs and module changes. Deleted or renamed inputs trigger rebuilding. Graph/pin read failures build conservatively; only a completed image release provides a comparison baseline.

Exact source `567b18c88d10016ff1b6d70fa9798e1e64d910bb` is adopted byte for byte as `b37d70d45`. Five Python methods passed in 5.114 seconds, covering 16 source-counted disposable Git scenarios with stub Go/GitHub commands. Pinned shellcheck and diff whitespace checks exited zero. Source and tool hashes match before/after. The CI guard includes the same unittest discovery invocation; no CI run was dispatched.

The enclosing login shell returned one after the Python process exited zero and source posthash completed: `/etc/bash_logout:4` read an unset variable. That separate harness postcheck failure is retained. Python was not rerun; the independent remaining checks ran once with a non-login shell and passed.

These direct copies preserve raw logs, exact command arguments, markers and hashes. They establish local fixture outcomes, not a live image build, provider operation or full repository qualification. `adoption-review.json` records the scope. No archive was created.
