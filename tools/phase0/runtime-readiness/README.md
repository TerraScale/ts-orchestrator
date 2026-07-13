# ARM64 runtime readiness validator

Validate the checked-in proposal without contacting a network, starting a service,
or selecting a candidate:

```bash
python3 tools/phase0/runtime-readiness/validate_runtime_readiness.py
python3 -m unittest discover -s tools/phase0/runtime-readiness -p 'test_*.py' -v
```

The validator fails if a host, kernel, filesystem, or runtime becomes selected;
if local x86_64 inspection is represented as ARM64 qualification; if L1R/L4 is
represented as run; if required candidate classes disappear; or if evidence uses
an unknown/non-primary source. Adversarial overlays under `fixtures/` exercise
those fail-closed rules.
