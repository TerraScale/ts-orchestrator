# Supply-chain candidate validator

This standard-library-only validator checks the Phase 0 candidate manifest without downloading or executing any candidate tool.

```text
python3 tools/phase0/supply-chain/validate_supply_chain_pins.py
python3 -m unittest discover -s tools/phase0/supply-chain -p 'test_*.py' -v
```

It fails closed on floating versions, non-primary or non-versioned sources, missing Linux architecture coverage, absent mirrors/gaps, any production-qualification claim, or any artifact/evidence/attestation signing selection. It also binds the current `global.json`, central TUnit declaration, TUnit/Microsoft.Testing.Platform lock resolution and content hashes, and every checked-in NuGet lock-file SHA-256. The negative fixture corpus is data-driven and contains only synthetic markers.
