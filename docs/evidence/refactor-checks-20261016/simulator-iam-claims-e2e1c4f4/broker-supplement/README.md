# Session 21017 broker observations

Recovered from four saved historical tool transcript records: exact launch call/response and terminal poll call/response. `transcript-excerpt.jsonl` preserves the selected original JSONL line bytes. `broker-observations.json` preserves decoded exact response fields and their line bindings. This is transcript-derived reconstruction, not an original native broker trace file.

Launch response: chunk `9629da`, session `21017`, wall `1.001403873` seconds, empty output. The terminal poll uses session `21017`; response chunk `2135a9` reports actual tool exit `0`, wall `0.000018812` seconds, and wrapper output binding the original receipt and runtime manifest hashes. The child Go runtime wall `2.647788` seconds comes from the original child receipt and is a different measurement. Missing response fields remain absent.

The sealed 37-member archive, its six docs files, all 31 original input bytes/modes/mtimes, and historical QA are unchanged. No runtime, Go, polling or repackaging occurred. The supplement establishes tool-session observations; it adds no NATS, Oracle-issued trust, production transport or other runtime qualification. HOLD for separate review and publication.
