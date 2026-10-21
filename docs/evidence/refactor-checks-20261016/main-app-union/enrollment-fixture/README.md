# Lower enrollment evidence

Review manifest.json and receipts/92eacab2-runtime-12983.json first. Exact donor 92eacab2 passed the selected lower boundary in 2.38s, zero skips; its wholeAPP fixturetest compile passed. Imported feature union 9012b9c3 also passed its separate whole APP fixturetest compile (receipt 62575). No feature-union runtime repeat is claimed. Feature import mapping is d34fcb90 -> 71203f70 and 92eacab2 -> 9012b9c3; all three relevant files were compared byte-for-byte.

## Qualified lower boundary

1. Genuine signed controller-c seed/Gate and root-signed foundation with SDK Vault support a real paused manager.
2. Public Request/Claim/Register/Issuer.Issue/Response Sign+Verify/Finish CAS produces the actual completed grant, exact receipt and issued scoped JWT/clientcertificate.
3. Current ordered registration, signed spec/adopted roots/full slot ledger and concrete SDK OCI recipient verification agree. A signed changed-expiry response is refused.
4. One actual issued-credential Agent establishes its signed session and verifies the independently read current registration. Grant Disable makes the same current-source composition refuse.
5. Session cancellation joins once; manager stays live/paused and deferred material/registry providers stay closed. No source.bind.

## Retained limits

1. Full RunManagedRuntime, fixed markers/config/baked roots/floor, RestoreMaterial tmpfs/Vault restoration and native bootstrap-admit-restart admission remain unqualified.
2. HTTP enrollment handler, IMDS/fixed credential installation, production session wrapper and serviceUID source child/currentControllerHostReader were not invoked.
3. Production ReadControllerHostBinding/RuntimeInstanceObserver/newOCIAdmissionProvider and HomeIAM/GuardedFactory/full BootstrapMaterial remain outside this fixture.
4. Positive material/registry delivery, containerd/cgroups, production management socket and CLI/image/systemd/live OCI acceptance are not covered. Existing full registry reauthorization and all-static/pool/DATA holds remain.
5. Existing fixture server CA and reused enrollment client CA are separate. Only temporary broker trust joins them; no production single-regional-CA installation claim. Disable asserts current-source refusal, not automatic live-session disconnect.

## History and integrity

Original d34 runtime 57352 failed before Claim at the invalid ts-gru-c descriptor. The one-line 92e correction uses genuine gru-1-ctl-3. Both donor compile receipts, original failure, corrected PASS and separate imported-union compile are retained individually. The prior 582 startup case was not repeated.

Each logs/*.gz uses deterministic gzip mtime 0 and was decompressed and compared byte-for-byte with its original raw log. Receipts retain raw and compressed SHA256 plus exact argv/cwd/redirection. Source snapshots, both diffs and the complete historical handoffs are included. Binaries are referenced by SHA256, not copied.

Run `sha256sum -c SHA256SUMS` from this directory to verify packet files. No runner, build, runtime, cloud operation, host modification or source mutation was started to prepare this packet.

The complete original packet is preserved in `evidence.tar.gz`. Extract it to a temporary directory, then run `sha256sum -c SHA256SUMS` there. Paths mentioned above are inside that archive. The presentation README normalizes trailing Markdown spaces; the archive retains exact originals.
