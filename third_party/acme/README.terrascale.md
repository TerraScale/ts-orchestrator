# Pinned ACME client source

This directory copies the `acme` package from `golang.org/x/crypto` at
`v0.58.0`, the version required by the root module. The upstream tag resolves
to commit `8fdf07b3114278fb3b78c1cf1814e08bd851eb4c`. The module archive checksum
is `h1:COkYLr4k7nDI4r6QtMML2AfzeIswWHAJthLS6K/M/54=`. The BSD-style upstream
`LICENSE`, package-root layout, filenames and upstream comments are retained.
The five production files are `acme.go`, `http.go`, `jws.go`, `rfc8555.go` and
`types.go`. Upstream tests, the separate `autocert` package and internal probe
and test helpers are omitted: this is a copy of the client package, not of the
whole cryptography module. There is no nested module or module replacement.
Import it as `github.com/TerraScale/ts-orchestrator/third_party/acme`.

Existing production imports of `golang.org/x/crypto/acme` and
`golang.org/x/crypto/acme/autocert` in `internal/edge/edge.go` remain untouched.
Nothing in production imports this copy yet. Existing ordering behavior and
the root module requirement are unchanged.

## Local changes and specification

The normative references were read on 2026-11-13:
[RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html) and
[RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html).

| File | Addition and reason | Specification |
| --- | --- | --- |
| `acme.go`, `types.go` | Decode and expose `Directory.RenewalInfoURL` to discover ARI support. | RFC 9773 §3 |
| `ari.go` | `CertificateID` combines unpadded base64url AKI keyIdentifier and DER serial INTEGER value, separated by a dot. Preserve the positive INTEGER's sign-padding byte; reject absent AKI, absent serial and nonpositive serial. | RFC 9773 §4.1; RFC 5280 §4.1.2.2 |
| `ari.go` | `Client.RenewalInfo` issues one unauthenticated GET and returns the suggested start/end and optional explanation URL. `ErrRenewalInfoNotSupported` identifies a directory without ARI. | RFC 9773 §§3, 4.1, 4.2 |
| `ari.go` | Preserve the exact `Retry-After` header and expose an absolute `RetryAfter` deadline, parsing delta-seconds and HTTP-date. Reject missing, invalid and overflowing values. Return authority problem documents through the existing `*Error` decoder. | RFC 9773 §§4.3, 4.3.2, 4.3.3; RFC 9110 §10.2.3; RFC 8555 §6.7 |
| `ari.go` | Reject expired-certificate queries; callers must avoid queries for certificates they consider replaced. | RFC 9773 §4.3 |
| `ari.go` | Reject invalid JSON, oversized bodies, missing/null window fields, invalid timestamps, empty/reversed windows and windows outside the supplied certificate's validity, including implausibly distant dates. | RFC 9773 §§4.2, 4.3.3; certificate-validity bounds, strict positive window length and the 1 MiB response limit are local validation policy, beyond RFC requirements |
| `ari.go`, `rfc8555.go` | `WithOrderReplaces` includes the predecessor identifier only when explicitly requested. Reject an empty identifier or an ARI-unaware directory before sending a new order. Existing `c.post` surfaces rejection status, problem type, detail and headers, including `alreadyReplaced` and unknown-certificate errors. | RFC 9773 §§5, 7.4; RFC 8555 §§6.7, 7.4 |
| `types.go`, `rfc8555.go` | Expose and decode `Order.Replaces` in the creation response and subsequent order retrieval. | RFC 9773 §5; RFC 8555 §7.1.3 |

`http.go` and `jws.go` are byte-for-byte upstream. Existing requests omit
`replaces` unless the new option is used. ARI GETs do not use POST-as-GET,
require no account key and perform no internal retry or sleep. The API reports
the server's requested checking deadline without silently changing it. It
does not choose a renewal time, schedule another check, enforce a minimum or
maximum checking interval, store replacement state or create orders on its
own. A future consumer must implement the scheduling, bounded intervals and
error backoff required by RFC 9773 §§4.2–4.3.3.

## Authority documentation

Read on 2026-11-13:

- [Let's Encrypt upcoming features, ARI](https://letsencrypt.org/upcoming-features/#acme-renewal-information-ari)
  says suggested renewal windows are available for all issued certificates and
  links RFC 9773.
- [Let's Encrypt rate limits, ARI renewals](https://letsencrypt.org/docs/rate-limits/#ari-renewals)
  documents exemption from all rate limits for ARI renewals, with at least one
  matching identifier and a certificate not previously replaced through ARI.
- [Let's Encrypt's ARI implementation guide](https://letsencrypt.org/2024/04/25/guide-to-integrating-ari-into-existing-acme-clients/)
  describes the same identifier, GET and `replaces` mechanisms. Its sample
  identifier helper still cites draft-03 and slices a DER serial at a fixed
  two-byte header. This copy uses the final RFC and constructs the INTEGER
  value without assuming a DER length-header size. The guide additionally
  states that exemption requires renewal within the suggested window; the
  current rate-limit page does not explicitly state that timing condition.
  This capability-only change makes no decision about exemption or renewal time.
- [Boulder divergences](https://github.com/letsencrypt/boulder/blob/main/docs/acme-divergences.md)
  and [implementation details](https://github.com/letsencrypt/boulder/blob/main/docs/acme-implementation_details.md)
  list no ARI-specific divergence. This is documentation evidence, not proof
  of live-authority behavior. No real authority is contacted by the journey.

## Proof and source qualification

`test/e2e/m1/certificates/ari` extracts the ACME HTTP/JWS envelope, directory,
nonce, new-order, order-response and problem-response patterns from the
certificates journey's stand-in authority. It adds ARI GETs, independent
certificate DER/AKI identifier derivation, ES256 signature and nonce checks,
replacement tracking and response cases. Only this protocol subset is needed;
the certificates journey's node, process and infrastructure helpers are not
included. The `acme-ari` CI matrix entry builds and runs it through
`test/e2e/m1/acme-ari.sh`. There is no public ARI test-server image in the
repository's existing lanes.

The proof checks the RFC identifier example and positive serials on both sides
of the sign-padding boundary; the returned window and explanation; exact
delta-seconds and HTTP-date checking deadlines; no immediate extra GET; a
normal order without ARI; the unsupported-directory error and absence of a
replacement request; a signed replacement accepted once and reflected on order
retrieval; surfaced unknown-certificate and HTTP 409 `alreadyReplaced` errors;
and rejection of missing/null fields, invalid timestamps, reversed/empty or
out-of-validity windows, invalid Retry-After and invalid/expired certificates.
It proves deadline propagation, not the scheduling of a future renewal.

Run the proof with `go run ./test/e2e/m1/certificates/ari` from the root module.
`scripts/ci/audit-replacements.py` retains a separate package-copy baseline
alongside the existing module-replacement baselines. It binds every tracked
file here, including these notes and the license, to a reviewed source digest;
checks that the selected upstream module is still the pinned version without
a replacement; and queries OSV for that upstream version. Package-copy
qualification considers an advisory applicable unless its affected import
metadata places it entirely outside the copied `golang.org/x/crypto/acme`
package. It prints the full response and every package-scope decision; missing
scope metadata fails closed. For example, GO-2026-5932 concerns the omitted
OpenPGP packages. Whole-module replacement checks retain their existing
module-wide advisory policy. The existing
`scripts/ci/audit-dependencies.sh` source scan also includes this package in the
root module's package graph; its release scan continues to inspect actual
release binaries. Existing CI runs both scans; no Makefile target is needed.

## Updating

Download the root module's selected `golang.org/x/crypto` archive with
`go mod download -json golang.org/x/crypto@<version>`. Verify its module checksum
and tag commit. Compare this directory's five upstream files with the
archive's `acme/` package, reapply only the changes listed above, retain the
license and omit upstream tests/subpackages. Review RFC and authority-document
changes, and remove the copy when an upstream release provides the required
capabilities and its consumers can migrate.

After reviewing the complete patch, stage the directory and use
`source_digest(ROOT, "third_party/acme")` from
`scripts/ci/audit-replacements.py` to update its `PACKAGE_BASELINES` digest.
Update the version, commit, checksum and these notes together. Run the ARI
lane, `go vet ./...` and the existing dependency qualification before pushing.
