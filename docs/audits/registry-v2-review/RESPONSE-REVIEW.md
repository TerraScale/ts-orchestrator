# Re-review of steward response `7893b82`

Reviewed commit: `7893b82f104284a7c8a6cec40b617a86af7889f5`.

## Conclusion

The response materially improves the draft registry and closes the exact original
owner/layer, invalid-co-reviewer, one-character statement/target, and root-version
mutations covered by its five new fixtures. It does **not** fully close C2–C6.
The new checks are useful Phase 0 guardrails, but string length and substring tests
must not be described as semantic or evidence-identity validation.

| Original issue | Result | Evidence and remaining action |
|---|---|---|
| C2 audit/registry parity | **Partially closed** | Owner and ordered acceptance-layer parity are now checked. Mutating `AUD-ID-001.kind` from `requirement` to `security` is still accepted because `finding.kind` is ignored. Validate finding kind against both the ID-derived kind and registry kind. If ordered layers are intentional, document it; otherwise compare a duplicate-free set. |
| C3 co-reviewers | **Partially closed** | Canonicality, uniqueness, and primary-owner exclusion are checked, and the five named cross-lane entries were populated. Removing `coReviewers` from a registry entry is still accepted by the Python checker because absence becomes `[]`. Require the field explicitly in the parser/schema. The response also does not represent co-review approval/provenance, so populated names are routing metadata, not review evidence. |
| C4 evidence targets | **Not closed** | Replacing the first target with `L0 placeholder target` is accepted. Length plus containment of the layer token remains an opaque string/count check; for example `L0` is also a substring of `L0C`. Use structured targets with an exact layer field, stable scenario/test ID, artifact identity, producer, candidate digest, and status; validate uniqueness and exact layer coverage. |
| C5 root metadata | **Partially closed, with lifecycle regressions** | The exact original schema/status/vocabulary mutations are rejected, and C# now types the fields. Python accepts an unknown root field and accepts duplicate contradictory `status: draft` / `status: frozen` keys because it searches only the first textual match. Conversely, semantically equivalent YAML spacing is rejected. Most importantly, removing question 1 after it is answered is rejected because `[1..10]` is hard-coded. Parse one root mapping, reject duplicate/unknown keys according to an explicit schema, validate types/sets semantically, and allow the unresolved-question set to shrink under a recorded decision. Model freeze preconditions separately from forcing `status: draft` forever. |
| C6 semantic quality | **Not closed** | `xxxxxxxxxxxxxxxxxxxx` is accepted as a normative statement. The 20-character threshold closes only the supplied `"x"` fixture; it does not establish fidelity or range completeness. Source commit/document identity and truncated-but-still-containing-range tests remain absent. Keep semantic review provenance and source-revision binding as freeze requirements. |

## Additional observations

- **Confirmed improvement:** both validators now agree on canonical co-reviewer shape,
  root field values for the current draft, statement minimum length, and the current
  layer/target positional convention.
- **Confirmed inconsistency risk:** Python performs root validation with regular
  expressions while C# deserializes YAML. The two validators therefore do not share
  duplicate-key, unknown-key, or formatting semantics.
- **Recommendation:** replace the five heuristic fixtures with adversarial pairs:
  invalid and valid-evolved root documents, missing versus explicitly empty
  co-reviewers, mismatched audit kind, `L0C` used for `L0`, duplicate layers/targets,
  opaque 20-character strings, and a truncated normative range that still contains
  the marker.
- **Recommendation:** retain all evidence states as `missing`. Nothing in this
  response creates an evidence artifact or supports contract freeze.

## Verification

Executed in a detached worktree at exactly `7893b82`:

- `python3 docs/audits/registry/check_registry_audit.py --negative-fixtures docs/audits/registry/fixtures/negative-cases.json` — PASS, 43 registry entries, 86 findings, 15 fixtures.
- `dotnet restore TerraScale.Orchestrator.slnx --locked-mode` — PASS.
- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — PASS, zero warnings/errors.
- `dotnet test TerraScale.Orchestrator.slnx --no-build` — PASS, 4/4 tests.

Controlled in-memory Python validations (no canonical file edits):

- mismatched semantic audit `kind` — incorrectly accepted;
- omitted `coReviewers` — incorrectly accepted;
- opaque `L0 placeholder target` — incorrectly accepted;
- unknown root field — accepted;
- duplicate contradictory root status — incorrectly accepted;
- semantically equivalent unresolved-question list spacing — incorrectly rejected;
- removing an answered question — incorrectly rejected;
- vacuous 20-character normative statement — incorrectly accepted.
