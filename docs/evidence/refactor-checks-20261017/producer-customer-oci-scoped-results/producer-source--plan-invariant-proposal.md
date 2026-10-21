# Foundation preparation: complete plan-boundary source review

Candidate reviewed read-only: `3e5036a77cfc32199ba14de01130bd2abe0de7f8`, tree `cc5e0ebf5db249a8a760db39c11dc22c3c708981`. No Go command or source mutation was used for this diagnosis. This is a static review, not a claim that the next runtime passes.

## Observed failure and retained evidence

The exact one-attempt Short-B run compiled, returned five individual refusal passes, then failed preparation at `foundation_preparation_integration_test.go:203`: `validate prepared GRU OCI plan: manual host architecture must be arm64 or amd64`. Its eleven preparation leaves did not execute. Elapsed 153.19788199901814 seconds; maximum child RSS 1,072,184 KiB; all source/tool/request/audit pre/post identities match. Short-B released, no retry.

Evidence directory `/tmp/ts-foundation-producer-3e50-shortb-runner-o5gpatg8`: receipt SHA256 `1b6bee62973c99b57dc90011c7b3abb6d41a7125d54246f565758797490e9c03`, final seal SHA256 `d7ab802c21f351e93938b9309916d3210609dabf05a898f5008e596eb36a61d6`, FINAL-SHA256SUMS SHA256 `c1d746c9f3efd8473cf38d1a69d31f10626e3b70ceea033917d7368b7b0038f9`. All nine actual native verification/launch/poll/terminal results are retained.

## Exact producer/consumer chain

`deploy/oci-region/template.go` embeds `sfo-1-plan.json`; `region.PrepareFoundationGrant` decodes it and calls `deriveFoundation` in `region/plan.go`, then constructs signed startup/material, keeps only funded controller-a, and calls `ociregion.ValidatePlan`. The SDK producer calls this shared pure producer with real SDK catalog facts. Public `region.Derive` also uses `deriveFoundation` for non-home regions, with host topology retained. There is no `BuildPlan` declaration/call in this exact source.

`ociregion.ValidatePlan` copies the plan before validating. Its hostArchitecture helper requires an explicit arm64/amd64 value; inventory pricing also calls the same helper. The embedded JSON has fixed A1 shapes but no architecture. Existing OCI donor `55a64f57126fd7f4dc8f8336cf147c6af635157b` adds explicit ARM64 host architectures and exact existing-operations-host expected shape/architecture to the three active JSON plans. OCI owns its coherent integration. No architecture inference from shape or default in validation is proposed.

## Three concrete mismatches found before the next run

1. Missing architecture is a production template prerequisite, repaired by exact owner donor55a. It must not be patched only in the fixture or by weakening hostArchitecture.
2. The production producer retains one funded host but leaves all three public API backend names from the template. validatePublic permits only planned hosts. Home naming adds another distinction: `naming.RegionCell("GRU").ControllerSlot("controller-a")` is `gru-1-ctl-1`, while blind template renaming leaves `ts-gru-1`. SFO/FRA names are `ts-sfo-1` and `ts-fra-1`. Derive the backend from the exact funded first host through the naming library, rather than truncating the old strings.
3. The SDK fixture returns `ocid1.service.oc1..services`. requireOCID requires the service's OCI region in component four. Return `ocid1.service.oc1.<exact requested region>.services`, deriving and validating the region from the original canonical SDK Host. The TLS dial remains confined to the fixture's verified literal loopback listener; no transport/authority assertion changes.

## Downstream plan invariant audit

| Consumer | Required invariant | Reviewed producer/fixture state |
| --- | --- | --- |
| validatePlan schema/catalog | schema2; exact cell/OCI region | Template schema2; catalog-derived GRU/sa-saopaulo-1, SFO/us-sanjose-1, FRA/eu-frankfurt-1 |
| preview names | exact control/network/workload; safe distinct names | Template has exact map; shared renamer preserves distinct names |
| host roster | controller count equals controller_replicas; no database members | Producer sets controller_replicas1 and hosts only controller-a; database_members0 remains |
| host shape/geometry | architecture explicit; safe A1 shape; cpu>0, memory>=cpu, boot>=50, controller data0 | donor55a supplies ARM64; fixed A1 template; approval1CPU/6GiB/50GB updates first host; data0 retained |
| network/address | canonical private nested CIDRs; catalog cell allocation; unique host IP | Existing Network uses 10.251/252/253.0.0/24; subnet/25; seed .11; public .128/26 |
| resource identities | exact resourceKinds plus instances/boot/data maps; typed regional IDs or null | Template exact map; GRU control/vault/key come from approved existing home target; other foundation IDs unbound; producer shrinks instance/boot maps to controller-a; data map empty |
| budget | positive finite currency/limit; one replacement and <=72h overlap; bounded storage | Approval USD/12000minor→120; template replacement1/72h, snapshot350GB/object10GB/staging10GB retained. These are recipe/forecast bounds, not complete history/usage financial coverage |
| operations baseline | if present, exact typed baseline fields | Producer deletes the baseline before plan validation; public general Derive retains owner55a's explicit expected shape/architecture |
| gateway/netbird | explicit null or exact scoped manager fields | Platform template declares operator_gateway:null, netbird:null; dedicated manager is separately signed in GRU |
| public API | exact fields; ports443/9465; bandwidth10/10; exact planned members; valid origin CA/ID | Fields/ports/bandwidth/certificate retained; proposed backend correction binds only actual funded host using naming, preserving all other public fields |
| security ingress | exact normalized rule fields, stateful CIDR boundaries and allowed public ports | Complete template rule maps retained; renamer updates cell CIDRs; public rules8080/9465/8444 preserve current TSAuth/client/Orch expectations |
| security egress/routes | complete stateful cell+NTP+service routes; exact service route triple | Template exact maps retained and renamed; live service CIDR replaces old one; fixture serviceID needs its exact region as above |
| identity/credential placeholders | exact safe IAM names; exact secret fields with both-null placeholders | Template IAM map retained/renamed; unbind preserves exact compartment_id/secret_id map and nulls |
| seed/retention | no bound seed instance without create identity; whole days1..3650 | New instance null, seed identity null, retention35 days |

The complete ValidatePlan body and helpers requireOCID, validateRules, validateGateway, validatePublic, validateBoundary, validateNetbird and hostArchitecture were read. Later preparation, worker-profile production, offline signing and exact retained publication calls were also inspected: generation1/three regions, three-controller material topology, twelve worker tuples from actual advertised ARM/AMD flexible shapes, four funded controller/manager slots, approval cap4000minor, independent image/application authority, expiry clamp and immutable-byte replay all stay required. No assertion or authority is proposed for removal.

## Minimal proposed owned diff, pending QA approval

Prerequisite: apply exact owner55a JSON architecture donor on a new isolated successor; do not mutate3e50 or either old packet.

`internal/region/grant_preparation.go`: add existing `internal/naming` import. Immediately after setting `plan["hosts"] = []any{first}`, derive `memberName, err := naming.RegionCell(cell).ControllerSlot(first["slot"].(string))`, return the existing producer error on failure, and set `plan["public_api"].(map[string]any)["terrabase_members"] = []any{memberName}`. This one shared producer correction covers pure and SDK preparation and both CLI ceremonies' source. It does not change three-slot bootstrap material or grant topology.

`internal/bootstrap/cli/foundation_preparation_integration_test.go`: in the services handler derive region from canonical `iaas.<region>.oraclecloud.com` request Host, require catalog.IsOCIRegion, and return the service OCID containing that exact region. Add in-root assertions for each cell's explicit ARM64, exactly one funded host, exactly one correct public backend (`gru-1-ctl-1`/`ts-sfo-1`/`ts-fra-1`) and unchanged three-controller material roster. Preserve all seventeen existing root/leaf identities and cryptographic/expiry/evidence/immutable replay/refusal assertions.

OCI owns the separate full provisioning fixture's equivalent service-ID fix. No production validator, authentication, trust decoder, budget authority, region scope or live provisioning change is proposed. No build/test/vet/lint/retry is authorized by this report.
