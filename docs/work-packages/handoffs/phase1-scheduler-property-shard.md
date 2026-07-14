# Phase 1 scheduler deterministic property/replay shard handoff

## Delivered

- Deterministic explicit-seed generators for valid placement and availability inputs plus invalid cases spanning all placement hard constraints and public validation families.
- Fourteen scheduler/availability property families execute 1,000 cases each for deterministic replay/permutation/culture, independent weighted-score selection and ordinal ties, resource/count conservation, capacity and constraint safety, quorum/minimum/disruption/topology/anti-affinity/reserve floors, typed caller safety holds, incomplete/conflicting evidence holds, generator diversity, and invalid-input rejection.
- Generator distribution assertions require every hard-constraint case to appear at least 50 times, every scheduler validator family at least 50 times, and every availability validator family at least 70 times. These checks prevent an accidentally vacuous or collapsed generator.
- A six-entry, maximum-32 strict embedded JSON replay corpus covers minimal hard-constraint, caller-hold, availability-floor, observation-conflict, and reserve-boundary seeds. Its canonical bytes are SHA-256 pinned; fixed resource name, version, shape, unknown fields, duplicate properties/identities/seeds, byte/count bounds, and positive seeds are validated before every entry reproduces its exact expected rejection.
- Mutation-sensitive assertions bind exact rejected checks, independently calculated scalar/BigInteger resource remainders and weighted-waste tuples, exact ordinal winners, exact availability reason codes, and neighboring reserve dimensions. Oracle subtraction does not call production `ResourceVector` arithmetic.
- Availability decisions and reasons are verified construction-closed with immutable public observations. Placement `ScheduleResult` records remain public caller-constructible DTOs in the existing production contract; the shard treats them as explanatory results, not mutation authority.
- The audit found unbounded `IEnumerable` materialization in the production placement and availability input surfaces. A shared maximum-plus-one snapshot now exposes named 4,096 candidate/observation, 1,024 port/fact/label, and exact-eight score-dimension technical limits; exact bounds remain accepted, while maximum+1, infinite, GetEnumerator/MoveNext/Current/Dispose failures reject secret-safely before any partial decision. A dedicated trap proves the extra element's `Current` is never read. Fatal runtime exceptions (`OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException`) are deliberately not translated. Canonical ordering and defensive snapshots are regression-tested. These are technical input bounds, not business capacity caps.

## Boundary and non-claims

The existing placement API has no generation or fencing epoch. This shard proves rejection of stateful stale/fencing observations only through the scheduler's closed caller-veto codes and proves incomplete/duplicate/conflicting availability evidence is held before policy arithmetic. It does not claim an intrinsic scheduler generation validator that does not exist.

This is scheduler-only feature evidence. It performs no filesystem/network/process/cloud/environment/clock operation, uses no nondeterministic randomness or new package, and does not claim full-domain/full-L0 thresholds, mutation coverage, fuzz/model evidence, or deployment authority.

## Verification

- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — passed with 0 warnings and 0 errors.
- `dotnet test tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj --no-build -- --minimum-expected-tests 20` — passed (69/69).
