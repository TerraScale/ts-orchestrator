# Phase 1 runtime executor-observation output audit 4 handoff

## Proven gap and correction

Two fully valid response-lost lifecycle requests for the same operation and allocation but different executor nodes produced equal authorized `ObserveExecutorIntent` values. The intent retained only operation and allocation, so persisted recovery work could not distinguish which validated executor boundary to query. Epoch, generation, action, observation, workload specification, admission, inventory, and health evidence were discarded as well.

`ObserveExecutorIntent` now retains the exact validated `RuntimeLifecycleRequest`. Its inherited operation identity and allocation compatibility getter derive from that request, with no redundant flattened state. The engine passes the already validated request only after existing rejection and response-safety checks.

Tests cover `Accepted` and `ResponseLost` across start, stop, drain, and cleanup paths; exact request and compatibility-reference retention; every top-level request property; a complete length-delimited nested request fingerprint; 1,000 culture-stable and evidence-permutation replays; rejected Hold-only behavior; defensive input capture; opaque output; and assembly-wide public construction, accessor, immutable-clone, and real `EvaluateLifecycle` route closure.

Review hardened that evidence with single-field and single-element mutants for every nested specification, native/OCI payload, admission, observation, health, inventory, conflict, port, and volume getter. Permutation replay now reverses two distinct allocation entries and each nested collection. Construction closure includes all exported public declared methods and accessors whose output can be the exact intent, the `RuntimeIntent` union, or `RuntimeDecision`, with only the two real engine origins, the decision projection, and immutable record copies allowlisted.

A final coupled-field review found that the OCI-to-native variant changed both driver and descriptor. A separate Native-to-Native pair now keeps every shared payload field and driver identical while changing only `NativeUnitDescriptor`, proving that leaf is independently retained.

The strict checked-in Runtime replay corpus models self-update decisions. Its observation case is `ObserveUpdateIntent`, which already retains an exact `SelfUpdateRequest`; it does not encode lifecycle `ObserveExecutorIntent`. No corpus bytes, checksum, or self-update fingerprint changed.

## Honest boundary

This closes only pure accepted-output provenance. Retaining a request does not perform or prove executor observation, response recovery, PID/start-time/invocation/cgroup verification, process state, systemd/containerd behavior, artifact authenticity, persistence, or deployment qualification. No adapter or external side effect was added.
