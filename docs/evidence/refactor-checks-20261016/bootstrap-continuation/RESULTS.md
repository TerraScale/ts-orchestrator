Bootstrap race continuation on c2eb7062

145 remaining unique top-level names now have explicit race PASS evidence. Four admission/selfupdate cases affected by transitive production receipt changes also PASS (3.546s). Gate RELEASED; worktree clean.

| Invocation | Result | Time |
|---|---|---|
| founder runtime initial28 | cumulative timeout;25 PASS; test26 interrupted after3s |360.102s|
| founder runtime remaining3 only |3 PASS|34.348s|
| founder authority22 |21 PASS,1 root SKIP|5.873s|
| generation/identity50 |48 parent PASS,2 root SKIP;10 children SKIP under one PASS parent|38.707s|
| launch/material/observation45 |40 PASS,5 root SKIP|31.036s|
| dependency-impact admission/selfupdate4 |4 PASS|3.546s|
| ordinary root follow-up7 parents |7 PASS, all10 previously skipped children PASS, no SKIP|bounded120s|
| exact five-capability e3 + no_new_privs |1 PASS, no SKIP|0.01s test|
| exact four-capability e1 + no_new_privs |1 PASS, no SKIP|0.00s test|

All skip gaps in these continuation logs were explicitly closed by privileged runs. No assertion failure or race report appeared. Full-package timeout and runtime-shard timeout remain failures by cumulative budget; neither is described as a successful full-package invocation.

Earlier prefix: retain93 completed names from1d0042a8 full-package timeout evidence; no wholesale repetition. Bootstrap source is unchanged1d004→c2, but transitive dependencies are not all unchanged. Four selfupdate cases were rerun for the known changed dependency.

Machine-readable per-log names, nested outcomes, SHA256 hashes and provenance: results.json. Original manifests/selectors and full logs remain in this directory. No source edits, cloud calls, deployment or push performed.
