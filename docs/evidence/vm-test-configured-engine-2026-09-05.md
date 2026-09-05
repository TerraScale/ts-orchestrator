# Configured engine guest attempt

The full Firecracker test ran on linux/amd64 with Go 1.27.1 and the supplied
TerraBase binary identified in the [diagnostic output](vm-test-configured-engine-2026-09-05.txt).
The [machine report](vm-test-configured-engine-2026-09-05.json) records the run
from 21:25:15Z to 21:27:59Z on September 5.

An isolated diagnostic declaration supplied six synthetic member identities,
one synthetic database permitted in GRU/SFO/FRA, and short-lived matching TLS
certificates. These inputs do not establish production keys or admitted engine
membership. No private material is retained in this evidence.

The first attempt refused configuration before guest creation because the full
suite reserves IAD networking as well as the six launch hosts. Commit `2d0c5955`
excludes that reserved expansion network from initial engine bindings. The
signed-bootstrap regression now includes IAD reservations while requiring six
launch members and five peers per member. Non-GRU bootstrap still requires
admitted allocation and controller configuration.

The corrected attempt booted `gru-member-1`. ts-node and orchestrator were
active/running. TerraBase exited with status 1 and was awaiting automatic
restart. Its 17 retained journal-entry counts produced no recognized fixed
failure category. In particular, missing configuration was no longer reported;
this alone does not prove parser, catalog, TLS, or membership acceptance. The
next failure remains unidentified. No guest became ready and no scenario ran.

Automatic cleanup completed. Provider paths were absent and fixture listeners
were unreachable in the retained report. A subsequent explicit `make vm-clean`
exited 0.

Verification passed:

- [Portable `make check`](engine-launch-network-portable-2026-09-05.txt)
- [Tagged runtime race tests](engine-launch-network-tagged-2026-09-05.txt)

Production acceptance, full VM qualification, and the engine launch contract
remain open. This run supplies no OCI or Cloudflare production evidence.
