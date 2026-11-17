# Host and load-balancer exposure

The OCI NLB forwards only TCP 80, 443 and 5432 and preserves client source
addresses. A socket, host firewall rule and OCI ingress rule are separate
observations: an allowance alone does not prove a listening service.

## Exposure table

Each row has one component owner. VCN means the same region's private network.
NetBird access also requires peer policy. Binding all interfaces does not
grant internet access through the NSGs.

| Port / protocol | Listener | Who may reach it | Owner | Reason |
| --- | --- | --- | --- | --- |
| 80 TCP | NLB and host edge | Internet | internal/edge | ACME HTTP-01, HTTPS redirects and bounded health probes. |
| 443 TCP | NLB and host edge | Internet | internal/edge | Authenticated product HTTP, gRPC, WebSockets, NetBird control and read-only orchestrator observations. Peer hops require their own identity. |
| 5432 TCP | NLB and host edge | Internet | internal/edge | TLS Postgres ingress with database authentication. |
| 3478 UDP | GRU NetBird server; existing NSGs allow it regionally | Internet | internal/netbird/manager | STUN discovers peer endpoint mappings for direct WireGuard paths. Intentional public exception. |
| 51820 UDP | Host NetBird client | Internet on existing hosts; VCN on document-made nodes | NetBird client | Authenticated WireGuard transport. Intentional public exception; document-made nodes enroll through NAT. |
| 22 TCP | Host OpenSSH | VCN / NetBird operator path, OCI Bastion | Host OS | Authenticated operator access. The network pass declares no public SSH rule. |
| 22 TCP on the NetBird interface | Host NetBird client | NetBird operators and automation | NetBird client | Identity-authorized operator sessions. |
| 53 TCP/UDP | Host resolver and NetBird DNS | Loopback / local overlay resolver | Host DNS | Local system and private peer-name resolution. |
| 4222 TCP | Cell client bridge on document-made nodes; no release listener in six-host runtime | VCN / admitted NetBird peers | Orchestrator NATS transport | Authenticated regional messaging. The public release listener and GitHub runner clients are deleted. Historical public NSG rules await C19b below. |
| 4223 TCP | Host mesh client | Loopback / regional mesh interface | internal/natscell/mesh | Authenticated service and rollout messaging. |
| 6222 TCP | NATS routes | VCN / regional NetBird peers | internal/natscell | Authenticated cluster routes and JetStream replication. |
| 7422 TCP | Contracted NATS leaf listener | VCN / admitted NetBird child regions | internal/natscell | Authenticated inter-region topology where declared. An allowance does not imply an active socket. |
| 4242 TCP | Swarm manager | VCN; loopback on a local node | internal/swarmruntime | Authenticated host membership and task assignment, restricted by host firewall. |
| 8081 TCP | TerraBase internal edge | Loopback; authenticated edge peer hops terminate on 443 | internal/edge | Local streaming and replay into a TerraBase task. |
| 8080, 8085, 8090, 8097, 8099 TCP and allocated task ports | Service tasks | Host / VCN / admitted NetBird readiness paths | internal/swarmruntime | TerraBase, canary, dashboard, auth and whoami backends. Dynamic task ports have no public NSG ingress. |
| 6432 TCP and allocated Postgres task ports | TerraBase tasks | Host / VCN | TerraBase | Private backend of TLS edge ingress on 5432. |
| 8095 TCP | GRU NetBird management | Loopback | internal/netbird/manager | Backend for the authenticated edge route. |
| 9095 TCP | GRU NetBird health | Loopback | internal/netbird/manager | Private process health. |
| 9096 TCP | GRU NetBird metrics | Loopback / VCN | internal/netbird/manager | Upstream metrics socket, excluded from public NSGs. |
| 9090 TCP | Prometheus | Loopback | Production monitoring | Regional query and ingestion backend. |
| 9091 TCP | TerraBase metrics | NetBird monitoring / VCN | TerraBase | Database runtime observations. |
| 9093 TCP | Alertmanager HTTP | Loopback / admitted NetBird monitoring | Production monitoring | Alert routing backend. The production unit disables cluster gossip. |
| 9094 TCP | Alert relay | Loopback | Production monitoring | Delivery to configured production alert integrations. |
| 9097 TCP | Blackbox exporter | Loopback | Production monitoring | Bounded monitoring probes. |
| 9108 TCP | Host metrics | NetBird monitoring | internal/hostmetrics | Read-only host, rollout, replica-load and service evidence. |
| 9443 TCP | TerraBase replication | VCN / admitted NetBird servers | TerraBase | Authenticated member replication. |
| 9463 TCP | Operator dashboard | NetBird operators and automation | internal/hostdashboard | Existing bearer-authenticated operator views. |
| 9464, 9465 TCP | Managed TerraBase admin and client | Loopback admin; VCN / admitted NetBird clients | TerraBase | Private administration, readiness and authenticated client traffic. |

The document-made ingress values live in internal/fleet/network.go.
The network pass, ts-orch region apply <label> network, reconciles public
edge TCP 80/443/5432 and VCN-only 4222/6222/7422 plus WireGuard. It does not
adopt the six hand-made hosts or their edge/host NSGs.

## Release selection and observation

Hosts discover qualified GitHub binary releases and verify their Sigstore
bundles before regional self-installation. Application discovery reads the
release tag of the existing ghcr.io/terrascale package, resolves the native
Linux digest and verifies provenance against the exact main workflow,
revision, run and attempt. It reuses the instance-principal Vault GHCR read
credential.

Selection grants no additional trust. Unsigned images, another workflow's
images and older signed identities fail verification or the durable floor.
A newer authorized selection run or attempt can select the same already-built
digest after a held rollout. Build publication alone cannot clear a hold. Regional bake, hold and
rollback remain authoritative.

The host requires a separate signed selection predicate bound to the service,
revision and exact image subject. Its certificate names the main target workflow
and an allowed trigger. TerraBase requires workflow_dispatch, so only the user's
manual release-only job selects its previously built pinned digest. Main build-only publication does not select a release.
Auth and dashboard allow push or workflow_dispatch; app canary requires
workflow_run. Claims use the selecting run and attempt. Keyless Sigstore signing
uses existing OIDC and GHCR permissions; no new GitHub attestation permission,
credential, host secret or package is introduced.

The existing Vault pull token is a classic MarioGK PAT: it can read every package
that account may access, rather than a package-scoped credential. This change
reuses it without expanding or rotating it.

GET /orchestrator/observation uses the existing edge certificate and GitHub
OIDC admission. It accepts only GET and exposes health, mesh pings,
registered host versions and desired/running images. It cannot apply, remove,
push or nudge. CI reads it over 443 and has no NATS dial path.
Release hosts requires every registered host's revision; release wait
requires fresh serving evidence for the chosen digest in every placement
region; release digests rejects incomplete or disagreeing running images.

## Six-host public 4222 removal: C19b

The 2026-11-16 outside baseline connected successfully to TCP 4222 on all
six hosts. This proves TCP connectivity, not authenticated mesh health.

| Region | Host | Public IP | Before 4222 | Public edge NSG rule |
| --- | --- | --- | --- | --- |
| fra | ts-fra-1 | 130.162.238.198 | Connected | 856A92 |
| fra | ts-fra-2 | 152.70.187.12 | Connected | 856A92 |
| sjc | ts-sjc-1 | 163.192.54.17 | Connected | 896F8B |
| sjc | ts-sjc-2 | 163.192.24.49 | Connected | 896F8B |
| gru | ts-gru-1 | 163.176.124.12 | Connected | 52C953 |
| gru | ts-gru-2 | 147.15.5.65 | Connected | 52C953 |

Rules belong to <label>-1-edge-nsg. Audited host security lists had empty
ingress; host NSGs admitted the VCN and ICMP fragmentation. Re-read NSGs,
VNIC memberships and security lists immediately before changing a rule.

Wait until the receiver release runs on all six hosts, producer changes
are merged and no old workflow can still push. Record all six revisions
and mesh health. Observe conntrack or NATS connections over a recorded
interval spanning old release/check workflow invocations. No outside VCN /
NetBird source may remain. One empty snapshot is insufficient.

Proceed FRA, then SJC, then GRU, one rule per region:

1. Save the exact public 4222 rule and NSG OCID. Prepare undo JSON, removing
   read-only API fields. Exclude duplicate public allowances in other
   attached NSGs and security lists.
2. Remove the rule with oci network nsg rules remove --region <oci-region>
   --nsg-id <edge-nsg-ocid> --security-rule-ids '["<rule-id>"]' --force.
3. From outside VCN and NetBird, require nc -vz -w3 <public-ip> 4222 to
   fail on both hosts. Record exit codes and UTC time.
4. From inside, record both hosts' ts-orch status, mesh health and
   authenticated HTTPS observations. Stop before the next region on any
   unexplained change.
5. Record one-command undo: oci network nsg rules add --region <oci-region>
   --nsg-id <edge-nsg-ocid> --security-rules file://<region>-4222-undo.json.
   Use the exact saved rule rather than a broader replacement.

This code change does not remove live NSG rules. C19/C19b evidence must
record actual NSG OCIDs, exact undo commands, observation interval and
before/after results once the deployed release permits the operation.
