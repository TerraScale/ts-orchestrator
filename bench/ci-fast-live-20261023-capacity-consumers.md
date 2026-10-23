# Managed-capacity image consumer check — 2026-10-23

## Result

No active managed-capacity launch recipe was found on the three serving founders. Their observed executable subcommand is `single-host`, which does not start the managed controller, its node scaler, its cell-spec registry, or its current-image discovery. This is a reachability finding, not a claim that an existing managed-capacity recipe uses a stock image.

**No persisted recipe ImageID or signed catalog OCIImageOCID was read or verified.** The regional catalog metadata requests returned ambiguous OCI 404 responses. Existing stock VM image IDs alone do not establish the image a future managed-capacity action would select.

The automated QCOW2 producer has no demonstrated consumer in the observed serving path. Preserve managed-image discovery, signed admission, qualification and manual provisioning tooling if removing that producer. Activating the separate managed controller later requires its existing image/authority prerequisites; this audit does not authorize activation or treating a stock image as qualified.

## Code reachability

Sources inspected at local commit `cfce4cf7fba69eda524cedfb9f1bd834773fb949`; runtime observations are separately stated below.

1. `internal/app/app.go`, `RunSingleHostServing`, calls `planHost`, starts the edge and `mesh.Run`, and calls `runSingleHost`. `internal/app/single_host.go` starts the SwarmKit/containerd node and release listener. Neither starts the managed capacity reservations or node scaler.
2. `internal/app/app.go` dispatches the distinct `run --config ...` command to `runController`. Only `internal/app/controller.go` calls `startCapacityReservations` and binds the node pool through `bindNodePool` / `bindNodeScaler`.
3. `internal/app/capacity_worker.go:21,78` genuinely carries independently signed worker `ImageID` values into a base recipe. `capacity_selection.go` can replay a persisted recipe and otherwise discovers and qualifies signed current images. These are real consumers in the managed-controller path, not proof that this path is running.
4. `internal/app/capacity_selection.go`, `imageInputs`, discovers current images, signed cell-spec host images and accepted bootstrap material. `prepare` requires the selected qualification's OCIImageOCID and architecture to match the recipe. `internal/app/capacity_reservation.go` requires the independent authority checks; no checks were bypassed in this audit.
5. `internal/app/cell_spec_operator.go`, `operatorServiceHostImage`, sets/revokes `HostImages` and `LaunchImage` through a planned signed cell-spec generation. It does not establish the contents of a live spec merely because the command ships in the executable.

`internal/nodescale/store.go` persists recipes in JetStream KV bucket `TS_NODESCALE`, key `state`. The cell-spec registry uses JetStream KV bucket `TS_SERVICE_SET`, key `current` (`internal/app/cell_spec_registry.go`). The single-host release listener explicitly has no JetStream (`internal/releasepush/server.go`, `Options`). The single-host cross-region mesh persists its service map in `<state>/mesh/desired.json`, not these managed-controller KV buckets (`internal/natscell/mesh/node.go`). No service-map contents were dumped.

The active geographic region catalog (`internal/ociregion/catalog/catalog.go`) is distinct from signed image discovery: it contains region identifiers and geography, not launch image IDs.

The direct region provisioning path is also separate. CLI dispatch sends `region add|rm` to `regionhost.Run`; `region create` uses a different path. R1 [PR #109](https://github.com/TerraScale/ts-orchestrator/pull/109) merged at 2026-10-22T20:39:14Z. `internal/regionhost/instance.go:115` lists Canonical Ubuntu 24.04 images compatible with the requested shape and selects architecture/non-Minimal; `cloudinit.go` installs a checksum-verified CI binary and `ts-orch.service`. This path does not read a managed-capacity recipe or the signed current-image catalog. Its stock-image selection is not evidence that the independent managed-controller recipe would be stock.

## Read-only founder observations

At approximately 2026-10-23 02:05–02:07 UTC, existing SSH identities inspected the three existing targets `ts-gru-1`, `ts-sjc-1`, `ts-fra-1`.

| Observation | GRU | SJC | FRA |
|---|---|---|---|
| `ts-orch.service` | active/running | active/running | active/running |
| Unit path | `/etc/systemd/system/ts-orch.service` | same | same |
| Serving executable/subcommand | `/usr/local/bin/terrascale-orchestrator single-host` | same | same |
| Directories matching `*TS_NODESCALE*`, `*TS_SERVICE_SET*`, or `jetstream` anywhere beneath `/var/lib/ts-orch` | none found | none found | none found |
| `oci` CLI available through existing SSH PATH | no | no | no |

Process inspection emitted only PID, executable path and first subcommand for executables matching the orchestrator. It found `single-host`, `netbird`, runtime loggers and one transient GRU `service` command; no managed `run` controller. This was a process snapshot, not a historical process audit. Recursive directory-name absence supports the code and process evidence; it does not parse or cryptographically validate persisted KV records.

The inspected `/var/lib` directory names showed `/var/lib/ts-orch` on all founders, plus `/var/lib/ts-orch-smoke` on GRU. This audit did not open old state/configuration contents or treat smoke state as serving state.

## Signed current-image catalog check and evidence gap

`internal/app/rollout_channel.go`, `instancePrincipalChannel`, derives the regional head bucket with `releasechannel.BucketName`. `internal/releasechannel/image_current.go` uses discovery objects under:

```text
releases/images/current/production/<role>/linux-<architecture>.json
```

The exact metadata-only query was executed once per region, with the existing local OCI identity and namespace returned by `oci os ns get`:

```sh
oci os object list --region REGION --namespace-name grxnmoqvrcdv \
  --bucket-name CELL-1-head --prefix releases/images/current/production/ \
  --all --query 'data[].{name:name,size:size,modified:"time-modified"}' --output json
```

| Region / bucket | UTC response | Result |
|---|---|---|
| FRA / `fra-1-head` | 2026-10-23T02:05:51.664217Z | HTTP 404 `BucketNotFound` |
| SJC / `sjc-1-head` | 2026-10-23T02:05:53.601040Z | HTTP 404 `BucketNotFound` |
| GRU / `gru-1-head` | 2026-10-23T02:05:55.179118Z | HTTP 404 `BucketNotFound` |

OCI's message says the bucket either does not exist **or** the identity is not authorized. Therefore these responses do not prove catalog absence, contain no image IDs, and do not prove anything about a stored signature's validity. No retries, credential changes, permission expansion, alternate credential extraction or catalog writes followed. The hosts had no existing `oci` CLI on PATH, so no additional instance-principal catalog query was attempted there.

## Limits and safety

The earlier source-image inventory is recorded in `ci-fast-live-20261023-image-consumers.md`; it proves current VM boot images, not future capacity recipes. This follow-up establishes that the managed-controller recipe path is not reached by the observed founder processes. It does not certify that every inaccessible or historical image catalog is empty.

No secret files, credential values, environment dumps, full runtime configs, signed authority payloads, production data or raw persisted recipe contents were read or printed. No instances, services, capacity, permissions, credentials or data were changed. No tasks were stopped or killed.
