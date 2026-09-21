# OCI TerraBase host and member readiness

An enrolled host and a healthy database are different stages. A replacement
host must be able to receive its retained volume before the database starts.
The controller now reads separate evidence for those stages.

After verifying its enrollment and credential gate, host convergence writes
`host.admission.<instance>.terrabase-server` to the private `ORCH_RUNTIME`
store, before installation or service convergence. Schema 1 records the exact
cell, instance, environment, artifact key, admitted digest, readiness flag and
observation time. A denied gate writes `ready: false`, replacing prior ready
evidence. This report is not itself a signed envelope; its producer checks the
enrollment gate, and NATS identity/subject permissions protect the store.
Production startup still requires signed enrollment configuration.

The member fleet's readiness reader checks that report against the exact
`ORCH_DELIVERY` target used by host convergence. Both paths use
`HostDesiredArtifactReader`, including the service/environment/cell key and
canonical SHA-256 digest validation. Missing or malformed targets, another
node/cell/environment/artifact, a different digest, a denied report, a future
timestamp or a report older than ten minutes cannot establish readiness.
The OCI instance must also be running and retain the expected identity,
compartment, image, bootstrap and create-key tags.

This permits storage recovery without claiming the database is serving.
Member health additionally requires a fresh schema-2 convergence report with
the exact node, cell, artifact and digest, `state: converged`, no error and
complete valid health gauges. A booted/stopped VM or a missing report does not
count as healthy. Role strings from the service are normalized (`leader` and
`follower` to the control-plane roles). The operator workload aggregate ignores
the separate admission records instead of interpreting them as convergence.
Dedicated enrollment progress projection/metrics still need implementation.

## Member fleet configuration

`TS_ORCH_MEMBER_FLEET_FILE` now requires schema 2 with an explicit environment
matching the deployed host's `TS_ORCH_HOST_ENVIRONMENT`. Schema 1 is rejected.
The other fields remain the reviewed OCI endpoint, cloud-init artifact and
regional launch templates:

```json
{
  "schemaVersion": 2,
  "environment": "production",
  "endpoint": "https://iaas.sa-saopaulo-1.oraclecloud.com",
  "bootstrapFile": "member.cloud-init",
  "regions": [
    {
      "region": "GRU",
      "compartmentId": "ocid1.compartment.oc1..replace",
      "availabilityDomain": "TENANCY:SA-SAOPAULO-1-AD-1",
      "faultDomain": "FAULT-DOMAIN-1",
      "subnetId": "ocid1.subnet.oc1.sa-saopaulo-1.replace",
      "networkSecurityGroupIds": ["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.replace"],
      "imageId": "ocid1.image.oc1.sa-saopaulo-1.replace",
      "generation": 1
    }
  ]
}
```

These are placeholder OCIDs, not deployment inputs. Region intent must admit
the cell and its exact endpoint. Environment accepts 1–64 lowercase letters,
digits or hyphens. Duplicate/unknown JSON properties are rejected.

## Qualification and remaining lifecycle gaps

Real NATS tests exercise the production readiness readers and host report
producer, including publication before a deliberately blocked runtime starts,
withdrawal on lost admission, artifact promotion/removal and identity/time
mismatches. Native execution and the admission gate are injected in that
producer test; it does not prove a fresh OCI node's complete enrollment.
Provider tests verify stopped-instance handling and identity/template drift
before accepting readiness. A real NATS placement test verifies that missing
member evidence during draining never advances to detach or retirement.

The complete storage and drain path remains a deployment blocker:

- `OciMemberHostFleet.VerifyMemberHostAsync` currently projects a boot-volume
  OCID as the retained volume, while `OciMemberHostVolumeAdapter` uses the
  separate data-volume attach/detach APIs. That contract must be corrected,
  including creation, ownership, mounting, restart and retention evidence.
- `EnsureVolumeAsync` still fabricates a logical volume ID when the provider
  reports none. This cannot qualify a production data volume.
- The OCI drain path publishes an empty host command; no production consumer
  of `HostAgentCommandSubject` is composed yet. Fresh unhealthy telemetry is
  still weaker than explicit proof that writers stopped. Implement durable,
  fenced drain handling and acknowledgement before allowing retirement.
- Retirement currently requests boot-volume deletion. It must never execute
  against a host whose only retained data is on that boot volume.

The missing-report guard closes one unsafe transition; it does not complete
those protocols. Keep OCI deployment disabled until the storage and drain
contracts pass real-caller qualification. See the
[readiness record](../evidence/oci-readiness-2026-09-20.md).
