# OCI manual estate bootstrap

ORCH-5 automates resources that change during normal operation. Humans create
the tenancy estate once, review it, and record its immutable identities. The
orchestrator creates compute instances, block volumes, attachments, registry
pulls, Object Storage objects, and reads work requests. It does not create or
change compartments, networks, IAM policies, or Vault resources.

Repeat the regional steps for the launch regions:

| TerraScale cell | OCI region |
| --- | --- |
| GRU | `sa-saopaulo-1` |
| SFO | `us-sanjose-1` |
| FRA | `eu-frankfurt-1` |

Have a second reviewer compare every recorded OCID, CIDR, policy statement,
bucket name, and Vault endpoint before installing the estate file.

## 1. Create compartments

Create three compartments below the TerraScale tenancy compartment:

- `terrascale-control` for regional controllers, Vault, the ledger bucket,
  and backup bucket.
- `terrascale-network` for VCNs, subnets, gateways, route tables, and NSGs.
- `terrascale-workload` for compute instances, boot volumes, and data volumes.

Record the tenancy OCID and all three compartment OCIDs. Do not reuse a
development compartment.

## 2. Create each regional network

In `terrascale-network`, create one VCN per launch region with a non-overlapping
RFC 1918 CIDR. Create one private workload subnet in every availability domain
present in that region. A region with one availability domain has one subnet.
Set `prohibitPublicIpOnVnic` on every subnet.

Create NSGs for the actual roles used in that region. At minimum, separate the
regional control group and TerraBase Members. Review these rules:

- No internet ingress to NATS, host-agent, or TerraBase member ports.
- Regional control traffic is admitted only from the regional control NSG.
- Member replication is admitted only from the member NSGs and the reviewed
  cross-region CIDRs.
- Egress is limited to OCI service gateways, time/DNS, and the reviewed
  inter-region paths.

Record the VCN, subnet, and NSG OCIDs. The startup check proves each subnet and
NSG belongs to the recorded VCN and network compartment.

## 3. Create the controller identity and IAM policy

Create a dynamic group matching only regional controller instances in
`terrascale-control`. Create reviewed policies that grant the group only the
following capabilities:

- Manage instances and volume-family resources in `terrascale-workload`.
- Use the recorded subnets and NSGs in `terrascale-network`.
- Read work requests for resources it manages.
- Read the recorded compartments, VCN, subnets, NSGs, and IAM policies.
- Download release artifacts from the Forgejo package registry only through the
  reviewed egress paths.
- Manage objects only in the recorded ledger and backup buckets.
- Use the recorded Vault key. Do not grant Vault or key creation/deletion.

OCI Email Delivery uses a separate Dashboard mail identity under D-26. Keep
its sender-domain DNS and least-privilege credential path separate from the
regional controller; this runbook does not configure email or grant email
permissions.

Copy each policy statement byte for byte into `iamPolicies[].statements` in the
estate file. Startup compares the provider's current statement set with that
reviewed set. A broadened or missing policy prevents the process from starting.

## 4. Create Vault and Object Storage resources

In `terrascale-control`, create a regional virtual private Vault and a
provider-managed AES key. Record the Vault OCID, key OCID, and the Vault's
`managementEndpoint`. Enable key rotation according to the production key
policy. Do not put key material or auth tokens in the estate file.

Create two private Object Storage buckets in `terrascale-control`:

- `terrascale-ledger-<region>` for the regional durable ledger.
- `terrascale-backups-<region>` for backup chunks and manifests.

Enable versioning and the reviewed retention/lifecycle rules. Object writes are
content-bound and create-only. Backup producers must split large artifacts into
chunks no larger than the configured OCI transport body limit, which may not
exceed 16 MiB, then store a content-addressed manifest.

## 5. Install the reviewed estate file

Install an absolute, root-owned path readable by the orchestrator service. The
document contains identities and policy text, not credentials:

```json
{
  "region": "sa-saopaulo-1",
  "tenancyId": "ocid1.tenancy.oc1...",
  "controlCompartmentId": "ocid1.compartment.oc1...",
  "networkCompartmentId": "ocid1.compartment.oc1...",
  "workloadCompartmentId": "ocid1.compartment.oc1...",
  "vcnId": "ocid1.vcn.oc1.sa-saopaulo-1...",
  "subnetIds": ["ocid1.subnet.oc1.sa-saopaulo-1..."],
  "networkSecurityGroupIds": [
    "ocid1.networksecuritygroup.oc1.sa-saopaulo-1..."
  ],
  "iamPolicyCompartmentId": "ocid1.compartment.oc1...",
  "iamPolicies": [
    {
      "id": "ocid1.policy.oc1...",
      "statements": [
        "Allow dynamic-group terrascale-orchestrator to manage instances in compartment terrascale-workload"
      ]
    }
  ],
  "vaultId": "ocid1.vault.oc1.sa-saopaulo-1...",
  "keyId": "ocid1.key.oc1.sa-saopaulo-1...",
  "keyManagementEndpoint": "https://<vault>-management.kms.sa-saopaulo-1.oraclecloud.com",
  "objectNamespace": "<tenancy-namespace>",
  "ledgerBucket": "terrascale-ledger-sa-saopaulo-1",
  "backupBucket": "terrascale-backups-sa-saopaulo-1"
}
```

Configure the service with:

```text
TS_ORCH_PROVIDER=oci
TS_ORCH_OCI_ESTATE_FILE=/etc/terrascale/oci-estate.json
TS_ORCH_OCI_KEY_ID=<instance-principal-key-id>
TS_ORCH_OCI_PRIVATE_KEY_FILE=/run/credentials/oci-instance-principal.pem
```

The key file must be a regular PKCS#1 or PKCS#8 RSA private key owned by the
service account with mode 0600 or stricter. `orchestrator run`,
`orchestrator check`, and the autoscaler refuse to start if any required
setting is absent or any read-only estate check fails.

## 6. Verify before handoff

Run the env-gated, read-only smoke from a controller host:

```bash
TS_ORCH_OCI_LIVE=1 go test -tags live_oci ./tests/live -run TestOCIEstateLiveSmoke
```

Then start `orchestrator check`. Save the reviewed estate file in the deployment
secret/configuration system. Do not commit real tenancy OCIDs, policy files, or
private-key paths to this repository.

Any later manual network, IAM, Vault, or bucket change requires the same
two-person review and a matching estate-file update before controllers restart.
