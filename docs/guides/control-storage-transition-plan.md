# Prepare the signed storage-transition plan

Run this command on the owner's machine after preparing the source/candidate
bootstrap grants and collecting the completed SFO and FRA preliminary receipts:

```sh
umask 077
terrascale-orchestrator plan-storage-transition --config /absolute/path/storage-plan-input.json > /absolute/path/storage-plan.signed.json
```

The command writes the exact canonical signed plan. It opens no broker, changes
no host journal, and makes no provider requests. A successful exit means the
signed intent matches the supplied original admissions and preliminary evidence.
It does not establish current host health or authorize source retirement by
itself. An output file from a failed command must not be delivered.

The input is a JSON object with these fields:

| Field | Value |
| --- | --- |
| `ownerPrivateKeyFile` | Absolute path to the owner's P-256 private key. Keep it off hosts. |
| `publicKeyFile` | Absolute path to the original bootstrap owner's canonical public PEM. |
| `sourceBootstrapGrantFile` | Original signed source host bootstrap grant. |
| `destinationBootstrapGrantFiles` | Exactly three original signed grants in GRU, SFO, FRA order. Reuse the source grant for a shared source/GRU host. |
| `preliminaryScopeFile` | Exact signed scope produced by `plan-preliminary-transfer`, extracted from that command's bundle. |
| `candidateReceiptFiles` | Exactly two completed signed candidate receipts in SFO, FRA order. |
| `plan` | Complete `controltransition.Plan` object from the [plan contract](../contracts/control-transition-plan.md). |

All file paths must be absolute and clean. Files must be regular, singly linked,
owned by the caller, and reached without symlinks. The input, grants, scope,
receipts and private key require private permissions, such as `0600`. The public
key may be readable by others but cannot be writable by them. File reads are
bounded; the input limit is 2 MiB and the final signed plan limit is 1 MiB.
Unknown fields, case aliases and duplicate JSON names are refused.

Prepare the full plan with the observed source inventory, accepted floors,
actual destination identities, certificates and ownership observations. The
command checks the source launch, store scope, directory, profile and account
names against its original signed bootstrap. It checks the preliminary capture
signer against that bootstrap's membership key and requires the capture request
to stay within the original grant's dates. It verifies all destination grant and
manifest identities and both signed preliminary receipts against the scope.

Original grants and capture requests are historical evidence and may have
expired. The new plan itself must remain live at output. This does not renew
bootstrap authority or permit a new candidate admission under an expired grant.
For a shared source/GRU host, the original grant binds the source manifest; the
future GRU prepared manifest remains a separate signed intention.

Save and deliver the exact resulting bytes. Re-running this command signs again
and produces a different signed-plan digest, even for identical input. A host
that already pinned one signed plan must retain that plan. Do not substitute a
new signature, reformat the output, or add a newline. `preliminaryScopeSha256`
uses the preliminary scope's canonical payload digest; bootstrap grant hashes
also use their existing payload-digest contract. The transition-plan digest
covers the complete signed envelope.

The checks authenticate the supplied evidence and its bindings. They do not
retrieve referenced restore evidence, observe OCI ownership, compare final
consumer state, validate actual filesystem identities, or establish the final
preparation barrier. Host delivery, independent receipt publication, privileged
phase execution and pre-NATS phase recovery remain unimplemented. The command
must not be used as a substitute for those gates.
