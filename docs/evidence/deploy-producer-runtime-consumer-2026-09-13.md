# Deploy producer to Orchestrator consumer boundary

Date: 2026-09-13  
Purpose: verify the assigned `ts-deploy` → Orchestrator runtime → delivery consumer path at its real serialization and authentication boundaries.

## Source and environment identity

- `ts-deploy` source: `58255816cb3a75e54fa034c7c0aefb6b61b15203`.
- `ts-orchestrator` source: `6ceedc4f61764a7e2684f980009527077a5abbb7`.
- The Orchestrator worktree had one pre-existing unrelated modification at `src/TerraScale.Orchestrator/Tooling/ToolingTests.cs`; it was not changed by this audit.
- Host: NixOS 26.05, Linux x64.
- SDK: `11.0.100-preview.7.26381.103`; test target runtime: .NET 10.0.11.
- Real local broker used for the transport probe: `nats-server` 2.14.4, started with `-a 127.0.0.1 -p 4223 -js`.
- No deployed Orchestrator endpoint was declared for this audit. The local NATS broker was the only declared runtime environment.

## Intended call path found in source

The current producer path is:

1. `ts-deploy/src/TerraScale.Deploy/Cli/Program.cs:364-388` validates a request, serializes it as JSON, and submits it with `HttpClient.PostAsync` to an `http` or `https` URL. A non-empty token is sent as an HTTP `Authorization: Bearer` header (`:371-374`).
2. The Orchestrator runtime registers the `direct_delivery` NATS request/reply service only when its durable direct-delivery composition and command verifier are present (`src/TerraScale.Orchestrator/Messaging/NatsRuntime.cs:317-394`). Its subject is `terrascale.control.<cell>.command.delivery` (`src/TerraScale.Orchestrator/Protocol/Messaging/NatsSubjectTaxonomy.cs:148-150`).
3. The NATS consumer first validates the signed envelope, exact payload bytes, cell, operation, time window, and authority lease through `DirectDeliveryCommandIngress.Decode` (`src/TerraScale.Orchestrator/Delivery/DirectDeliveryCommandIngress.cs:61-108`). It then calls `DirectDeliveryService` or the handoff mapper and replies with `DeliveryWireCodec.SerializeReceipt` (`NatsRuntime.cs:349-383`).

These are different transports and different authentication boundaries. The producer has no NATS client, signed command envelope, payload digest header, cell header, authority generation, writer epoch, attempt, or command signature.

## Real producer serialization probe

Command (run from `ts-deploy`):

```text
nice -n 19 dotnet run --project src/TerraScale.Deploy/TerraScale.Deploy.csproj --no-restore -- deploy --operation-id operation-1 --repository owner/repository --commit 0123456789abcdef0123456789abcdef01234567 --tree-digest git:0123456789abcdef0123456789abcdef01234567 --artifact-name service.tar --manifest-name service.manifest.json --artifact-digest sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --signature-digest sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --manifest-digest sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc --manifest-signature-digest sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd --kind service --architecture linux/amd64 --service api --environment production --region gru --configuration-revision sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee --migration-revision sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff --requested-by release-bot --reason 'deploy the candidate' --dry-run
```

Result: exit 0 and a valid `ts-deploy` `DeliveryRequest`. Its top-level keys were:

```text
["artifact","configurationRevision","informational","migrationRevision","operationId","reason","requestedBy","rollback","schemaVersion","source","target"]
```

Its artifact keys were:

```text
["architecture","digest","kind","manifestDigest","manifestName","manifestSignatureDigest","name","signatureDigest","snippet"]
```

The Orchestrator's live `DeliveryRequest` accepts only `schemaVersion`, `operationId`, `source`, `artifact`, `target`, `configurationRevision`, `migrationRevision`, `requestedBy`, `reason`, `authorityGeneration`, `writerEpoch`, and `attempt`; its live `DeliveryArtifact` accepts only `digest`, `manifestDigest`, and `kind` (`src/TerraScale.Orchestrator/ControlPlane/Delivery/DirectDeliveryContracts.cs:11-41`). Its codec uses `JsonUnmappedMemberHandling.Disallow` (`:340-346`). Therefore the producer document's `artifact.name`, `artifact.manifestName`, `artifact.signatureDigest`, `artifact.manifestSignatureDigest`, `artifact.architecture`, `artifact.snippet`, and top-level `informational`/`rollback` fields cannot be consumed as the Orchestrator direct request. The producer also omits the three authority fields, which are defaulted by the DTO only when the payload reaches that DTO; it still cannot pass the signed ingress without envelope headers.

## Real transport and authentication probe

The broker was started as a real process, not a test double:

```text
nats-server -a 127.0.0.1 -p 4223 -js
NATS_READY=1 URL=nats://127.0.0.1:4223
```

The following real HTTP request used the exact same valid request fields and pointed `ts-deploy` at the actual NATS client port:

```text
nice -n 19 dotnet run --project src/TerraScale.Deploy/TerraScale.Deploy.csproj --no-restore -- deploy ... --orchestrator-url http://127.0.0.1:4223
```

The broker returned its native `INFO` line, which is not an HTTP status line. `ts-deploy` returned exit 1:

```json
{
  "code": "orchestrator_unavailable",
  "message": "The Orchestrator delivery endpoint could not be reached.",
  "remediation": "Received an invalid status line: 'INFO {...}'."
}
```

Passing the native NATS URL is rejected before network submission, also with a real producer command:

```text
nice -n 19 dotnet run --project src/TerraScale.Deploy/TerraScale.Deploy.csproj --no-restore -- deploy ... --orchestrator-url nats://127.0.0.1:4223
```

Result: exit 2, `orchestrator_url_invalid`, with remediation to pass an absolute HTTP or HTTPS URL. This confirms that the producer cannot address the runtime's declared NATS service.

## Focused boundary tests

All commands were run with the current built binaries and reduced priority:

```text
nice -n 19 dotnet test TerraScale.Deploy.slnx --configuration Release --no-build --no-restore
```

Result: `16 total, 16 passed, 0 failed`.

```text
nice -n 19 tests/TerraScale.Orchestrator.Tests/bin/Release/net10.0/linux-x64/TerraScale.Orchestrator.Tests --treenode-filter '/*/*/DeployHandoffMapperTests/*' --no-ansi --no-progress --show-stderr Failed --show-stdout Failed --maximum-parallel-tests 1
nice -n 19 tests/TerraScale.Orchestrator.Tests/bin/Release/net10.0/linux-x64/TerraScale.Orchestrator.Tests --treenode-filter '/*/*/DeployHandoffContractDriftTests/*' --no-ansi --no-progress --show-stderr Failed --show-stdout Failed --maximum-parallel-tests 1
nice -n 19 tests/TerraScale.Orchestrator.Tests/bin/Release/net10.0/linux-x64/TerraScale.Orchestrator.Tests --treenode-filter '/*/*/DirectDeliveryCommandIngressTests/*' --no-ansi --no-progress --show-stderr Failed --show-stdout Failed --maximum-parallel-tests 1
nice -n 19 tests/TerraScale.Orchestrator.Tests/bin/Release/net10.0/linux-x64/TerraScale.Orchestrator.Tests --treenode-filter '/*/*/DirectDeliveryCommandWireTests/*' --no-ansi --no-progress --show-stderr Failed --show-stdout Failed --maximum-parallel-tests 1
nice -n 19 tests/TerraScale.Orchestrator.Tests/bin/Release/net10.0/linux-x64/TerraScale.Orchestrator.Tests --treenode-filter '/*/*/DirectDeliveryProductionAdapterTests/*' --no-ansi --no-progress --show-stderr Failed --show-stdout Failed --maximum-parallel-tests 1
```

Results: `28/28`, `6/6`, `7/7`, `7/7`, and `30/30` passed respectively. These tests prove the Orchestrator's contract mapper, canonical wire codec, signed envelope validation, and adapter composition policy at their source boundaries. They do not prove a producer-to-runtime transport call because no producer currently emits the signed NATS request; no mocked boundary was used for the transport probe above.

## Outcome and handoff

The assigned end-to-end path is **not connected**. The bounded evidence is conclusive at both real boundaries: `ts-deploy` emits HTTP JSON with a wider DTO, while the Orchestrator consumes signed NATS request/reply messages with a narrower DTO and envelope. No production change was made, because choosing an HTTP ingress, adding NATS publishing and signing to `ts-deploy`, or changing the consumer contract would select a transport and security design that is not declared by the current source of truth.

Required follow-up decision: choose one authenticated transport and canonical payload contract. Until that decision is made, a live producer-to-runtime-to-consumer success test cannot be added without guessing, and the integration remains an explicit gap.
