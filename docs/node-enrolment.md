# Node identity and enrolment

Each single-host process creates its node identity before starting its host
services. The private keys stay at /var/lib/ts-orch/node/tls.key (PKCS#8 P-256)
and /var/lib/ts-orch/node/wg.key (base64 X25519, WireGuard encoding). Both files
have mode 0600, survive process restarts and remain on their originating node.
An invalid existing key fails startup instead of replacing the identity.

The node keys are independent of the release listener's existing identity.
The node list supplies public identity to subsequent mesh consumers. It does
not change the mesh transport, the release listener certificate or regional
host pinning.

## Collect and build

Run the public-key command on each enrolled host through the existing
authenticated operator SSH path:

    ssh NODE 'sudo ts-orch node keys' > NODE-public.json

An optional positional STATE directory selects another local state directory.
Only wg_public_key and tls_spki_sha256 appear in that output. Never collect
either private key file. For each node, combine that public output with its
reviewed name, region and addresses:

    jq --arg name "$node_name" --arg region "$region" \
      --arg public_ip "$public_ip" --arg private_ip "$private_ip" \
      '. + {name:$name,region:$region,public_ip:$public_ip,private_ip:$private_ip}' \
      "$node_name-public.json" > "$node_name-entry.json"
    jq -s '.' *-entry.json > inventory.json
    ts-orch node list build "$sequence" inventory.json deploy/m1/nodes.json
    make generate

Names are ts-<lowercase catalog region>-<index>, with node indices 1 through
254. The builder derives mesh_ip as 10.201.<catalog index + 1>.<node index>.
This reserves 10.201.0.0/16 for node mesh addresses. It is separate from the
documented regional VCN, container, NetBird and ts-ops allocations; consult
[the address plan](network/address-plan.md) before adding network routes.

The list is one JSON object with sequence and nodes. Every node has name,
region, public_ip, private_ip, mesh_ip, wg_public_key and tls_spki_sha256.
The sequence is a positive integer and must increase for every content
change. Duplicate identities, keys or addresses and incorrect derived mesh
addresses are refused. No nodes have been enrolled in the shipped list:
sequence zero and an empty nodes array mean that no list is available.

Review and merge deploy/m1/nodes.json and its generated embedded bytes in
deploy/m1/embed.go through a normal repository PR. CI checks their agreement.
Adding, replacing or removing a node follows the same collect, rebuild,
review and publish procedure. The existing regional provisioning command
continues to maintain its release listener pins independently.

## Sign and publish

Main CI retains nodes.json alongside the binaries in its run's release.
The binary embeds the reviewed list. After binary release push, CI runs:

    ts-orch release nodes publish "$GITHUB_SHA" deploy/m1/nodes.json

For a separate list delivery within the same authorized CI run, without
installing a binary, the equivalent commands are:

    ts-orch release nodes sign "$GITHUB_SHA" deploy/m1/nodes.json > nodes-release.json
    ts-orch release nodes push nodes-release.json

These commands require the existing GitHub Actions OIDC environment and
id-token: write permission. The signed request has kind nodes, sha, artifact
(url and sha256), and token. As with binary releases, the signature is the
GitHub OIDC token for the main CI workflow, and the artifact URL must belong
to that exact signed commit and run. A token from another workflow, an
unknown signing key, an invalid signature or a different run's artifact
is refused. The receiver downloads only that run's nodes.json and verifies
its SHA-256 and schema before accepting it. Sign and push within the token's
validity interval; tokens are transport credentials, not persistent node
credentials.

Push uses the existing pinned regional release endpoints. Founders relay
accepted lists through the existing worker release channel; workers repeat
verification before storing them. With an empty list, publish sends nothing.

Each host atomically stores its accepted list and release-run floor under
its state directory at node/nodes.json. A list update does not restart the
binary. Older sequences and older release runs are refused, including after
restart. Equal sequences must have identical contents. The newer of the
embedded and stored lists wins; accepting a newer embedded list preserves
the release-run floor. The embedded list is authenticated by its binary's
release, while pushed lists are authenticated when received. The local
state directory must remain writable only by the host administrator.

The M1 e2e lane generates its own node and signing keys, exercises the
collection/build/sign/push commands over a local release listener and
checks signature, digest, replay and restart behavior. The host flow also
checks that single-host startup creates its private keys and preserves them
through a service restart.
