# Node identity and enrolment

Each single-host process creates its node identity before starting its host
services. The private keys stay at /var/lib/ts-orch/node/tls.key (PKCS#8 P-256)
and /var/lib/ts-orch/node/wg.key (base64 X25519, WireGuard encoding). Both files
have mode 0600, survive process restarts and remain on their originating node.
An invalid or incomplete existing pair remains unchanged. Identity errors are
logged once and reported by ts_orch_node_feature_available{feature="identity"};
the host continues serving and receiving releases. Both keys are generated
only when neither exists. The public-key command only reads an existing pair.

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
254. The builder derives mesh_ip as 10.201.<fixed catalog mesh index>.<node index>.
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
deploy/m1/embed.go through a normal repository PR. CI checks their agreement,
a sequence increase for changed list contents, and the uniqueness and
stability of every catalog mesh index.
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
GitHub OIDC token for the main CI workflow. The receiver obtains
deploy/m1/nodes.json from raw.githubusercontent.com at the full commit SHA
covered by that token. GitHub resolves that immutable commit path to the
file in its tree; the release asset is not used for list delivery. This
requires outbound HTTPS to raw.githubusercontent.com and the GitHub Actions
issuer's JWKS endpoint. The repository is public, so no repository access
token is needed. The envelope digest additionally detects a transport
mismatch; authorization rests on the signed commit and its file contents.
Another workflow, pull-request event, non-main ref, repository, unknown
signing key or invalid signature is refused. The download has a 30-second
context; any failed fetch leaves the stored list unchanged.
Sign and push within the token's validity interval; tokens are transport credentials, not persistent node
credentials.

Push uses the existing pinned regional release endpoints. Founders relay
accepted lists through the existing worker release channel; workers repeat
verification before storing them. With an empty list, publish sends nothing.

Each host atomically stores its accepted list and release-run floor under
its state directory at node/nodes.json. A list update does not restart the
binary. Older sequences and older release runs return the stale state without
changing the list, including after restart. Equal sequences must have
identical contents. The newer of the embedded and stored lists wins; accepting a newer embedded list preserves
the release-run floor. The embedded list is authenticated by its binary's
release, while pushed lists are authenticated when received. The local
state directory must remain writable only by the host administrator.

The M1 e2e lane generates its own node and signing keys, exercises the
collection/build/sign/push commands over a local release listener and
checks signature, digest, replay and restart behavior. The host flow also
checks that single-host startup creates its private keys and preserves them
through a service restart.

## Before the list decides anything

Today a change that reaches the main branch can cause the main CI workflow
to sign a list. Required human review for the list file and immutable
release assets are decisions to make before a later slice consumes the
list. This slice does not use the list to change mesh membership, release
delivery or host pinning.

A stored-list error is logged once and reported by
ts_orch_node_feature_available{feature="list"}. The list handler then refuses
list requests while the host continues serving and accepting binary
releases. Startup opens the list once. An error never replaces an existing
node identity or changes its private key files.
