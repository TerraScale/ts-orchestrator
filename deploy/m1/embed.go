// Package m1 embeds the milestone 1 host install files so `ts-orch region
// add` can put them in a new host's cloud-init.
package m1

import "embed"

// Files holds the host install files and first-party app release declarations.
// deploy/m1/install.sh also copies the host files over ssh.
//
//go:embed host-runtime.sh ts-orch.service services/netbird-server.service services/app-canary.json services/ts-auth.json services/ts-dashboard.json allowed-keys.json
var Files embed.FS

const NodeList = "{\"sequence\":1,\"nodes\":[{\"name\":\"ts-gru-1\",\"region\":\"gru\",\"public_ip\":\"163.176.124.12\",\"private_ip\":\"10.251.0.11\",\"mesh_ip\":\"10.201.1.1\",\"wg_public_key\":\"KAxe+OOt9S/0cFlYtvhRE+2yIU4x2+YV7UzJ0oLcxCc=\",\"tls_spki_sha256\":\"9e7eecc34411c0faa9645093333beef15098980ec25777dd7068526877f65c30\"},{\"name\":\"ts-sjc-1\",\"region\":\"sjc\",\"public_ip\":\"163.192.54.17\",\"private_ip\":\"10.252.0.3\",\"mesh_ip\":\"10.201.2.1\",\"wg_public_key\":\"9dxcDpYfQFFMb4/1BaYUqoJtaq1Oa6L/uvUhoiLMQlg=\",\"tls_spki_sha256\":\"714406a25906dfadb16e8d2ec84ce9c6f315b7a8fd3a977a50f9d6bca05d4145\"},{\"name\":\"ts-fra-1\",\"region\":\"fra\",\"public_ip\":\"130.162.238.198\",\"private_ip\":\"10.253.0.51\",\"mesh_ip\":\"10.201.3.1\",\"wg_public_key\":\"LIy121PSl7MO4uiQhPbEGqIWTu6kTqZJjMdvTa13RTM=\",\"tls_spki_sha256\":\"0cb9f2dad2a41966e58a6199bea762f44b9a4681686222c350f67ecbd84244f1\"}]}\n"
