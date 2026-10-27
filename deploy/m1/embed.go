// Package m1 embeds the milestone 1 host install files so `ts-orch region
// add` can put them in a new host's cloud-init.
package m1

import "embed"

// Files holds the host install files and first-party app release declarations.
// deploy/m1/install.sh also copies the host files over ssh.
//
//go:embed host-runtime.sh ts-orch.service services/app-canary.json services/ts-auth.json services/ts-dashboard.json
var Files embed.FS
