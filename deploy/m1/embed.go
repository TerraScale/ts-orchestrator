// Package m1 embeds the milestone 1 host install files so `ts-orch region
// add` can put them in a new host's cloud-init.
package m1

import "embed"

// Files holds host-runtime.sh and ts-orch.service, which deploy/m1/install.sh
// also copies over ssh.
//
//go:embed host-runtime.sh ts-orch.service
var Files embed.FS
