// Package managerbundle embeds the pinned foundation deployment in the control binary.
package managerbundle

import "embed"

// Files contains only NetBird-owned host assets.
//
//go:embed systemd/netbird-backup.service systemd/netbird-backup.timer Caddyfile.netbird dashboard.environment templates/config.yaml.tmpl
var Files embed.FS
