// Package serviceidentity owns reserved identities installed on owned hosts.
// Numeric IDs are peer pins only after trusted provisioning and file ownership
// validation. Existing conflicting accounts are never modified or adopted.
package serviceidentity

import "fmt"

const (
	Orchestrator    = "terrascale-orchestrator"
	TerraBase       = "terrascale-terrabase"
	SocketGroup     = "terrascale-keylease"
	OrchestratorUID = 62010
	TerraBaseUID    = 62011
	SocketGID       = 62012
	SocketDirectory = "/run/terrascale-keys"
	SocketPath      = SocketDirectory + "/lease.sock"
)

func UID(name string) (int, bool) {
	switch name {
	case Orchestrator:
		return OrchestratorUID, true
	case TerraBase:
		return TerraBaseUID, true
	}
	return 0, false
}

// Bootstrap provisions only the two reserved service accounts and their
// groups. Explicit UID/GID allocation does not depend on distribution system
// account ranges; occupied numbers or names must match the whole local record.
// Supplementary membership is supplied by systemd, never persistent broad
// membership in the orchestrator's private group.
func Bootstrap(name string) string {
	uid, ok := UID(name)
	if !ok {
		return ""
	}
	var script string
	for _, group := range []struct {
		name string
		gid  int
	}{{name, uid}, {SocketGroup, SocketGID}} {
		script += fmt.Sprintf(`if ! /usr/bin/getent group %s >/dev/null; then
  /usr/sbin/groupadd --gid %d %s
fi
/usr/bin/awk -F: '$1 == "%s" { if ($3 != %d || $4 != "") exit 1; found++ } END { if (found != 1) exit 1 }' /etc/group
/usr/bin/test "$(/usr/bin/getent group %d | /usr/bin/cut -d: -f1)" = %s
`, group.name, group.gid, group.name, group.name, group.gid, group.gid, group.name)
	}
	script += fmt.Sprintf(`if ! /usr/bin/getent passwd %s >/dev/null; then
  /usr/sbin/useradd --uid %d --gid %d --no-user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin --no-log-init %s
fi
/usr/bin/awk -F: '$1 == "%s" { if ($3 != %d || $4 != %d || $6 != "/nonexistent" || $7 != "/usr/sbin/nologin") exit 1; found++ } END { if (found != 1) exit 1 }' /etc/passwd
/usr/bin/test "$(/usr/bin/getent passwd %d | /usr/bin/cut -d: -f1)" = %s
/usr/bin/test "$(/usr/bin/id -u %s)" = %d
/usr/bin/test "$(/usr/bin/id -g %s)" = %d
`, name, uid, uid, name, name, uid, uid, uid, name, name, uid, name, uid)
	return script
}

// UnitProperties preserves private primary groups. Only the orchestrator owns
// the shared runtime directory; its privileged access is not given to engines.
func UnitProperties(name string) []string {
	if _, ok := UID(name); !ok {
		return nil
	}
	properties := []string{"SupplementaryGroups=" + SocketGroup}
	directory := "terrascale-keys"
	if name == TerraBase {
		directory = "terrascale-database"
	}
	properties = append(properties, "RuntimeDirectory="+directory, "RuntimeDirectoryMode=0700", "RuntimeDirectoryPreserve=no", "ExecStartPre=/usr/bin/chgrp "+SocketGroup+" /run/"+directory, "ExecStartPre=/usr/bin/chmod 0710 /run/"+directory)

	return properties
}
