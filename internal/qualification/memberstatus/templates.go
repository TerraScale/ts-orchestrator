package memberstatus

import (
	"fmt"
	"path/filepath"
	"strings"
)

func templateQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`;|&()<>*?[]{}!#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
func guestPath(root, path string) string {
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, strings.TrimLeft(path, "/"))
}

const runnerPreamble = `#!/bin/sh
set -eu
RUNNER_STAGE=runner
RUNNER_LOG=
RUNNER_RESULT=FAILED

finish() {
    status=$?
    trap - EXIT
    if [ "$RUNNER_RESULT" = PASS ] && [ "$status" -eq 0 ]; then
        result='@SUCCESS@'
    else
        if [ "$status" -eq 0 ]; then
            status=1
        fi
        result="@PREFIX@FAILED stage=$RUNNER_STAGE status=$status"
        if [ -n "$RUNNER_LOG" ]; then
            printf '%s\n' "$result" >>"$RUNNER_LOG" || :
        fi
    fi
    printf '%s\n' "$result" >&2
    sync || :
    systemctl --no-wall reboot || :
    exit "$status"
}

trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

`

func ShellRunner(guestRoot, rustTestName string) string {
	preamble := strings.NewReplacer("@SUCCESS@", RunnerSuccess, "@PREFIX@", RunnerPrefix).Replace(runnerPreamble)
	return preamble + strings.NewReplacer(
		"@LOG_DIR@", templateQuote(guestPath(guestRoot, "/var/log/ts-member-status-qualification")),
		"@PROBE@", templateQuote(guestPath(guestRoot, "/opt/ts-member-status/memberstatus-probe")),
		"@SERVER@", templateQuote(guestPath(guestRoot, "/opt/ts-member-status/tb-server")),
		"@GO_BINARY@", templateQuote(guestPath(guestRoot, "/opt/ts-member-status/go-host-test")),
		"@RUST_BINARY@", templateQuote(guestPath(guestRoot, "/opt/ts-member-status/rust-test")),
		"@RUST_NAME@", templateQuote(rustTestName), "@GO_TIMEOUT@", GoTestTimeout, "@GO_NAME@", GoTestName,
	).Replace(`LOG_DIR=@LOG_DIR@
mkdir -p "$LOG_DIR"
export TB_MEMBER_STATUS_PROBE_BINARY=@PROBE@
export TB_SERVER_TEST_BINARY=@SERVER@

run_capture() {
    label=$1
    shift
    output="$LOG_DIR/$label.log"
    RUNNER_STAGE=$label
    RUNNER_LOG=$output
    if "$@" >"$output" 2>&1; then
        cat "$output"
        RUNNER_LOG=
    else
        status=$?
        cat "$output"
        exit "$status"
    fi
}

run_capture go-host-test @GO_BINARY@ -test.v -test.timeout=@GO_TIMEOUT@ -test.run=^@GO_NAME@$
run_capture rust-test @RUST_BINARY@ --exact @RUST_NAME@ --nocapture --test-threads=1
RUNNER_RESULT=PASS
exit 0
`)
}

func ManagedVolumeShellRunner(guestRoot string) string {
	preamble := strings.NewReplacer("@SUCCESS@", VolumeRunnerSuccess, "@PREFIX@", VolumeRunnerPrefix).Replace(runnerPreamble)
	return preamble + strings.NewReplacer("@LOG_DIR@", templateQuote(guestPath(guestRoot, "/var/log/ts-managed-volume-qualification")), "@BINARY@", templateQuote(guestPath(guestRoot, "/opt/ts-managed-volume-qualification/host.test")), "@TEST_NAME@", ManagedVolumeGoTestName, "@GO_TIMEOUT@", GoTestTimeout).Replace(`LOG_DIR=@LOG_DIR@
mkdir -p "$LOG_DIR"
run_capture() {
    RUNNER_STAGE=go-host-test
    RUNNER_LOG="$LOG_DIR/go-host-test.log"
    if @BINARY@ -test.run '^@TEST_NAME@$' -test.v -test.timeout=@GO_TIMEOUT@ >"$RUNNER_LOG" 2>&1; then
        cat "$RUNNER_LOG"
        RUNNER_LOG=
    else
        status=$?
        cat "$RUNNER_LOG"
        exit "$status"
    fi
}

run_capture
RUNNER_RESULT=PASS
exit 0
`)
}

func ManagedVolumeSetupScript() string {
	return strings.NewReplacer("@UUID@", ManagedVolumeUUID, "@MOUNT@", templateQuote(MountPath), "@MEMBER@", templateQuote(MemberDir), "@MATERIAL@", templateQuote(MaterialPath), "@CONTROL@", templateQuote(ControlPath)).Replace(`#!/bin/sh
set -eu
EXPECTED_UUID='@UUID@'
DEVICE=/dev/vdb
ALIAS=/dev/oracleoci/oraclevdb
MOUNT=@MOUNT@
BLKID=/usr/sbin/blkid

if [ "${TS_FC_VOLUME_UUID:-}" != "$EXPECTED_UUID" ]; then
    echo "managed volume UUID environment is missing or unexpected" >&2
    exit 1
fi
attempt=0
while [ "$attempt" -lt 120 ]; do
    if [ -b "$DEVICE" ] && [ -e "/dev/disk/by-uuid/$TS_FC_VOLUME_UUID" ] &&
       [ "$(readlink -f "/dev/disk/by-uuid/$TS_FC_VOLUME_UUID")" = "$DEVICE" ]; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.5
done
if [ "$attempt" -ge 120 ]; then
    echo "managed volume did not appear with the pinned UUID" >&2
    exit 1
fi
observed_uuid=$("$BLKID" -s UUID -o value "$DEVICE")
if [ "$observed_uuid" != "$EXPECTED_UUID" ]; then
    echo "managed volume device UUID differs from the pin" >&2
    exit 1
fi
for directory in /srv/ts-managed @MEMBER@ @MATERIAL@ @CONTROL@ "$MOUNT"; do
    if [ -L "$directory" ] || [ ! -d "$directory" ]; then
        echo "managed runtime directory is unsafe: $directory" >&2
        exit 1
    fi
done
chown 0:65534 /srv/ts-managed @MEMBER@ @MATERIAL@ @CONTROL@ "$MOUNT"
chmod 0750 /srv/ts-managed @MEMBER@ @MATERIAL@ "$MOUNT"
chmod 0730 @CONTROL@
for material in @MATERIAL@/authority.tbca @MATERIAL@/trusted-public-key @MATERIAL@/server.crt @MATERIAL@/server.key @MATERIAL@/client-ca.pem @MATERIAL@/server-ca.pem @MATERIAL@/client-managed-manifest.json @MATERIAL@/client-config.json @MATERIAL@/client-chain.pem @MATERIAL@/client-private-key.pem @MATERIAL@/client-api-keys.json; do
    if [ -L "$material" ] || [ ! -f "$material" ]; then
        echo "managed authority material is unsafe: $material" >&2
        exit 1
    fi
    chown 0:65534 "$material"
    chmod 0440 "$material"
done
if [ -L /dev/oracleoci ] || [ -e /dev/oracleoci ] && [ ! -d /dev/oracleoci ]; then
    echo "managed volume alias directory is unsafe" >&2
    exit 1
fi
mkdir -p /dev/oracleoci
if [ -e "$ALIAS" ] || [ -L "$ALIAS" ]; then
    echo "managed volume alias already exists" >&2
    exit 1
fi
ln -s ../vdb "$ALIAS"
if findmnt -rn -S "$DEVICE" >/dev/null 2>&1 ||
   findmnt -rn -S "/dev/disk/by-uuid/$TS_FC_VOLUME_UUID" >/dev/null 2>&1; then
    echo "managed volume device is already mounted" >&2
    exit 1
fi
if mountpoint -q "$MOUNT"; then
    echo "managed volume mountpoint is already mounted" >&2
    exit 1
fi
mount -t ext4 -o rw "$ALIAS" "$MOUNT"
if [ "$(findmnt -n -o TARGET --source "$DEVICE")" != "$MOUNT" ] ||
   [ "$(findmnt -n -o FSTYPE --target "$MOUNT")" != ext4 ] ||
   [ "$(findmnt -n -o OPTIONS --target "$MOUNT" | tr ',' '\n' | grep -xc rw)" -ne 1 ]; then
    echo "managed volume did not mount read-write as ext4" >&2
    exit 1
fi
chown 0:65534 "$MOUNT"
chmod 0750 "$MOUNT"
mkdir -m 0700 "$MOUNT/data" "$MOUNT/replication"
chown 65534:65534 "$MOUNT/data" "$MOUNT/replication"
chmod 0700 "$MOUNT/data" "$MOUNT/replication"
`)
}

func ManagedVolumeSetupUnit(filesystemUUID string) string {
	return fmt.Sprintf(`[Unit]
Description=Prepare the pinned TerraScale managed test volume
After=local-fs.target
Before=%s

[Service]
Type=oneshot
User=root
Environment=TS_FC_VOLUME_UUID=%s
TimeoutStartSec=90s
ExecStart=%s
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
`, ServiceName, filesystemUUID, ManagedVolumeSetupScriptPath)
}

func ServiceUnit(managedVolumeUUID string) string {
	ordering, environment, capabilities := "", "", CapabilityBoundingSet
	if managedVolumeUUID != "" {
		ordering = fmt.Sprintf("Requires=%s\nAfter=%s\n", ManagedVolumeSetupService, ManagedVolumeSetupService)
		environment = "Environment=TS_FC_VOLUME_UUID=" + managedVolumeUUID + "\n"
		capabilities = ManagedVolumeCapabilityBoundingSet
	}
	return fmt.Sprintf(`[Unit]
Description=TerraScale member-status Firecracker qualification
After=local-fs.target
%s

[Service]
Type=oneshot
%sDelegate=yes
DelegateSubgroup=supervisor
MemoryMax=5G
NoNewPrivileges=yes
AmbientCapabilities=
CapabilityBoundingSet=%s
TimeoutStartSec=%ds
KillMode=control-group
StandardOutput=journal+console
StandardError=journal+console
ExecStart=/usr/local/sbin/ts-member-status-qualification

[Install]
WantedBy=multi-user.target
`, ordering, environment, capabilities, GuestServiceTimeoutSeconds)
}
