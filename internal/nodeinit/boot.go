package nodeinit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	metadataURL      = "http://169.254.169.254/opc/v2/instance/metadata/"
	binaryPath       = "/usr/local/bin/terrascale-orchestrator"
	binaryLink       = "/usr/local/bin/ts-orch"
	imageReleasePath = "/usr/local/lib/ts-orch/image-release.sha256"
	recordedUUID     = "/etc/ts-orch/data-volume-uuid"
	recordedSerial   = "/etc/ts-orch/data-volume-serial"
)

func Boot(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("node-init takes no arguments")
	}
	metadata, err := instanceMetadata(ctx)
	if err != nil {
		return err
	}
	updated, err := installRelease(ctx, metadata[ReleaseURLKey], metadata[ReleaseSHA256Key], out)
	if err != nil {
		return err
	}
	volume := metadata[VolumeKey]
	if volume == "" {
		return errors.New("node-init: no data volume is bound to this instance yet; ts-orch region apply binds one, and ts-node-init.service starts again")
	}
	tail := "installed_sha=" + updated + "\n" + directMounts + updatedRelease + prebuiltUnits
	if recorded(recordedUUID) && recorded(recordedSerial) {
		err = runScript(ctx, "data-volume-rebind", rebindProbe+tail, out)
	} else if updated != "" {
		err = fmt.Errorf("node-init: %s has sha256 %s, not launch release %s, before this instance's first bind; nothing is bound or formatted", binaryPath, updated, metadata[ReleaseSHA256Key])
	} else if err = checkBootBinding(volume, metadata[UUIDKey], metadata[SerialKey], metadata[FormatKey]); err == nil {
		err = runScript(ctx, "data-volume", unmountedTargets+dataVolumeProbe+tail, out, metadata[FormatKey], volume, metadata[UUIDKey], metadata[SerialKey])
	}
	if err != nil {
		return err
	}
	return link()
}

func checkBootBinding(volumeID, expectedUUID, expectedSerial, mayFormat string) error {
	if !volumeIdentity.MatchString(volumeID) || (expectedUUID != "" && !FilesystemUUID.MatchString(expectedUUID)) || (expectedSerial != "" && !DiskSerial.MatchString(expectedSerial)) ||
		(mayFormat != "true" && mayFormat != "false") || (mayFormat == "true" && expectedSerial != "") || (mayFormat == "false" && expectedUUID == "") {
		return fmt.Errorf("node-init: instance metadata binds volume %q with may-format %q, UUID %q and serial %q; a bind needs a volume OCID, may-format true without a serial or false with a UUID", volumeID, mayFormat, expectedUUID, expectedSerial)
	}
	return nil
}

func instanceMetadata(ctx context.Context) (map[string]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := (&http.Client{Timeout: 8 * time.Second}).Do(request)
	if err != nil {
		return nil, fmt.Errorf("node-init: read instance metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node-init: read instance metadata: %s", response.Status)
	}
	var document map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&document); err != nil {
		return nil, fmt.Errorf("node-init: decode instance metadata: %w", err)
	}
	metadata := map[string]string{}
	for _, key := range []string{ReleaseURLKey, ReleaseSHA256Key, VolumeKey, FormatKey, UUIDKey, SerialKey} {
		value, present := document[key]
		text, ok := value.(string)
		if present && !ok {
			return nil, fmt.Errorf("node-init: instance metadata %s is not a string", key)
		}
		metadata[key] = text
	}
	return metadata, nil
}

func installRelease(ctx context.Context, url, sum string, out io.Writer) (string, error) {
	if !sha256Hex.MatchString(sum) || !plainURL.MatchString(url) {
		return "", fmt.Errorf("node-init: instance metadata %s and %s need a plain https URL and a lowercase sha256", ReleaseURLKey, ReleaseSHA256Key)
	}
	installed, err := fileSHA256(binaryPath)
	switch {
	case err == nil && installed == sum:
		fmt.Fprintf(out, "node-init: %s already has sha256 %s\n", binaryPath, sum)
		return "", nil
	case err == nil:
		baked, readErr := os.ReadFile(imageReleasePath)
		if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
			return "", readErr
		}
		if readErr == nil && strings.TrimSpace(string(baked)) == installed {
			if err := download(ctx, url, sum); err != nil {
				return "", err
			}
			fmt.Fprintf(out, "node-init: replaced the image's binary sha256 %s with launch release %s\n", installed, sum)
			return "", nil
		}
		fmt.Fprintf(out, "node-init: %s has sha256 %s, not launch release %s; the self-update's release-installed record must name it\n", binaryPath, installed, sum)
		return installed, nil
	case errors.Is(err, fs.ErrNotExist):
		if err := download(ctx, url, sum); err != nil {
			return "", err
		}
		fmt.Fprintf(out, "node-init: installed %s with sha256 %s\n", binaryPath, sum)
		return "", nil
	default:
		return "", err
	}
}

func download(ctx context.Context, url, sum string) error {
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o755); err != nil {
		return err
	}
	staged, err := os.CreateTemp(filepath.Dir(binaryPath), ".terrascale-orchestrator-*")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 5 * time.Minute}).Do(request)
	if err != nil {
		return fmt.Errorf("node-init: download release: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("node-init: download release %s: %s", url, response.Status)
	}
	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(staged, digest), response.Body); err != nil {
		return fmt.Errorf("node-init: download release: %w", err)
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != sum {
		return fmt.Errorf("node-init: release %s has sha256 %s, instance metadata %s wants %s; nothing installed", url, got, ReleaseSHA256Key, sum)
	}
	if err := staged.Chmod(0o755); err != nil {
		return err
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	if err := staged.Close(); err != nil {
		return err
	}
	if err := os.Rename(staged.Name(), binaryPath); err != nil {
		return err
	}
	return syncDir(filepath.Dir(binaryPath))
}

func link() error {
	if target, err := os.Readlink(binaryLink); err == nil && target == filepath.Base(binaryPath) {
		return nil
	}
	staged := binaryLink + ".node-init"
	if err := os.Remove(staged); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Symlink(filepath.Base(binaryPath), staged); err != nil {
		return err
	}
	if err := os.Rename(staged, binaryLink); err != nil {
		return err
	}
	return syncDir(filepath.Dir(binaryLink))
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func recorded(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func runScript(ctx context.Context, name, script string, out io.Writer, args ...string) error {
	command := exec.CommandContext(ctx, "bash", append([]string{"-c", script, name}, args...)...)
	command.Stdout, command.Stderr = out, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("node-init: %s left the host unbound: %w", name, err)
	}
	return nil
}

const rebindProbe = `set -euo pipefail
device=/dev/oracleoci/oraclevdb
probe_failed() {
 echo "data volume refused: $*" >&2
 exit 1
}
expected_uuid=$(cat /etc/ts-orch/data-volume-uuid) || probe_failed recorded-uuid
[[ $expected_uuid =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || probe_failed recorded-uuid
expected_serial=$(cat /etc/ts-orch/data-volume-serial) || probe_failed recorded-serial
[[ $expected_serial =~ ^[0-9a-fA-F]{32}$ ]] || probe_failed recorded-serial
arrival=$(timeout 120 udevadm wait "$device" 2>&1) || probe_failed device-wait
test -z "$arrival" || probe_failed device-wait-output
test -b "$device" || probe_failed block-device
resolved=$(timeout 10 readlink -f "$device") || probe_failed device-path
test -b "$resolved" || probe_failed device-path
serial=$(timeout 10 lsblk -dnr -o SERIAL "$resolved" 2>&1) || probe_failed disk-serial
test "$serial" = "$expected_serial" || probe_failed expected-serial
fstype=$(timeout 10 blkid -p -s TYPE -o value "$resolved" 2>&1) || probe_failed blkid-type
test "$fstype" = ext4 || probe_failed filesystem-type
uuid=$(timeout 10 blkid -p -s UUID -o value "$resolved" 2>&1) || probe_failed blkid-uuid
test "$uuid" = "$expected_uuid" || probe_failed expected-uuid
`

const directMounts = `mounted=()
unwind() {
 status=$?
 if test "$status" -ne 0; then
  for ((index=${#mounted[@]}-1; index>=0; index--)); do
   umount "${mounted[index]}" || echo "data volume: could not unmount ${mounted[index]}" >&2
  done
 fi
}
trap unwind EXIT
holders=$(timeout 10 blkid -c /dev/null -o device -t UUID="$uuid" 2>&1) || probe_failed uuid-device
test "$holders" = "$resolved" || probe_failed uuid-device
if mountpoint -q /var/lib/ts-data; then
 source=$(findmnt -rn -M /var/lib/ts-data -o SOURCE) || probe_failed data-mount
 source=$(readlink -f "$source") || probe_failed data-mount
 test "$source" = "$resolved" || probe_failed data-mount
 root=$(findmnt -rn -M /var/lib/ts-data -o FSROOT) || probe_failed data-mount
 test "$root" = / || probe_failed data-mount
else
 install -d -m 0755 /var/lib/ts-data
 contents=$(timeout 10 ls -A /var/lib/ts-data) || probe_failed data-directory
 test -z "$contents" || probe_failed data-directory
 mount -t ext4 "$resolved" /var/lib/ts-data
 mounted+=(/var/lib/ts-data)
fi
state_mounted=false
if mountpoint -q /var/lib/ts-orch; then
 data_device=$(findmnt -rn -M /var/lib/ts-data -o MAJ:MIN) || probe_failed state-mount
 state_device=$(findmnt -rn -M /var/lib/ts-orch -o MAJ:MIN) || probe_failed state-mount
 test -n "$data_device" && test "$state_device" = "$data_device" || probe_failed state-mount
 root=$(findmnt -rn -M /var/lib/ts-orch -o FSROOT) || probe_failed state-mount
 test "$root" = /ts-orch || probe_failed state-mount
 state_mounted=true
fi
install -d -m 0755 /var/lib/ts-data/terrabase
install -d -m 0700 /var/lib/ts-data/ts-orch
if test "$state_mounted" = false; then
 install -d -m 0700 /var/lib/ts-orch
 contents=$(timeout 10 ls -A /var/lib/ts-orch) || probe_failed state-directory
 test -z "$contents" || probe_failed state-directory
 mount --bind /var/lib/ts-data/ts-orch /var/lib/ts-orch
 mounted+=(/var/lib/ts-orch)
fi
install -d -m 0755 /usr/local/lib/ts-orch
`

const unmountedTargets = `for target in /var/lib/ts-data /var/lib/ts-orch; do
 if mountpoint -q "$target"; then
  echo "data volume refused: $target is already mounted before this instance's first bind" >&2
  exit 1
 fi
done
`

const updatedRelease = `if test -n "$installed_sha"; then
 timeout 10 python3 -c '
import json, sys
installed = sys.argv[1]
path = "/var/lib/ts-orch/nats/release-installed"
try:
 with open(path) as file:
  record = json.load(file)
except FileNotFoundError:
 sys.exit("/usr/local/bin/terrascale-orchestrator has sha256 " + installed + ", not the launch release, and the self-update recorded no install in " + path)
digests = record.get("sha256") if isinstance(record, dict) else None
if not isinstance(digests, list) or installed not in digests:
 sys.exit("/usr/local/bin/terrascale-orchestrator has sha256 " + installed + ", which neither the launch release nor the self-update record " + path + " names")
' "$installed_sha" || probe_failed installed-binary
fi
`

var prebuiltUnits = mountCheck + "bash /usr/local/lib/ts-orch/data-mount-check.sh || probe_failed mount-check\n" + dropIns("/run/systemd/system", "/usr/bin/env bash")
