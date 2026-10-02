package membership

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Break-glass quorum-loss recovery runs out of band on a stopped survivor.
// Controller authority needs JetStream quorum, so nothing in the controller
// can act while quorum is lost. These helpers only inspect and copy the
// survivor's store; re-founding lost peers reuses the founder replacement
// path with root-signed retirement evidence.

// BackupManifestName lists every backed-up file with its SHA-256 digest.
const BackupManifestName = "SHA256SUMS"

// RecoveryTarget is the local survivor broker the operator recovers.
type RecoveryTarget struct {
	Cell          string
	Slot          string
	StoreDir      string
	ClientAddress string
	RouteAddress  string
}

// Inventory is what the survivor's JetStream store holds on disk.
type Inventory struct {
	Accounts  map[string][]string
	MetaGroup bool
	Files     int
	Bytes     int64
}

// Confirm requires the operator to type phrase exactly. Anything else,
// including end of input, aborts.
func Confirm(in io.Reader, out io.Writer, warning, phrase string) error {
	fmt.Fprintf(out, "\nWARNING: %s\nType %q to continue: ", warning, phrase)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.TrimSpace(line) != phrase {
		return errors.New("confirmation phrase did not match; nothing was changed")
	}
	return nil
}

// BrokerStopped fails while either embedded broker listener accepts TCP, so
// a store is never copied or re-founded under a live server.
func BrokerStopped(ctx context.Context, target RecoveryTarget) error {
	dialer := net.Dialer{Timeout: time.Second}
	for _, address := range []string{target.ClientAddress, target.RouteAddress} {
		if address == "" {
			continue
		}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			return fmt.Errorf("embedded broker still accepts connections on %s; stop the controller service first", address)
		}
	}
	return nil
}

// Preflight checks the survivor is stopped and inventories its store.
func Preflight(ctx context.Context, target RecoveryTarget, out io.Writer) (Inventory, error) {
	if target.Cell == "" || target.Slot == "" || target.StoreDir == "" || !filepath.IsAbs(target.StoreDir) {
		return Inventory{}, errors.New("recovery target needs a cell, slot and absolute store directory")
	}
	if err := BrokerStopped(ctx, target); err != nil {
		return Inventory{}, err
	}
	inventory, err := inventoryStore(target.StoreDir)
	if err != nil {
		return Inventory{}, err
	}
	fmt.Fprintf(out, "survivor %s/%s store %s: %d files, %d bytes, metadata group present=%t\n",
		target.Cell, target.Slot, target.StoreDir, inventory.Files, inventory.Bytes, inventory.MetaGroup)
	accounts := make([]string, 0, len(inventory.Accounts))
	for account := range inventory.Accounts {
		accounts = append(accounts, account)
	}
	slices.Sort(accounts)
	for _, account := range accounts {
		fmt.Fprintf(out, "  account %s streams: %s\n", account, strings.Join(inventory.Accounts[account], ", "))
	}
	return inventory, nil
}

func inventoryStore(root string) (Inventory, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return Inventory{}, err
	}
	if !info.IsDir() {
		return Inventory{}, errors.New("survivor store is not a directory")
	}
	inventory := Inventory{Accounts: make(map[string][]string)}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if entry.IsDir() {
			if len(parts) == 4 && parts[0] == "jetstream" && parts[2] == "streams" {
				inventory.Accounts[parts[1]] = append(inventory.Accounts[parts[1]], parts[3])
			}
			if entry.Name() == "_meta_" {
				inventory.MetaGroup = true
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("survivor store contains a non-regular file %s", relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		inventory.Files++
		inventory.Bytes += info.Size()
		return nil
	})
	return inventory, err
}

// Backup copies the stopped survivor's store to a new directory and writes a
// SHA-256 manifest last, so a partial copy never verifies.
func Backup(ctx context.Context, target RecoveryTarget, destination string, in io.Reader, out io.Writer) error {
	if destination == "" || !filepath.IsAbs(destination) {
		return errors.New("backup destination must be an absolute path")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("backup destination already exists")
	}
	if within(destination, target.StoreDir) || within(target.StoreDir, destination) {
		return errors.New("backup destination must be outside the survivor store")
	}
	if _, err := Preflight(ctx, target, out); err != nil {
		return err
	}
	if err := Confirm(in, out, "this copies the stopped survivor store. Keep the controller stopped until recovery ends.",
		"back up "+target.Cell+"/"+target.Slot); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	var manifest []string
	err := filepath.WalkDir(target.StoreDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(target.StoreDir, path)
		if err != nil || relative == "." {
			return err
		}
		copied := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(copied, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("survivor store contains a non-regular file %s", relative)
		}
		sum, err := copyFile(path, copied)
		if err != nil {
			return err
		}
		manifest = append(manifest, sum+"  "+filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return fmt.Errorf("back up survivor store: %w", err)
	}
	if err := BrokerStopped(ctx, target); err != nil {
		return fmt.Errorf("broker started during backup; discard %s: %w", destination, err)
	}
	slices.Sort(manifest)
	if err := writeSynced(filepath.Join(destination, BackupManifestName),
		[]byte(strings.Join(manifest, "\n")+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(out, "backed up %d files to %s\n", len(manifest), destination)
	return nil
}

// VerifyBackup recomputes every manifest digest and rejects extra files.
func VerifyBackup(dir string) (int, error) {
	data, err := os.ReadFile(filepath.Join(dir, BackupManifestName))
	if err != nil {
		return 0, fmt.Errorf("read backup manifest: %w", err)
	}
	want := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || name == "" || strings.Contains(name, "..") {
			return 0, errors.New("backup manifest is malformed")
		}
		want[name] = sum
	}
	seen := 0
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == BackupManifestName {
			return nil
		}
		expected, ok := want[relative]
		if !ok || !entry.Type().IsRegular() {
			return fmt.Errorf("backup contains unlisted file %s", relative)
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		if sum != expected {
			return fmt.Errorf("backup file %s digest differs", relative)
		}
		seen++
		return nil
	})
	if err != nil {
		return 0, err
	}
	if seen != len(want) {
		return 0, errors.New("backup is missing listed files")
	}
	return seen, nil
}

// Runbook is the documented break-glass procedure. Steps the binary does not
// automate are marked as operator steps.
func Runbook(target RecoveryTarget) string {
	return fmt.Sprintf(`Break-glass quorum-loss recovery for cell %[1]s (survivor %[2]s)

Use only when a majority of controllers is permanently lost and normal slot
replacement cannot run (authority needs JetStream quorum). The most recent
writes acknowledged only by lost controllers may be lost.

 1. Operator: confirm the lost controllers' instances are TERMINATED in OCI
    and cannot return. Terminate any that still exist.
 2. Operator: stop the controller service on every survivor.
 3. On every survivor:  ts-orch cluster recover-quorum preflight --config <controller.json>
 4. On every survivor:  ts-orch cluster recover-quorum backup --config <controller.json> --out <dir>
    then:               ts-orch cluster recover-quorum verify-backup --dir <dir>
    Copy each backup off the host before continuing.
 5. For each lost peer slot, let a survivor render or copy its
    <slot>.retirement-request.json, and root-sign it offline with
    ts-orch bootstrap sign-slot-retirement.
 6. On the seed survivor, as the controller service account:
    ts-orch cluster recover-quorum refound --config <controller.json> --slot <slot> \
        --retirement <slot>.retirement --backup <dir>
    Each lost slot is relaunched as its next ledger attempt with the same
    private IP and NATS server name, so it rejoins the survivor's raft groups
    with an empty store instead of needing a single-node restart.
 7. Operator: start the survivor controller service. The survivor and the
    re-founded peers form a metadata quorum and the peers catch up by
    snapshot. Streams keep their R3 configuration; confirm with the operator
    status commands that every stream reports three current replicas.

A literal single-node restart is not offered: the signed topology fixes the
slot count, and a standalone server does not load R3 streams from its store.
If the seed slot itself is lost, stop here: seed handoff needs a new signed
founder authority.
`, target.Cell, target.Slot)
}

func within(path, root string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, "../")
}

func copyFile(source, destination string) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(output, hash), input); err != nil {
		output.Close()
		return "", err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
