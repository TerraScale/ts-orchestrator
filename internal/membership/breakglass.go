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
	"syscall"
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

// Confirm requires the operator to type phrase exactly, ending with a
// newline. Anything else, including end of input before a newline, aborts.
func Confirm(in io.Reader, out io.Writer, warning, phrase string) error {
	fmt.Fprintf(out, "\nWARNING: %s\nType %q to continue: ", warning, phrase)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return fmt.Errorf("confirmation was not entered; nothing was changed: %w", err)
	}
	if strings.TrimSpace(line) != phrase {
		return errors.New("confirmation phrase did not match; nothing was changed")
	}
	return nil
}

// errNoBrokerListener rejects a target with no listener to probe: such a
// target can establish neither a stopped nor a running broker.
var errNoBrokerListener = errors.New("recovery target needs the embedded broker's fixed client and route listener addresses")

// BrokerStopped succeeds only when every embedded broker listener positively
// refuses TCP connections, so a store is never copied under a live server.
// A timeout, an unreachable or unresolvable address, or cancellation proves
// nothing about the broker and fails the check.
func BrokerStopped(ctx context.Context, target RecoveryTarget) error {
	addresses, err := target.listeners()
	if err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: time.Second}
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			return fmt.Errorf("embedded broker still accepts connections on %s; stop the controller service first", address)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return fmt.Errorf("cannot establish that the broker on %s is stopped: %w", address, err)
		}
	}
	return nil
}

// BrokerRunning succeeds when an embedded broker listener accepts TCP. The
// data-bearing survivor must be running before any lost peer is re-founded,
// so an empty replacement can only join the survivor's metadata group and
// never forms a new one with another empty replacement.
func BrokerRunning(ctx context.Context, target RecoveryTarget) error {
	addresses, err := target.listeners()
	if err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: time.Second}
	var last error
	for _, address := range addresses {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			conn.Close()
			return nil
		}
		last = err
	}
	return fmt.Errorf("survivor broker is not accepting connections; start the survivor controller service first: %w", last)
}

func (target RecoveryTarget) listeners() ([]string, error) {
	var addresses []string
	for _, address := range []string{target.ClientAddress, target.RouteAddress} {
		if address == "" {
			continue
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || host == "" || port == "" || port == "0" || strings.HasPrefix(port, "-") {
			return nil, errNoBrokerListener
		}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return nil, errNoBrokerListener
	}
	return addresses, nil
}

// Preflight checks the survivor is stopped and inventories its store.
func Preflight(ctx context.Context, target RecoveryTarget, out io.Writer) (Inventory, error) {
	if target.Cell == "" || target.Slot == "" || target.StoreDir == "" || !filepath.IsAbs(target.StoreDir) {
		return Inventory{}, errors.New("recovery target needs a cell, slot and absolute store directory")
	}
	if _, err := target.listeners(); err != nil {
		return Inventory{}, err
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
// SHA-256 manifest last, so a partial copy never verifies. The manifest
// records which survivor and store it was taken from, and the copy must hold
// exactly what Preflight inventoried, so a store modified during the copy
// never verifies. A failed backup removes its destination.
func Backup(ctx context.Context, target RecoveryTarget, destination string, in io.Reader, out io.Writer) (err error) {
	if destination == "" || !filepath.IsAbs(destination) {
		return errors.New("backup destination must be an absolute path")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("backup destination already exists")
	}
	// Compare physical paths: a symlinked ancestor must not place the
	// backup inside the store it copies (or the store inside the backup).
	store, err := filepath.EvalSymlinks(target.StoreDir)
	if err != nil {
		return fmt.Errorf("resolve survivor store: %w", err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("resolve backup destination parent: %w", err)
	}
	physical := filepath.Join(parent, filepath.Base(destination))
	if within(physical, store) || within(store, physical) ||
		within(destination, target.StoreDir) || within(target.StoreDir, destination) {
		return errors.New("backup destination must be outside the survivor store")
	}
	inventory, err := Preflight(ctx, target, out)
	if err != nil {
		return err
	}
	if err := Confirm(in, out, "this copies the stopped survivor store. Keep the controller stopped until recovery ends.",
		"back up "+target.Cell+"/"+target.Slot); err != nil {
		return err
	}
	if err := os.Mkdir(physical, 0o700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(physical)
		}
	}()
	var manifest []string
	var copiedBytes int64
	err = filepath.WalkDir(target.StoreDir, func(path string, entry fs.DirEntry, err error) error {
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
		copied := filepath.Join(physical, relative)
		if entry.IsDir() {
			return os.Mkdir(copied, 0o700)
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("survivor store contains a non-regular file %s", relative)
		}
		sum, size, err := copyFile(path, copied)
		if err != nil {
			return err
		}
		copiedBytes += size
		manifest = append(manifest, sum+"  "+filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return fmt.Errorf("back up survivor store: %w", err)
	}
	if err := BrokerStopped(ctx, target); err != nil {
		return fmt.Errorf("broker started during backup: %w", err)
	}
	if len(manifest) != inventory.Files || copiedBytes != inventory.Bytes {
		return fmt.Errorf("survivor store changed during backup: inventoried %d files (%d bytes), copied %d files (%d bytes)",
			inventory.Files, inventory.Bytes, len(manifest), copiedBytes)
	}
	slices.Sort(manifest)
	header := backupProvenance{Cell: target.Cell, Slot: target.Slot, StoreDir: target.StoreDir,
		TakenAt: time.Now().UTC().Truncate(time.Second)}.lines()
	if err := writeSynced(filepath.Join(physical, BackupManifestName),
		[]byte(strings.Join(append(header, manifest...), "\n")+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(out, "backed up %d files to %s\n", len(manifest), destination)
	return nil
}

// backupProvenance binds a backup to the survivor and store it copied.
type backupProvenance struct {
	Cell     string
	Slot     string
	StoreDir string
	TakenAt  time.Time
}

const backupProvenancePrefix = "# "

func (provenance backupProvenance) lines() []string {
	return []string{
		backupProvenancePrefix + "cell " + provenance.Cell,
		backupProvenancePrefix + "slot " + provenance.Slot,
		backupProvenancePrefix + "store " + provenance.StoreDir,
		backupProvenancePrefix + "taken " + provenance.TakenAt.Format(time.RFC3339),
	}
}

// BackupMaxAge bounds how old a backup refound accepts as the survivor's
// safety copy.
const BackupMaxAge = 24 * time.Hour

// VerifyBackup recomputes every manifest digest and rejects extra, missing,
// duplicated or escaping entries.
func VerifyBackup(dir string) (int, error) {
	_, files, err := verifyBackup(dir)
	return files, err
}

// VerifyBackupFor verifies a backup and that it was taken from target's
// store within maxAge of now.
func VerifyBackupFor(dir string, target RecoveryTarget, now time.Time, maxAge time.Duration) (int, error) {
	provenance, files, err := verifyBackup(dir)
	if err != nil {
		return 0, err
	}
	if provenance.Cell != target.Cell || provenance.Slot != target.Slot || provenance.StoreDir != target.StoreDir {
		return 0, fmt.Errorf("backup was taken from %s/%s store %s, not this survivor",
			provenance.Cell, provenance.Slot, provenance.StoreDir)
	}
	if provenance.TakenAt.IsZero() || provenance.TakenAt.After(now.Add(time.Minute)) ||
		now.Sub(provenance.TakenAt) > maxAge {
		return 0, fmt.Errorf("backup taken at %s is not a current survivor backup",
			provenance.TakenAt.Format(time.RFC3339))
	}
	return files, nil
}

func verifyBackup(dir string) (backupProvenance, int, error) {
	data, err := os.ReadFile(filepath.Join(dir, BackupManifestName))
	if err != nil {
		return backupProvenance{}, 0, fmt.Errorf("read backup manifest: %w", err)
	}
	var provenance backupProvenance
	want := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if header, ok := strings.CutPrefix(line, backupProvenancePrefix); ok {
			key, value, _ := strings.Cut(header, " ")
			switch key {
			case "cell":
				provenance.Cell = value
			case "slot":
				provenance.Slot = value
			case "store":
				provenance.StoreDir = value
			case "taken":
				provenance.TakenAt, _ = time.Parse(time.RFC3339, value)
			default:
				return backupProvenance{}, 0, errors.New("backup manifest is malformed")
			}
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || !validBackupName(name) {
			return backupProvenance{}, 0, errors.New("backup manifest is malformed")
		}
		if _, duplicate := want[name]; duplicate {
			return backupProvenance{}, 0, fmt.Errorf("backup manifest lists %s twice", name)
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
		return backupProvenance{}, 0, err
	}
	if seen != len(want) {
		return backupProvenance{}, 0, errors.New("backup is missing listed files")
	}
	return provenance, seen, nil
}

// validBackupName accepts a relative slash path with no empty, "." or ".."
// element; names that merely contain two dots are valid.
func validBackupName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || name == BackupManifestName {
		return false
	}
	for _, element := range strings.Split(name, "/") {
		if element == "" || element == "." || element == ".." {
			return false
		}
	}
	return true
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
 5. For each lost peer slot, render its retirement request on a survivor:
    ts-orch cluster recover-quorum render-retirement --config <controller.json> \
        --slot <slot> --out <dir>
    (or copy a <slot>.retirement-request.json the leader rendered before
    quorum was lost), then root-sign it offline with
    ts-orch bootstrap sign-slot-retirement.
 6. Operator: start the controller service on every survivor again. A lone
    survivor waits for quorum without authority, but its broker runs. The
    data-bearing survivor must be running before any lost peer boots:
    re-founded peers start with empty stores, and two of them without the
    survivor could elect an empty metadata group of their own.
 7. On the seed survivor, as the controller service account, one lost slot
    at a time:
    ts-orch cluster recover-quorum refound --config <controller.json> --slot <slot> \
        --retirement <slot>.retirement --backup <dir>
    refound refuses while the survivor broker is not running. Each lost slot
    is relaunched as its next ledger attempt with the same private IP and
    NATS server name, so it rejoins the survivor's raft groups with an empty
    store (the survivor's longer log wins every election) instead of needing
    a single-node restart. Wait until the re-founded peer reports current in
    the metadata group before re-founding the next slot.
 8. Confirm with the operator status commands that every stream reports
    three current replicas. Streams keep their R3 configuration.

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

func copyFile(source, destination string) (string, int64, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", 0, err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(output, hash), input)
	if err != nil {
		output.Close()
		return "", 0, err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return "", 0, err
	}
	if err := output.Close(); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
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
