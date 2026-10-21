package foundation

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/ociresourcetest"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// This scenario crosses the real SQLite process/filesystem and signed OCI SDK
// HTTP boundaries. Its raw scope tests concrete archive/SDK helpers, not manager
// admission or the public APIs with genuine signed constructor proofs.
// The loopback OCI protocol server persists both region copies.
func TestBackupArchivePersistentIdentityAndProtectedCopies(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	data := filepath.Join(root, "original", "data")
	if err := os.MkdirAll(filepath.Join(data, "idp"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config.yaml")
	configBytes := []byte("server:\n  store:\n    encryptionKey: preserved-data-key\n  auth:\n    sessionCookieEncryptionKey: preserved-cookie-key\n")
	if err := os.WriteFile(config, configBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "idp", "signing.key"), []byte("preserved-private-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	sqlite(t, ctx, data, `
import sqlite3, sys
from pathlib import Path
root = Path(sys.argv[1])
with sqlite3.connect(root / 'store.db') as db:
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE peers (id TEXT, public_key TEXT)')
    db.execute("INSERT INTO peers VALUES ('peer-original', 'wireguard-original')")
with sqlite3.connect(root / 'idp.db') as db:
    db.execute('CREATE TABLE policy (id TEXT, source TEXT, destination TEXT)')
    db.execute("INSERT INTO policy VALUES ('policy-original', 'gru', 'sjc')")
`)
	// The writer has uncommitted changes in both stores. Graceful shutdown
	// commits them before the snapshot may read either file.
	writerProcess := exec.CommandContext(ctx, "python3", "-c", `
import sqlite3, sys
from pathlib import Path
root = Path(sys.argv[1])
peers = sqlite3.connect(root / 'store.db')
policy = sqlite3.connect(root / 'idp.db')
peers.execute("INSERT INTO peers VALUES ('peer-at-shutdown', 'wireguard-at-shutdown')")
policy.execute("INSERT INTO policy VALUES ('policy-at-shutdown', 'fra', 'gru')")
print('ready', flush=True)
sys.stdin.readline()
peers.commit()
policy.commit()
peers.close()
policy.close()
`, data)
	input, err := writerProcess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := writerProcess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := writerProcess.Start(); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("SQLite writer did not become ready: %v", err)
	}
	var stopWriter = func() error {
		if err := input.Close(); err != nil {
			return err
		}
		return writerProcess.Wait()
	}
	defer func() {
		if stopWriter != nil {
			_ = stopWriter()
		}
	}()
	var resumed atomic.Bool
	var public atomic.Bool
	var unlocked atomic.Bool
	var failSJC atomic.Bool
	var puts atomic.Int32
	var requests atomic.Int32
	var foreignInventory atomic.Bool
	objects := t.TempDir()
	factory, endpoint := ociresourcetest.Server(t, func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		parts := strings.SplitN(strings.TrimPrefix(request.URL.Path, "/n/tenancy/b/"), "/", 3)
		bucket := parts[0]
		if bucket != "netbird-gru" && bucket != "netbird-sjc" {
			http.Error(w, "wrong admitted bucket", 400)
			return
		}
		region := "sa-saopaulo-1"
		if bucket == "netbird-sjc" {
			region = "us-sanjose-1"
		}
		bucketID, kmsID := "ocid1.bucket.oc1."+region+"."+bucket, "ocid1.key.oc1."+region+"."+bucket
		if len(parts) == 1 {
			privacy := "NoPublicAccess"
			if public.Load() {
				privacy = "ObjectRead"
			}
			writeJSON(t, w, map[string]any{"id": bucketID, "name": bucket, "namespace": "tenancy", "compartmentId": "ocid1.compartment.oc1..control", "kmsKeyId": kmsID,
				"publicAccessType": privacy, "etag": "bucket-etag", "timeCreated": "2026-01-01T00:00:00Z", "createdBy": "foundation"})
			return
		}
		if parts[1] == "retentionRules" {
			locked := "2020-01-01T00:00:00Z"
			if unlocked.Load() {
				locked = "2099-01-01T00:00:00Z"
			}
			writeJSON(t, w, map[string]any{"items": []any{map[string]any{"id": "retention", "displayName": "foundation-retention", "etag": "retention-etag",
				"timeCreated": "2020-01-01T00:00:00Z", "timeModified": "2020-01-01T00:00:00Z", "timeRuleLocked": locked,
				"duration": map[string]any{"timeAmount": 7, "timeUnit": "DAYS"}}}})
			return
		}
		if len(parts) == 2 && parts[1] == "o" && request.Method == http.MethodGet {
			var inventory []map[string]any
			bucketDir := filepath.Join(objects, bucket)
			err := filepath.WalkDir(bucketDir, func(name string, entry os.DirEntry, walkErr error) error {
				if os.IsNotExist(walkErr) {
					return nil
				}
				if walkErr != nil || entry.IsDir() {
					return walkErr
				}
				relative, err := filepath.Rel(bucketDir, name)
				if err != nil {
					return err
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if strings.HasPrefix(relative, request.URL.Query().Get("prefix")) {
					inventory = append(inventory, map[string]any{"name": relative, "size": info.Size()})
				}
				return nil
			})
			if err != nil {
				t.Error(err)
			}
			slices.SortFunc(inventory, func(a, b map[string]any) int { return strings.Compare(a["name"].(string), b["name"].(string)) })
			start := request.URL.Query().Get("start")
			inventory = slices.DeleteFunc(inventory, func(object map[string]any) bool { return object["name"].(string) < start })
			if foreignInventory.Load() {
				inventory = []map[string]any{{"name": "netbird/foundation/v1/foreign.tar", "size": 1}}
			}
			page := map[string]any{"objects": inventory}
			if len(inventory) > 1 {
				page["objects"], page["nextStartWith"] = inventory[:1], inventory[1]["name"]
			}
			writeJSON(t, w, page)
			return
		}
		if len(parts) != 3 || parts[1] != "o" || !filepath.IsLocal(parts[2]) {
			http.Error(w, "invalid object request", 400)
			return
		}
		name := filepath.Join(objects, bucket, parts[2])
		switch request.Method {
		case http.MethodPut:
			if !resumed.Load() {
				t.Error("server remained stopped during the remote upload")
			}
			if failSJC.Load() && bucket == "netbird-sjc" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"code":"NotAuthorized","message":"scope refused"}`)
				return
			}
			wire, err := io.ReadAll(request.Body)
			if err != nil {
				t.Error(err)
				return
			}
			digest := sha256.Sum256(wire)
			if request.Header.Get("if-none-match") != "*" || request.Header.Get("opc-sse-kms-key-id") != kmsID ||
				request.Header.Get("opc-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) || request.ContentLength != int64(len(wire)) {
				t.Error("upload lost immutable write, regional KMS or checksum protection")
				http.Error(w, "invalid protection headers", 400)
				return
			}
			if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
				t.Error(err)
				return
			}
			file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				w.WriteHeader(412)
				return
			}
			if _, err := file.Write(wire); err != nil {
				t.Error(err)
			}
			if err := file.Close(); err != nil {
				t.Error(err)
			}
			puts.Add(1)
			w.Header().Set("etag", "archive-etag")
			w.WriteHeader(200)
		case http.MethodGet:
			wire, err := os.ReadFile(name)
			if err != nil {
				http.Error(w, "absent", 404)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(wire)))
			w.Header().Set("etag", "archive-etag")
			_, _ = w.Write(wire)
		default:
			http.Error(w, "unexpected method", 405)
		}
	})
	installation := entityid.Derive("netbird-backup-integration", "installation")
	scope := backupScope{InstallationID: installation, StoreGeneration: entityid.Derive("netbird-foundation-store", installation) + ":1", TenancyID: "ocid1.tenancy.oc1..t", Namespace: "tenancy"}
	for i, region := range [2]string{"sa-saopaulo-1", "us-sanjose-1"} {
		bucket := [2]string{"netbird-gru", "netbird-sjc"}[i]
		scope.Destinations[i] = backupDestination{Region: region, Bucket: bucket, BucketID: "ocid1.bucket.oc1." + region + "." + bucket, CompartmentID: "ocid1.compartment.oc1..control", KMSKeyID: "ocid1.key.oc1." + region + "." + bucket}
	}
	var targets [2]BackupTarget
	for i, region := range []string{"sa-saopaulo-1", "us-sanjose-1"} {
		regional, err := ociclient.New(factory.Provider(), ociclient.Options{Region: region})
		if err != nil {
			t.Fatal(err)
		}
		client, err := regional.ObjectStorage()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, endpoint)
		targets[i] = BackupTarget{client: client, scope: scope, index: i}
	}
	var paused atomic.Int32
	quiesce := func(context.Context) (func(context.Context) error, error) {
		paused.Add(1)
		resumed.Store(false)
		if stopWriter != nil {
			err := stopWriter()
			stopWriter = nil
			if err != nil {
				return nil, err
			}
		}
		return func(context.Context) error { resumed.Store(true); return nil }, nil
	}
	// Raw facts confer no current manager authority on any public operation.
	beforeRequests, beforePaused := requests.Load(), paused.Load()
	if _, err := NewBackupTargets(ctx, factory, region.FoundationResolver{}, region.VerifiedNetBirdManager{}); err == nil {
		t.Fatal("constructor accepted absent manager proof")
	}
	if _, err := Backup(ctx, data, config, targets, quiesce); err == nil {
		t.Fatal("backup accepted raw target facts")
	}
	if _, err := LatestBackup(ctx, targets[1]); err == nil {
		t.Fatal("inventory accepted raw target facts")
	}
	if _, err := Restore(ctx, targets[1], "foreign", filepath.Join(root, "unadmitted")); err == nil {
		t.Fatal("restore accepted raw target facts")
	}
	if requests.Load() != beforeRequests || paused.Load() != beforePaused {
		t.Fatal("absent authority caused remote or service effects")
	}
	if _, err := os.Lstat(filepath.Join(root, "unadmitted")); !os.IsNotExist(err) {
		t.Fatal("absent authority touched replacement identity")
	}
	swapped := [2]BackupTarget{targets[1], targets[0]}
	if _, err := Backup(ctx, data, config, swapped, quiesce); err == nil {
		t.Fatal("backup accepted reversed regional slots")
	}
	mismatched := targets
	mismatched[1].scope.Namespace = "foreign"
	if _, err := Backup(ctx, data, config, mismatched, quiesce); err == nil {
		t.Fatal("backup accepted different complete scopes")
	}
	started := time.Now()
	record, err := backupArchiveFixture(t, ctx, data, config, targets, quiesce)
	if err != nil {
		t.Fatal(err)
	}
	if puts.Load() != 2 || !resumed.Load() {
		t.Fatalf("protected copies=%d resumed=%v", puts.Load(), resumed.Load())
	}
	latest, err := targets[1].latestBackup(ctx)
	if err != nil || latest != record {
		t.Fatalf("automatic remote discovery changed the snapshot: %v", err)
	}
	foreignInventory.Store(true)
	if _, err := targets[1].latestBackup(ctx); err == nil {
		t.Fatal("inventory accepted an object outside the exact scope prefix")
	}
	foreignInventory.Store(false)
	// Neither the selected destination nor its surviving peer can be transplanted.
	for _, mutate := range []struct {
		name   string
		change func(*backupScope)
	}{
		{"generation", func(s *backupScope) { s.StoreGeneration = strings.TrimSuffix(s.StoreGeneration, ":1") + ":2" }},
		{"installation", func(s *backupScope) {
			s.InstallationID = entityid.Derive("netbird-backup-integration", "foreign")
			s.StoreGeneration = entityid.Derive("netbird-foundation-store", s.InstallationID) + ":1"
		}},
		{"tenancy", func(s *backupScope) { s.TenancyID = "ocid1.tenancy.oc1..foreign" }},
		{"namespace", func(s *backupScope) { s.Namespace = "foreign" }},
		{"GRU destination", func(s *backupScope) { s.Destinations[0].BucketID += "foreign" }},
		{"SJC destination", func(s *backupScope) { s.Destinations[1].BucketID += "foreign" }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			foreign := targets[1]
			mutate.change(&foreign.scope)
			before := requests.Load()
			if err := foreign.download(ctx, record.Object, io.Discard); err == nil || requests.Load() != before {
				t.Fatal("foreign object scope reached remote GET")
			}
			// Rehashing/renaming the original archive cannot replace its manifest scope.
			archive, err := os.Open(filepath.Join(objects, "netbird-sjc", record.Object))
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			forgedObject := record.Object
			if prefix, err := foreign.scope.prefix(); err == nil {
				originalPrefix, err := scope.prefix()
				if err != nil {
					t.Fatal(err)
				}
				forgedObject = prefix + strings.TrimPrefix(record.Object, originalPrefix)
			}
			missingParent := filepath.Join(root, "absent-"+strings.ReplaceAll(mutate.name, " ", "-"))
			stage, _, err := extractBackup(ctx, archive, foreign.scope, forgedObject, filepath.Join(missingParent, "identity"))
			if err == nil || stage != "" || !strings.Contains(err.Error(), "scope") && !strings.Contains(err.Error(), "generation") {
				t.Fatalf("foreign manifest was not rejected before staging: %v", err)
			}
			if _, err := os.Lstat(missingParent); !os.IsNotExist(err) {
				t.Fatal("foreign manifest touched replacement parent")
			}
		})
	}
	// Even a digest-valid, correctly named archive must carry exact scope/time.
	for _, malformed := range []struct {
		name     string
		manifest backupManifest
		unknown  bool
	}{
		{name: "unscoped legacy", manifest: backupManifest{Version: 1, CreatedAt: record.CreatedAt}},
		{name: "missing scope", manifest: backupManifest{Version: 2, CreatedAt: record.CreatedAt}},
		{name: "wrong manifest generation", manifest: func() backupManifest {
			m := backupManifest{Version: 2, CreatedAt: record.CreatedAt, Scope: scope}
			m.Scope.StoreGeneration += "foreign"
			return m
		}()},
		{name: "wrong timestamp", manifest: backupManifest{Version: 2, CreatedAt: record.CreatedAt.Add(time.Second), Scope: scope}},
		{name: "unknown member", manifest: backupManifest{Version: 2, CreatedAt: record.CreatedAt, Scope: scope}, unknown: true},
	} {
		t.Run(malformed.name, func(t *testing.T) {
			wire, err := json.Marshal(malformed.manifest)
			if err != nil {
				t.Fatal(err)
			}
			if malformed.unknown {
				wire = append([]byte(`{"unexpected":1,`), wire[1:]...)
			}
			var body bytes.Buffer
			writer := tar.NewWriter(&body)
			if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Size: int64(len(wire)), Mode: 0o600}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(wire); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			archive, err := os.CreateTemp(t.TempDir(), "manifest-*.tar")
			if err != nil {
				t.Fatal(err)
			}
			defer archive.Close()
			if _, err := archive.Write(body.Bytes()); err != nil {
				t.Fatal(err)
			}
			prefix, err := scope.prefix()
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body.Bytes())
			object := prefix + record.CreatedAt.Format("20060102T150405.000000000Z") + "/" + hex.EncodeToString(digest[:]) + ".tar"
			missingParent := filepath.Join(root, "absent-malformed-"+strings.ReplaceAll(malformed.name, " ", "-"))
			if stage, _, err := extractBackup(ctx, archive, scope, object, filepath.Join(missingParent, "identity")); err == nil || stage != "" || !strings.Contains(err.Error(), "manifest") {
				t.Fatalf("invalid manifest reached staging: %v", err)
			}
			if _, err := os.Lstat(missingParent); !os.IsNotExist(err) {
				t.Fatal("invalid manifest created a replacement directory")
			}
		})
	}
	// Losing the entire first host and its region's copy still permits recovery.
	if err := os.RemoveAll(filepath.Dir(data)); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(objects, "netbird-gru")); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement")
	created, err := restoreArchiveFixture(t, ctx, targets[1], record.Object, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Equal(record.CreatedAt) {
		t.Fatal("recovery time changed")
	}
	gotConfig, err := os.ReadFile(filepath.Join(replacement, "config.yaml"))
	if err != nil || !bytes.Equal(gotConfig, configBytes) {
		t.Fatalf("encryption material changed: %v", err)
	}
	key, err := os.ReadFile(filepath.Join(replacement, "data", "idp", "signing.key"))
	if err != nil || string(key) != "preserved-private-identity" {
		t.Fatalf("signing identity changed: %v", err)
	}
	sqlite(t, ctx, filepath.Join(replacement, "data"), `
import sqlite3, sys
from pathlib import Path
root = Path(sys.argv[1])
for name in ('store.db', 'idp.db'):
    with sqlite3.connect(root / name) as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
with sqlite3.connect(root / 'store.db') as db:
    assert db.execute('SELECT id, public_key FROM peers ORDER BY id').fetchall() == [('peer-at-shutdown', 'wireguard-at-shutdown'), ('peer-original', 'wireguard-original')]
with sqlite3.connect(root / 'idp.db') as db:
    assert db.execute('SELECT id, source, destination FROM policy ORDER BY id').fetchall() == [('policy-at-shutdown', 'fra', 'gru'), ('policy-original', 'gru', 'sjc')]
`)
	t.Logf("isolated persistent-store recovery=%s recoverable-data-age=%s source-bytes=%d", time.Since(started), time.Since(created), record.Bytes)
	if _, err := restoreArchiveFixture(t, ctx, targets[1], record.Object, replacement); err == nil {
		t.Fatal("restore overwrote an existing identity")
	}
	// Reject a protection downgrade before quiescing the real service.
	for _, downgrade := range []*atomic.Bool{&public, &unlocked} {
		downgrade.Store(true)
		before := paused.Load()
		if _, err := backupArchiveFixture(t, ctx, filepath.Join(replacement, "data"), filepath.Join(replacement, "config.yaml"), targets, quiesce); err == nil || paused.Load() != before {
			t.Fatal("unprotected backup stopped the service or was accepted")
		}
		downgrade.Store(false)
	}
	// Snapshot and cancellation failures resume through an uncancelled context
	// and leave no unencrypted temporary archives on the original host.
	if _, err := backupArchiveFixture(t, ctx, filepath.Join(replacement, "data"), filepath.Join(root, "missing-config"), targets, quiesce); err == nil || !resumed.Load() {
		t.Fatal("snapshot failure did not resume the server")
	}
	cancelled, cancelSnapshot := context.WithCancel(ctx)
	if _, err := backupArchiveFixture(t, cancelled, filepath.Join(replacement, "data"), filepath.Join(replacement, "config.yaml"), targets,
		func(context.Context) (func(context.Context) error, error) {
			resumed.Store(false)
			cancelSnapshot()
			return func(restart context.Context) error {
				resumed.Store(true)
				return restart.Err()
			}, nil
		}); err == nil || !resumed.Load() {
		t.Fatal("cancelled snapshot left the foundation stopped")
	}
	if leftovers, err := filepath.Glob(filepath.Join(replacement, ".netbird-backup-*")); err != nil || len(leftovers) != 0 {
		t.Fatalf("unencrypted archive remained after cancellation: %v", err)
	}
	// Partial remote failure keeps the successful copy and returns an error.
	failSJC.Store(true)
	partial, err := backupArchiveFixture(t, ctx, filepath.Join(replacement, "data"), filepath.Join(replacement, "config.yaml"), targets, quiesce)
	if err == nil || !resumed.Load() {
		t.Fatal("partial copy failure claimed success or left the service stopped")
	}
	if _, err := os.Stat(filepath.Join(objects, "netbird-gru", partial.Object)); err != nil {
		t.Fatal("partial failure lost its successful regional copy")
	}
	// A damaged remote body is never installed on a replacement.
	objectPath := filepath.Join(objects, "netbird-sjc", record.Object)
	wire, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	wire[len(wire)/2] ^= 1
	if err := os.WriteFile(objectPath, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	badReplacement := filepath.Join(root, "damaged-replacement")
	if _, err := restoreArchiveFixture(t, ctx, targets[1], record.Object, badReplacement); err == nil {
		t.Fatal("corrupt remote archive was accepted")
	}
	if _, err := os.Lstat(badReplacement); !os.IsNotExist(err) {
		t.Fatal("failed recovery published a partial replacement")
	}
	// Even a digest-valid archive cannot write outside the replacement root.
	var malicious bytes.Buffer
	writer := tar.NewWriter(&malicious)
	manifest, err := json.Marshal(backupManifest{Version: 2, CreatedAt: record.CreatedAt, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ name, body string }{{"manifest.json", string(manifest)}, {"data/../../escaped", "bad"}} {
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Size: int64(len(entry.body)), Mode: 0o600}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(malicious.Bytes())
	prefix, err := scope.prefix()
	if err != nil {
		t.Fatal(err)
	}
	maliciousObject := prefix + record.CreatedAt.Format("20060102T150405.000000000Z") + "/" + hex.EncodeToString(digest[:]) + ".tar"
	if err := os.WriteFile(filepath.Join(objects, "netbird-sjc", maliciousObject), malicious.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := restoreArchiveFixture(t, ctx, targets[1], maliciousObject, badReplacement); err == nil {
		t.Fatal("archive traversal was accepted")
	}
	if _, err := os.Lstat(filepath.Join(root, "escaped")); !os.IsNotExist(err) {
		t.Fatal("recovery escaped its isolated root")
	}
	failSJC.Store(false)
	newest, err := backupArchiveFixture(t, ctx, filepath.Join(replacement, "data"), filepath.Join(replacement, "config.yaml"), targets, quiesce)
	if err != nil {
		t.Fatal(err)
	}
	latest, err = targets[1].latestBackup(ctx)
	if err != nil || latest != newest {
		t.Fatalf("paginated discovery did not choose the newest recoverable archive: %v", err)
	}
}

// backupArchiveFixture joins the real local snapshot and SDK archive helpers;
// it deliberately has no production admission proof or public-API success claim.
func backupArchiveFixture(t *testing.T, ctx context.Context, data, config string, targets [2]BackupTarget,
	quiesce func(context.Context) (func(context.Context) error, error),
) (record BackupRecord, err error) {
	t.Helper()
	for _, target := range targets {
		if err := target.protectedBucket(ctx); err != nil {
			return record, err
		}
	}
	archive, err := os.CreateTemp(filepath.Dir(data), ".netbird-backup-*.tar")
	if err != nil {
		return record, err
	}
	defer func() { err = errors.Join(err, archive.Close(), os.Remove(archive.Name())) }()
	record, err = snapshotBackup(ctx, archive, data, config, targets[0].scope, quiesce)
	if err != nil {
		return record, err
	}
	for _, target := range targets {
		if err := target.upload(ctx, archive, record); err != nil {
			return record, err
		}
	}
	return record, nil
}

func restoreArchiveFixture(t *testing.T, ctx context.Context, target BackupTarget, object, replacement string) (created time.Time, err error) {
	t.Helper()
	if err := target.protectedBucket(ctx); err != nil {
		return created, err
	}
	archive, err := os.CreateTemp(filepath.Dir(replacement), ".netbird-restore-*.tar")
	if err != nil {
		return created, err
	}
	defer func() { err = errors.Join(err, archive.Close(), os.Remove(archive.Name())) }()
	if err := target.download(ctx, object, archive); err != nil {
		return created, err
	}
	stage, created, err := extractBackup(ctx, archive, target.scope, object, replacement)
	if err != nil {
		return created, err
	}
	defer os.RemoveAll(stage)
	return created, publishBackup(stage, replacement)
}

func sqlite(t *testing.T, ctx context.Context, directory, script string) {
	t.Helper()
	command := exec.CommandContext(ctx, "python3", "-c", script, directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("SQLite integration process: %v\n%s", err, output)
	}
}

func writeJSON(t *testing.T, writer http.ResponseWriter, value any) {
	t.Helper()
	wire, err := json.Marshal(value)
	if err != nil {
		t.Error(err)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(wire)
}
