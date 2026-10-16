package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// Real clean-commit ELF candidates, Git ancestry, filesystem persistence,
// independent signatures and the OCI SDK/HTTP sequence store are exercised.
// Provider endpoints and the qualifying CI result are fixture-local.
func TestBundleRetainsQualifiedSignedReleaseWithoutSource(t *testing.T) {
	f := newApplyHTTPFixture(t)
	migrationPath := writeBundleMigration(t, f)
	env := bundleFixtureEnv(t, f)
	checks := atomic.Int64{}
	check := env.check
	env.check = func(q release.Qualification, digest string) error {
		checks.Add(1)
		return check(q, digest)
	}
	// One regional proof is absent; every other region must still be retained.
	missing := filepath.Join(f.releaseDir, "production", "SFO", "amd64", "production.json")
	proof, err := os.ReadFile(missing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle")
	args := bundleFixtureArgs(f, migrationPath, out)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.bundleWith(args, env); err == nil || !strings.Contains(err.Error(), "SFO") {
		t.Fatalf("regional refusal lost: %v\n%s", err, output.String())
	}
	if checks.Load() != 1 || f.inspections.Load() != 1 {
		t.Fatalf("shared checks repeated: source=%d binary=%d", checks.Load(), f.inspections.Load())
	}
	first := readBundleChannel(t, out, "GRU")
	if first.ReleaseSequence != 621 || first.RunNumber != 620 {
		t.Fatalf("signer sequence changed historical CI provenance: %+v", first)
	}
	for _, cell := range []string{"GRU", "FRA"} {
		channel := readBundleChannel(t, out, cell)
		if _, err := channel.Verify(f.roots, cell, "production", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if channel.ReleaseSequence != first.ReleaseSequence {
			t.Fatal("regions received different release sequences")
		}
		if err := c.verifyProductionArtifacts(filepath.Join(out, "production"), f.roots, cell, "production",
			map[string]binaryReceipt{"amd64": f.binary}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "SFO", "channel.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused region has an apply input: %v", err)
	}
	f.mu.Lock()
	for cell, objects := range f.objects {
		for name := range objects {
			if cell != "GRU" || name != release.SequenceObject("orchestrator", "production") {
				t.Errorf("producer mutated regional release object: %s %s", cell, name)
			}
		}
	}
	f.mu.Unlock()
	// Retrying cannot replace the already published local bundle.
	if err := c.bundleWith(args, env); err == nil || !strings.Contains(err.Error(), "must not exist") {
		t.Fatalf("existing output overwritten: %v", err)
	}
	if checks.Load() != 1 || f.inspections.Load() != 1 {
		t.Fatal("existing output accessed producer inputs")
	}
	if got := readBundleChannel(t, out, "GRU"); got.ReleaseSequence != first.ReleaseSequence {
		t.Fatal("existing bundle changed")
	}
	// Restoring this region and producing to a fresh output reuses the durable
	// reservation of the same content identity after a producer restart.
	if err := os.WriteFile(missing, proof, 0o600); err != nil {
		t.Fatal(err)
	}
	retry := filepath.Join(t.TempDir(), "bundle")
	if err := c.bundleWith(bundleFixtureArgs(f, migrationPath, retry), env); err != nil {
		t.Fatalf("retained producer retry: %v\n%s", err, output.String())
	}
	if got := readBundleChannel(t, retry, "SFO"); got.ReleaseSequence != first.ReleaseSequence {
		t.Fatal("producer restart allocated another sequence for identical content")
	}
	// The root remains an existing independent trust input, outside the bundle.
	rootPath := filepath.Join(t.TempDir(), "root.pub")
	root, err := os.ReadFile(f.rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, root, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{f.sourceDir, f.releaseDir} {
		if err := os.Rename(directory, directory+"-unavailable"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Rename(directory+"-unavailable", directory) })
	}
	// Apply must never call any producer boundary once inputs disappear.
	applyEnv := f.env
	applyEnv.check = func(release.Qualification, string) error {
		t.Error("apply queried CI")
		return errors.New("CI unavailable")
	}
	applyEnv.git = func(context.Context, ...string) (string, error) {
		t.Error("apply queried source")
		return "", errors.New("source unavailable")
	}
	applyEnv.secret = func(context.Context, string, string) ([]byte, error) {
		t.Error("apply requested signer secret")
		return nil, errors.New("signer unavailable")
	}
	if err := c.applyWith([]string{"--dir", out, "--root-key", rootPath, "--namespace", "ns"}, applyEnv); err != nil {
		t.Fatalf("source-independent bundle apply: %v\n%s", err, output.String())
	}
}

func TestBundleRefusesBeforeCredentialsOrOutput(t *testing.T) {
	f := newApplyHTTPFixture(t)
	migrationPath := writeBundleMigration(t, f)
	for _, cell := range []string{"FRA", "GRU", "SFO"} {
		if err := os.Remove(filepath.Join(f.releaseDir, "production", cell, "amd64", "production.json")); err != nil {
			t.Fatal(err)
		}
	}
	env := bundleFixtureEnv(t, f)
	var secretReads atomic.Int64
	env.secret = func(context.Context, string, string) ([]byte, error) {
		secretReads.Add(1)
		return nil, errors.New("signing credential must remain unread")
	}
	out := filepath.Join(t.TempDir(), "bundle")
	args := []string{"--dir", f.releaseDir, "--out", out, "--source-revision", f.binary.SourceRevision,
		"--root-key", f.rootPath, "--source-checkout", f.sourceDir, "--namespace", "ns", "--sequence-migration", migrationPath,
		"--update-delegation-secret", "unavailable", "--signing-key-secret", "unavailable", "--vault-id", "invalid-vault",
		"--cell", "FRA", "--cell", "GRU", "--cell", "SFO", "--arch", "amd64"}
	if err := (command{ctx: t.Context(), output: io.Discard}).bundleWith(args, env); err == nil {
		t.Fatal("unqualified release produced a bundle")
	}
	if secretReads.Load() != 0 {
		t.Fatal("unqualified release read signer credentials")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed bundle published an output: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for cell, objects := range f.objects {
		if len(objects) > 0 {
			t.Errorf("unqualified release mutated %s: %v", cell, objects)
		}
	}
}

func writeBundleMigration(t *testing.T, f *applyHTTPFixture) string {
	t.Helper()
	private, err := readDelegatedPrivateKey(f.leafPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	public := private.Public().(ed25519.PublicKey)
	keyID, _ := trust.KeyID(public)
	encoded, _ := trust.EncodeDelegatedPublicKey(public)
	migration := release.SequenceMigration{Schema: release.SequenceMigrationSchema, Namespace: "ns", Bucket: "gru-1-head", Region: "GRU",
		SignerKeyID: keyID, SignerPublicKey: encoded, Role: "orchestrator", Environment: "production", SequenceFloor: 620}
	for _, cell := range []string{"GRU", "SFO", "FRA"} {
		migration.Regions = append(migration.Regions, release.SequenceFloor{Cell: cell, RunNumber: 620,
			IssuedAt: time.Now().UTC().Add(-time.Minute), EvidenceSHA256: f.binary.SHA256})
	}
	envelope, err := release.SignSequenceMigration(migration, time.Now().UTC(), f.rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "migration.json")
	if err := os.WriteFile(path, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func bundleFixtureArgs(f *applyHTTPFixture, migration, output string) []string {
	return []string{"--dir", f.releaseDir, "--out", output, "--source-revision", f.binary.SourceRevision,
		"--root-key", f.rootPath, "--source-checkout", f.sourceDir, "--namespace", "ns", "--sequence-migration", migration,
		"--update-delegation", f.delegationPath, "--signing-key", f.leafPath,
		"--cell", "GRU", "--cell", "SFO", "--cell", "FRA", "--arch", "amd64"}
}

func bundleFixtureEnv(t *testing.T, f *applyHTTPFixture) deployEnv {
	t.Helper()
	env := f.env
	env.check = func(q release.Qualification, digest string) error { return q.MatchBinary(f.binary, digest) }
	env.git = func(ctx context.Context, args ...string) (string, error) {
		// Keep fixture Git entirely local while production retains its pinned
		// source-host check. Ancestry and fetch still execute the real Git tool.
		if len(args) >= 3 && args[2] == "remote" {
			return "https://github.com/" + release.QualificationRepository + ".git", nil
		}
		if len(args) >= 3 && args[2] == "fetch" {
			return runGit(ctx, "-C", f.sourceDir, "fetch", "--quiet", "--no-tags", f.sourceDir,
				"refs/heads/main:refs/remotes/origin/main")
		}
		return runGit(ctx, args...)
	}
	return env
}

func readBundleChannel(t *testing.T, directory, cell string) releasechannel.Channel {
	t.Helper()
	wire, err := os.ReadFile(filepath.Join(directory, cell, "channel.json"))
	if err != nil {
		t.Fatal(err)
	}
	var channel releasechannel.Channel
	if err := json.Unmarshal(wire, &channel); err != nil {
		t.Fatal(err)
	}
	return channel
}
