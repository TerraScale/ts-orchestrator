package generationinstall

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/generationtest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

var expected = bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
	ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}

// cell is gru-1's schema-2 material (TS-668) under one root, and its bucket.
type cell struct {
	t        *testing.T
	kv       jetstream.KeyValue
	material generationtest.Material
	roots    trust.Keyring
	key      ed25519.PrivateKey
}

func newCell(t *testing.T) *cell {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true,
		StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "TS_TRUST_ROOTS", MaxValueSize: MaxRecordBytes})
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	roots, _ := trust.ParseKeyring(public)
	now := time.Now()
	material := generationtest.New(t, now).SchemaTwo(t).WithoutIssuers(t).InterRegion(t, now, expected.ControllerSlots)
	return &cell{t: t, kv: kv, material: material, roots: roots, key: private}
}

// sign returns generation number of the material, after previous.
func (c *cell) sign(number uint64, previous []trust.Envelope, issuedAt time.Time) []trust.Envelope {
	c.t.Helper()
	fingerprint := ""
	if len(previous) != 0 {
		fingerprint, _ = trust.Fingerprint(previous[len(previous)-1])
	}
	envelope, err := bootstrap.SignMaterialGeneration(c.material.Generation(expected, number, fingerprint), issuedAt,
		issuedAt.AddDate(0, 6, 0), c.key)
	if err != nil {
		c.t.Fatal(err)
	}
	return append(slices.Clone(previous), envelope)
}

func wire(t *testing.T, chain []trust.Envelope) []byte {
	t.Helper()
	encoded, err := bootstrap.EncodeMaterialGenerationChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (c *cell) leader() Leader {
	return Leader{KV: c.kv, Expected: expected, Roots: func() trust.Keyring { return c.roots },
		Guard: func(context.Context) error { return nil }}
}

func (c *cell) config(slot string) []byte {
	return c.material.Files[bootstrapstart.GenerationConfigFile(slot)]
}

// The record only moves forward, under CAS and the leader's term: an older
// chain, a fork, another cell's chain and a config unlike its pin are
// refused.
func TestLeaderKeepsTheRecordExtensionOnly(t *testing.T) {
	c := newCell(t)
	leader := c.leader()
	ctx := t.Context()
	issued := time.Now().Add(-time.Minute)
	first := c.sign(1, nil, issued)
	second := c.sign(2, first, issued)
	fork := c.sign(2, first, issued.Add(time.Second))
	must := func(status string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	if status := must(leader.Publish(ctx, wire(t, first))); status != "published" {
		t.Fatal(status)
	}
	if status := must(leader.Publish(ctx, wire(t, first))); status != "unchanged" {
		t.Fatal(status)
	}
	if _, err := leader.Arm(ctx, "controller-a", true); err == nil {
		t.Fatal("armed a slot whose pinned config is not stored")
	}
	if _, err := leader.SetConfig(ctx, "controller-a", c.config("controller-b")); err == nil {
		t.Fatal("stored a config unlike its pin")
	}
	must(leader.SetConfig(ctx, "controller-a", c.config("controller-a")))
	if status := must(leader.Arm(ctx, "controller-a", true)); status != "armed" {
		t.Fatal(status)
	}
	if status := must(leader.Publish(ctx, wire(t, second))); status != "published" {
		t.Fatal(status)
	}
	report, err := leader.Report(ctx)
	if err != nil || report.Generation != 2 || len(report.Armed) != 0 || len(report.Configs) != 0 {
		t.Fatalf("a new chain must clear configs and arms: %+v", report)
	}
	other := newCell(t)
	other.material = c.material
	for name, chain := range map[string][]byte{"an older chain": wire(t, first), "a fork": wire(t, fork),
		"another root's chain": wire(t, other.sign(3, second, issued)), "a non-canonical chain": []byte(" " + string(wire(t, second)))} {
		if _, err := leader.Publish(ctx, chain); err == nil {
			t.Errorf("published %s", name)
		}
	}
	if _, err := leader.Arm(ctx, "controller-d", true); err == nil {
		t.Fatal("armed an unknown slot")
	}
	// A write between the read and the CAS, and a fenced leader, store
	// nothing.
	before, err := c.kv.Get(ctx, RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	raced := leader
	raced.Guard = func(ctx context.Context) error {
		_, err := c.kv.Put(ctx, RecordKey, before.Value())
		return err
	}
	if _, err := raced.SetConfig(ctx, "controller-a", c.config("controller-a")); err == nil {
		t.Fatal("a stale revision was written")
	}
	fenced := leader
	fenced.Guard = func(context.Context) error { return errors.New("fenced") }
	if _, err := fenced.SetConfig(ctx, "controller-b", c.config("controller-b")); err == nil {
		t.Fatal("a fenced leader wrote")
	}
	after, err := c.kv.Get(ctx, RecordKey)
	var record Record
	if err != nil || protocol.DecodeStrict(after.Value(), &record, MaxRecordBytes) != nil || len(record.Configs) != 0 {
		t.Fatalf("record changed: %+v %v", record, err)
	}
}

// stager is controller-a's stager over a fake Vault that serves the
// material and records every reference it was asked for.
type stager struct {
	*Stager
	base  string
	asked []bootstrap.SecretReference
}

func (c *cell) stager() *stager {
	c.t.Helper()
	base := c.t.TempDir()
	s := &stager{base: base}
	s.Stager = &Stager{KV: c.kv, Roots: func() trust.Keyring { return c.roots },
		Target: bootstrapstart.GenerationTarget{Slot: "controller-a",
			ManifestSHA256: digest([]byte("manifest of controller-a")), Expected: expected},
		Read: func(_ context.Context, reference bootstrap.SecretReference) ([]byte, error) {
			s.asked = append(s.asked, reference)
			return slices.Clone(c.material.Files[reference.TargetFile]), nil
		},
		Installed: filepath.Join(base, "secrets", bootstrapstart.MaterialGenerationsFile),
		Spool:     filepath.Join(base, "state", "material-generation")}
	return s
}

func (s *stager) spooled(t *testing.T) []string {
	t.Helper()
	var names []string
	err := filepath.WalkDir(s.base, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			relative, _ := filepath.Rel(s.base, path)
			names = append(names, relative)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// The stager fetches only what its slot holds, writes only into its spool,
// arms only while the record arms the slot, and stages nothing for another
// manifest of its slot.
func TestStagerStagesOnlyItsSlot(t *testing.T) {
	c := newCell(t)
	leader := c.leader()
	ctx := t.Context()
	chain := c.sign(1, nil, time.Now().Add(-time.Minute))
	if _, err := leader.Publish(ctx, wire(t, chain)); err != nil {
		t.Fatal(err)
	}
	s := c.stager()
	if status := s.Pass(ctx); status.Error == "" || status.Staged != 0 {
		t.Fatalf("staged without the slot's config: %+v", status)
	}
	if _, err := leader.SetConfig(ctx, "controller-a", c.config("controller-a")); err != nil {
		t.Fatal(err)
	}
	if status := s.Pass(ctx); status.Error != "" || status.Staged != 1 || status.Armed {
		t.Fatalf("stage: %+v", status)
	}
	for _, reference := range s.asked {
		if reference.Slot != "" && reference.Slot != "controller-a" {
			t.Fatalf("fetched another slot's %s", reference.TargetFile)
		}
	}
	for _, name := range s.spooled(t) {
		slotBound := strings.Contains(name, "-controller-")
		if !strings.HasPrefix(name, filepath.Join("state", "material-generation")+"/") ||
			slotBound && !strings.Contains(name, "-controller-a") {
			t.Fatalf("wrote %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(s.Spool, bootstrapstart.GenerationArmedFile)); err == nil {
		t.Fatal("armed without the record arming the slot")
	}
	if _, err := leader.Arm(ctx, "controller-a", true); err != nil {
		t.Fatal(err)
	}
	if status := s.Pass(ctx); !status.Armed {
		t.Fatalf("arm: %+v", status)
	}
	armed, err := os.ReadFile(filepath.Join(s.Spool, bootstrapstart.GenerationArmedFile))
	fingerprint, _ := trust.Fingerprint(chain[0])
	if err != nil || string(armed) != fingerprint {
		t.Fatalf("armed marker %q, %v", armed, err)
	}
	if err := s.report(ctx, s.Pass(ctx)); err != nil {
		t.Fatal(err)
	}
	report, err := leader.Report(ctx)
	if err != nil || report.Slots[0] != (Status{Slot: "controller-a", Staged: 1, Armed: true}) {
		t.Fatalf("report %+v, %v", report, err)
	}
	if _, err := leader.Arm(ctx, "controller-a", false); err != nil {
		t.Fatal(err)
	}
	if status := s.Pass(ctx); status.Armed {
		t.Fatalf("disarm: %+v", status)
	}
	if _, err := os.Stat(filepath.Join(s.Spool, bootstrapstart.GenerationArmedFile)); err == nil {
		t.Fatal("the armed marker survived a disarm")
	}
	// Installed: the spool is cleared.
	if err := os.MkdirAll(filepath.Dir(s.Installed), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Installed, wire(t, chain), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := s.Pass(ctx); status.Installed != 1 || status.Staged != 0 || len(s.spooled(t)) != 1 {
		t.Fatalf("installed: %+v, files %v", status, s.spooled(t))
	}

	other := c.stager()
	other.Target.ManifestSHA256 = digest([]byte("another manifest"))
	if _, err := leader.Arm(ctx, "controller-a", true); err != nil {
		t.Fatal(err)
	}
	if status := other.Pass(ctx); status.Error == "" || status.Armed || len(other.spooled(t)) != 0 {
		t.Fatalf("staged a generation for another manifest: %+v %v", status, other.spooled(t))
	}
}
