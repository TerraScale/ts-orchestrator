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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/identityrekey"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

var expected = bootstrap.MaterialGenerationExpectation{DeploymentID: "0000000000YY15F5R431V5JPJ9", Environment: "production",
	ClusterID: "00000000006GRRF84JEVN9TX7M", Cell: "GRU", ControllerSlots: []string{"controller-a", "controller-b", "controller-c"}}

// cell is gru-1's v1 material (TS-668) under one root, and its bucket.
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
	material := generationtest.New(t, now).WithoutIssuers(t).InterRegion(t, now, expected.ControllerSlots)
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

func TestDisarmWithdrawsStaleAuthorizationButRetainsLeaderFence(t *testing.T) {
	for _, fault := range []string{"expired", "retired root", "fenced", "CAS conflict"} {
		t.Run(fault, func(t *testing.T) {
			c := newCell(t)
			leader := c.leader()
			chain := wire(t, c.sign(1, nil, time.Now().Add(-time.Minute)))
			if _, err := leader.Publish(t.Context(), chain); err != nil {
				t.Fatal(err)
			}
			if _, err := leader.SetConfig(t.Context(), "controller-a", c.config("controller-a")); err != nil {
				t.Fatal(err)
			}
			if _, err := leader.Arm(t.Context(), "controller-a", true); err != nil {
				t.Fatal(err)
			}
			before, err := c.kv.Get(t.Context(), RecordKey)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "expired":
				leader.Now = func() time.Time { return time.Now().AddDate(1, 0, 0) }
			case "retired root":
				other := newCell(t)
				leader.Roots = func() trust.Keyring { return other.roots }
			case "fenced":
				leader.Guard = func(context.Context) error { return errors.New("fenced") }
			case "CAS conflict":
				leader.Guard = func(ctx context.Context) error {
					_, err := c.kv.Put(ctx, RecordKey, before.Value())
					return err
				}
			}
			status, err := leader.Arm(t.Context(), "controller-a", false)
			refused := fault == "fenced" || fault == "CAS conflict"
			if refused && err == nil || !refused && (err != nil || status != "disarmed") {
				t.Fatalf("disarm %s: %s, %v", fault, status, err)
			}
			after, err := c.kv.Get(t.Context(), RecordKey)
			var record Record
			if err != nil || protocol.DecodeStrict(after.Value(), &record, MaxRecordBytes) != nil ||
				string(record.Chain) != string(chain) || string(record.Configs["controller-a"]) != string(c.config("controller-a")) ||
				slices.Contains(record.Armed, "controller-a") != refused {
				t.Fatalf("disarm changed more than authorization: %v", err)
			}
			if !refused {
				if _, err := leader.Arm(t.Context(), "controller-a", true); err == nil {
					t.Fatal("stale chain gained new authorization")
				}
			}
		})
	}
}

func TestReportInspectsExpiredAndRetiredMaterialWithoutAuthorizingChanges(t *testing.T) {
	for _, fault := range []string{"expired", "retired root", "untrusted root", "tampered signature"} {
		t.Run(fault, func(t *testing.T) {
			c := newCell(t)
			leader, ctx := c.leader(), t.Context()
			chain := c.sign(1, nil, time.Now().Add(-time.Minute))
			if _, err := leader.Publish(ctx, wire(t, chain)); err != nil {
				t.Fatal(err)
			}
			if _, err := leader.SetConfig(ctx, "controller-a", c.config("controller-a")); err != nil {
				t.Fatal(err)
			}
			if _, err := leader.Arm(ctx, "controller-a", true); err != nil {
				t.Fatal(err)
			}
			stager := c.stager()
			fingerprint, err := trust.Fingerprint(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			status := Status{Slot: stager.Target.Slot, DeploymentID: expected.DeploymentID, AcceptanceSHA256: stager.Target.AcceptanceSHA256,
				Fingerprint: fingerprint, Staged: 1, Installed: 1, Armed: true}
			if err := stager.report(ctx, status); err != nil {
				t.Fatal(err)
			}
			historical := c.roots
			switch fault {
			case "expired":
				leader.Now = func() time.Time { return chain[0].ExpiresAt }
			case "retired root", "untrusted root":
				other := newCell(t)
				leader.Roots = func() trust.Keyring { return other.roots }
				if fault == "untrusted root" {
					historical = other.roots
				}
			case "tampered signature":
				chain[0].Signature = strings.Repeat("A", 86)
				record, err := protocol.EncodeJSON(Record{Chain: wire(t, chain)})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.kv.Put(ctx, RecordKey, record); err != nil {
					t.Fatal(err)
				}
			}
			before, err := c.kv.Get(ctx, RecordKey)
			if err != nil {
				t.Fatal(err)
			}
			report, err := leader.Report(ctx, historical)
			if fault == "untrusted root" || fault == "tampered signature" {
				if err == nil {
					t.Fatal("unverified material was reported")
				}
				return
			}
			if err != nil || report.Generation != 1 || report.Fingerprint != fingerprint || !report.ExpiresAt.Equal(chain[0].ExpiresAt) ||
				report.Expired != (fault == "expired") || len(report.Slots) == 0 || report.Slots[0] != status {
				t.Fatalf("historically verified status is not inspectable: %+v, %v", report, err)
			}
			after, err := c.kv.Get(ctx, RecordKey)
			if err != nil || after.Revision() != before.Revision() {
				t.Fatal("inspection mutated the generation record")
			}
			if _, err := leader.Publish(ctx, wire(t, chain)); err == nil {
				t.Fatal("stale generation was republished")
			}
			if _, err := leader.SetConfig(ctx, "controller-a", c.config("controller-a")); err == nil {
				t.Fatal("stale generation authorized config")
			}
			if _, err := leader.Arm(ctx, "controller-a", true); err == nil {
				t.Fatal("stale generation was armed")
			}
			if outcome, err := leader.Arm(ctx, "controller-a", false); err != nil || outcome != "disarmed" {
				t.Fatalf("disarm: %s, %v", outcome, err)
			}
			if report, err := leader.Report(ctx, historical); err != nil || len(report.Armed) != 0 {
				t.Fatalf("successful disarm cannot be reported: %+v, %v", report, err)
			}
		})
	}
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
	report, err := leader.Report(ctx, c.roots)
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
			AcceptanceSHA256: digest([]byte("manifest of controller-a")), Expected: expected,
			Broker: identityrekey.BrokerIdentity{Operator: c.material.OperatorID, SystemAccount: c.material.SystemID,
				CellAccount: c.material.CellID, HostSigner: c.material.HostSignerID, RoleSigner: c.material.RoleSignerID}},
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
	report, err := leader.Report(ctx, c.roots)
	if err != nil || report.Slots[0] != (Status{Slot: "controller-a", Staged: 1, Armed: true, DeploymentID: expected.DeploymentID, AcceptanceSHA256: s.Target.AcceptanceSHA256, Fingerprint: fingerprint}) {
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
	other.Target.AcceptanceSHA256 = digest([]byte("another manifest"))
	if _, err := leader.Arm(ctx, "controller-a", true); err != nil {
		t.Fatal(err)
	}
	if status := other.Pass(ctx); status.Error == "" || status.Armed || len(other.spooled(t)) != 0 {
		t.Fatalf("staged a generation for another manifest: %+v %v", status, other.spooled(t))
	}
}

func TestEqualInstalledChainStillRequiresRootsAndAcceptance(t *testing.T) {
	for _, fault := range []string{"roots", "acceptance", "baseline"} {
		t.Run(fault, func(t *testing.T) {
			c := newCell(t)
			chain := wire(t, c.sign(1, nil, time.Now().Add(-time.Minute)))
			if _, err := c.leader().Publish(t.Context(), chain); err != nil {
				t.Fatal(err)
			}
			s := c.stager()
			if err := os.MkdirAll(filepath.Dir(s.Installed), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(s.Installed, chain, 0o600); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "roots":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				c.roots, err = trust.ParseKeyring(public)
				if err != nil {
					t.Fatal(err)
				}
			case "acceptance":
				s.Target.AcceptanceSHA256 = digest([]byte("another acceptance"))
			case "baseline":
				s.Target.MaterialGenerationSHA256 = digest([]byte("missing accepted baseline"))
			}
			status := s.Pass(t.Context())
			if status.Error == "" || status.Installed != 0 || status.Armed {
				t.Fatalf("equal-wire shortcut accepted invalid %s: %+v", fault, status)
			}
		})
	}
}

func TestSpoolCleanupKeepsUnrelatedAndForeignSlotFiles(t *testing.T) {
	c := newCell(t)
	s := c.stager()
	if err := os.MkdirAll(s.Spool, 0o700); err != nil {
		t.Fatal(err)
	}
	keep := []string{"unrelated.txt", "ca.pem.tmp", ".ca.pem", "controller-b.creds", bootstrapstart.GenerationConfigFile("controller-b")}
	remove := []string{"ca.pem", ".ca.pem.tmp", bootstrapstart.GenerationArmedFile}
	for _, names := range [][]string{keep, remove} {
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(s.Spool, name), []byte("observed"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if status := s.Pass(t.Context()); status.Error != "" {
		t.Fatal(status.Error)
	}
	for _, name := range keep {
		if _, err := os.Stat(filepath.Join(s.Spool, name)); err != nil {
			t.Fatalf("cleanup changed unrelated %s: %v", name, err)
		}
	}
	for _, name := range remove {
		if _, err := os.Stat(filepath.Join(s.Spool, name)); !os.IsNotExist(err) {
			t.Fatalf("cleanup kept local stage %s: %v", name, err)
		}
	}
}

func TestReadinessReportRejectsStaleDeploymentAcceptanceAndGeneration(t *testing.T) {
	c := newCell(t)
	chain := c.sign(1, nil, time.Now().Add(-time.Minute))
	if _, err := c.leader().Publish(t.Context(), wire(t, chain)); err != nil {
		t.Fatal(err)
	}
	s := c.stager()
	fingerprint, err := trust.Fingerprint(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	valid := Status{Slot: s.Target.Slot, DeploymentID: expected.DeploymentID, AcceptanceSHA256: s.Target.AcceptanceSHA256, Fingerprint: fingerprint, Staged: 1, Installed: 1, Armed: true}
	for _, fault := range []string{"deployment", "acceptance", "generation", "current"} {
		status := valid
		switch fault {
		case "deployment":
			status.DeploymentID = "00000000000ZGTG9F4ZD9XG0T1"
		case "acceptance":
			status.AcceptanceSHA256 = digest([]byte("another acceptance"))
		case "generation":
			status.Fingerprint = digest([]byte("another generation"))
		}
		if err := s.report(t.Context(), status); err != nil {
			t.Fatal(err)
		}
		report, err := c.leader().Report(t.Context(), c.roots)
		if err != nil {
			t.Fatal(err)
		}
		if fault == "current" {
			if report.Slots[0] != valid {
				t.Fatalf("current report refused: %+v", report.Slots[0])
			}
		} else if report.Slots[0].Error == "" || report.Slots[0].Staged != 0 || report.Slots[0].Installed != 0 || report.Slots[0].Armed {
			t.Fatalf("stale %s report admitted readiness: %+v", fault, report.Slots[0])
		}
	}
}

func TestReadinessReportAcceptsGenerationWithoutControllerConfigs(t *testing.T) {
	c := newCell(t)
	c.material = generationtest.New(t, time.Now()).WithoutIssuers(t)
	generation := c.material.Generation(expected, 1, "")
	generation.ControllerConfigs = nil
	now := time.Now()
	envelope, err := bootstrap.SignMaterialGeneration(generation, now.Add(-time.Minute), now.Add(time.Hour), c.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.leader().Publish(t.Context(), wire(t, []trust.Envelope{envelope})); err != nil {
		t.Fatal(err)
	}
	s := c.stager()
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		t.Fatal(err)
	}
	status := Status{Slot: s.Target.Slot, DeploymentID: expected.DeploymentID, AcceptanceSHA256: s.Target.AcceptanceSHA256, Fingerprint: fingerprint, Staged: 1, Installed: 1, Armed: true}
	if err := s.report(t.Context(), status); err != nil {
		t.Fatal(err)
	}
	report, err := c.leader().Report(t.Context(), c.roots)
	if err != nil || report.Slots[0] != status {
		t.Fatalf("valid configless report refused: %+v, %v", report, err)
	}
}

func TestVerifiedArmedStageSurvivesVaultOutageAndShutdown(t *testing.T) {
	c := newCell(t)
	leader, ctx := c.leader(), t.Context()
	chain := c.sign(1, nil, time.Now().Add(-time.Minute))
	if _, err := leader.Publish(ctx, wire(t, chain)); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.SetConfig(ctx, "controller-a", c.config("controller-a")); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.Arm(ctx, "controller-a", true); err != nil {
		t.Fatal(err)
	}
	s := c.stager()
	if status := s.Pass(ctx); status.Error != "" || !status.Armed {
		t.Fatalf("initial stage: %+v", status)
	}
	path := filepath.Join(s.Spool, "ca.pem")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	asked := len(s.asked)
	s.Read = func(context.Context, bootstrap.SecretReference) ([]byte, error) {
		t.Fatal("verified stage read Vault again")
		return nil, errors.New("Vault unavailable")
	}
	for range 2 {
		if status := s.Pass(ctx); status.Error != "" || !status.Armed {
			t.Fatalf("unchanged stage: %+v", status)
		}
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || len(s.asked) != asked {
		t.Fatal("verified spool was replaced")
	}
	armed, err := os.ReadFile(filepath.Join(s.Spool, bootstrapstart.GenerationArmedFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"before pass", "during verification"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			roots := s.Roots
			defer func() { s.Roots = roots }()
			if phase == "before pass" {
				cancel()
			} else {
				s.Roots = func() trust.Keyring { cancel(); return c.roots }
			}
			if status := s.Pass(ctx); status.Error == "" {
				t.Fatal("canceled stage reported success")
			}
			got, err := os.ReadFile(filepath.Join(s.Spool, bootstrapstart.GenerationArmedFile))
			after, statErr := os.Stat(path)
			if err != nil || statErr != nil || string(got) != string(armed) || !os.SameFile(before, after) {
				t.Fatal("shutdown disarmed or replaced verified stage")
			}
		})
	}
}

type replacementCancellation struct {
	context.Context
	beforeReplacement func()
}

func (ctx replacementCancellation) Err() error {
	err := ctx.Context.Err()
	if err == nil {
		ctx.beforeReplacement()
	}
	return err
}

func TestShutdownDuringSpoolReplacementPublishesArmedSuccessor(t *testing.T) {
	c := newCell(t)
	leader := c.leader()
	first := c.sign(1, nil, time.Now().Add(-time.Minute))
	stage := func(chain []trust.Envelope) {
		t.Helper()
		if _, err := leader.Publish(t.Context(), wire(t, chain)); err != nil {
			t.Fatal(err)
		}
		if _, err := leader.SetConfig(t.Context(), "controller-a", c.config("controller-a")); err != nil {
			t.Fatal(err)
		}
		if _, err := leader.Arm(t.Context(), "controller-a", true); err != nil {
			t.Fatal(err)
		}
	}
	stage(first)
	s := c.stager()
	if status := s.Pass(t.Context()); status.Error != "" || !status.Armed {
		t.Fatalf("initial stage: %+v", status)
	}
	second := c.sign(2, first, time.Now().Add(-time.Minute))
	stage(second)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reads := len(s.asked)
	// Cancel immediately after the last pre-replacement context check succeeds.
	replacement := replacementCancellation{Context: ctx, beforeReplacement: func() {
		if len(s.asked) > reads {
			cancel()
		}
	}}
	status := s.Pass(replacement)
	if ctx.Err() == nil || status.Error != "" || !status.Armed || status.Staged != 2 {
		t.Fatalf("shutdown left incomplete replacement: %+v, %v", status, ctx.Err())
	}
	actual, err := os.ReadFile(filepath.Join(s.Spool, bootstrapstart.MaterialGenerationsFile))
	if err != nil || !slices.Equal(actual, wire(t, second)) {
		t.Fatalf("successor chain missing after shutdown: %v", err)
	}
	fingerprint, err := trust.Fingerprint(second[1])
	if err != nil {
		t.Fatal(err)
	}
	armed, err := os.ReadFile(filepath.Join(s.Spool, bootstrapstart.GenerationArmedFile))
	if err != nil || string(armed) != fingerprint {
		t.Fatalf("successor armed marker missing after shutdown: %q %v", armed, err)
	}
}

func TestUnverifiedSpoolRefetchesOrDisarms(t *testing.T) {
	for _, fault := range []string{"corrupt", "missing", "changed chain", "changed config", "expired", "roots", "acceptance"} {
		t.Run(fault, func(t *testing.T) {
			c := newCell(t)
			leader, ctx := c.leader(), t.Context()
			first := c.sign(1, nil, time.Now().Add(-time.Minute))
			if _, err := leader.Publish(ctx, wire(t, first)); err != nil {
				t.Fatal(err)
			}
			if _, err := leader.SetConfig(ctx, "controller-a", c.config("controller-a")); err != nil {
				t.Fatal(err)
			}
			if _, err := leader.Arm(ctx, "controller-a", true); err != nil {
				t.Fatal(err)
			}
			s := c.stager()
			if status := s.Pass(ctx); status.Error != "" || !status.Armed {
				t.Fatalf("initial stage: %+v", status)
			}
			switch fault {
			case "corrupt":
				if err := os.WriteFile(filepath.Join(s.Spool, "ca.pem"), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(filepath.Join(s.Spool, "ca.pem")); err != nil {
					t.Fatal(err)
				}
			case "changed chain":
				if _, err := leader.Publish(ctx, wire(t, c.sign(2, first, time.Now()))); err != nil {
					t.Fatal(err)
				}
			case "changed config":
				if err := os.WriteFile(filepath.Join(s.Spool, bootstrapstart.GenerationConfigFile("controller-a")), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "expired":
				s.Now = func() time.Time { return time.Now().AddDate(1, 0, 0) }
			case "roots":
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				roots, err := trust.ParseKeyring(public)
				if err != nil {
					t.Fatal(err)
				}
				s.Roots = func() trust.Keyring { return roots }
			case "acceptance":
				s.Target.AcceptanceSHA256 = digest([]byte("foreign acceptance"))
			}
			reads := 0
			s.Read = func(context.Context, bootstrap.SecretReference) ([]byte, error) {
				reads++
				return nil, errors.New("Vault unavailable")
			}
			status := s.Pass(ctx)
			if status.Error == "" || status.Armed {
				t.Fatalf("invalid stage kept authority: %+v", status)
			}
			if _, err := os.Stat(filepath.Join(s.Spool, bootstrapstart.GenerationArmedFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid stage remained armed")
			}
			if (fault == "corrupt" || fault == "missing" || fault == "changed config") && reads == 0 {
				t.Fatal("invalid local files skipped exact Vault recovery")
			}
		})
	}
}
