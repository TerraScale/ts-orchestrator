package controltransition

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func testKey(t testing.TB) (*security.CommandSignatureSigner, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func testPlan(t testing.TB) Plan {
	t.Helper()
	h := strings.Repeat("a", 64)
	_, sourcePublic := testKey(t)
	p := Plan{Version: 1, Mode: Mode, EstateID: "launch", TransitionID: "first-r3", IssuedAt: time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC), ClusterName: "control-r3", TrustBundleSHA256: h, SourceTopologyEpoch: 1, TargetTopologyEpoch: 2, GlobalElectionFloor: 11, RegionalElectionFloor: 7,
		Source: Source{NodeID: "gru-one", ServerName: "source-r1", BootstrapGrantSHA256: h, InitialManifestSHA256: h, CaptureManifestSHA256: strings.Repeat("b", 64), LaunchSHA256: h, StoreScopeSHA256: h, ProfileSHA256: h, StoreDir: "/data/source", CaptureDir: "/data/capture", ArchiveDir: "/data/archives", ReceiptPublicKeyPEM: string(sourcePublic)},
		Limits: Limits{MaxStoreBytes: 1 << 30, MaxStoreFiles: 10000, MaxSnapshotBytes: 1 << 20, MaxTransferBytes: 1 << 30, MaxRestoreBytes: 1 << 30}}
	p.ExpiresAt = p.IssuedAt.Add(time.Hour)
	for i, region := range []string{"gru", "sfo", "fra"} {
		_, public := testKey(t)
		ociRegion := []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i]
		p.Destinations = append(p.Destinations, Destination{Region: region, NodeID: region + "-one", ServerName: region + "-r3", BootstrapGrantSHA256: h, PreparedManifestSHA256: strings.Repeat("b", 64), ActivationManifestSHA256: strings.Repeat("c", 64), RouteURL: "nats-route://" + region + ".internal:6222", CertificateSHA256: strings.Repeat(string(rune('d'+i)), 64), ReceiptPublicKeyPEM: string(public), PreliminaryStoreDir: "/data/preliminary", StoreDir: "/data/r3", StagingDir: "/data/staging", Objects: ObjectLocation{OCIRegion: ociRegion, Namespace: "tenancy", Bucket: region + "-control", BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.launch", OwnershipObservationSHA256: h, Prefix: "control-transitions/first-r3"}})
	}
	for _, role := range []string{"global", "gru-regional"} {
		p.Accounts = append(p.Accounts, Account{Role: role, SourceName: role, DestinationName: role, Streams: []Stream{{Name: "KV_ORCH_LEADERS", SourceConfigSHA256: h, FinalConfigSHA256: h}, {Name: "ORCH_OPERATIONS", SourceConfigSHA256: h, FinalConfigSHA256: h, Consumers: []Consumer{{Name: "worker", Durable: true, SourceConfigSHA256: h, FinalConfigSHA256: h}}}}})
	}
	return p
}

func TestPlanSignatureLifetimeAndImmutableScope(t *testing.T) {
	p := testPlan(t)
	signer, public := testKey(t)
	signed, err := SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyPlan(public, signed)
	if err != nil {
		t.Fatal(err)
	}
	if v.Digest() != Digest(signed) || v.OwnerKeyID() != signer.PublicKeyID() {
		t.Fatal("signature identity lost")
	}
	for _, now := range []time.Time{p.IssuedAt, p.ExpiresAt.Add(-time.Nanosecond)} {
		if err := v.Check(now); err != nil {
			t.Fatal(err)
		}
	}
	for _, now := range []time.Time{p.IssuedAt.Add(-time.Nanosecond), p.ExpiresAt} {
		if v.Check(now) == nil {
			t.Fatal("expired or future plan accepted")
		}
	}
	if (VerifiedPlan{}).Check(p.IssuedAt) == nil {
		t.Fatal("zero verification accepted")
	}
	if _, err := (VerifiedPlan{}).Plan(); err == nil {
		t.Fatal("zero plan decoded")
	}
	decoded, err := v.Plan()
	if err != nil {
		t.Fatal(err)
	}
	decoded.Destinations[1].NodeID = "sfo-attacker"
	decoded.Accounts[0].Streams[1].Consumers[0].Name = "attacker"
	again, err := v.Plan()
	if err != nil || again.Destinations[1].NodeID != p.Destinations[1].NodeID || again.Accounts[0].Streams[1].Consumers[0].Name != "worker" {
		t.Fatal("caller mutated verified scope")
	}
	_, foreign := testKey(t)
	if _, err := VerifyPlan(foreign, signed); err == nil {
		t.Fatal("foreign owner accepted")
	}
	for _, domain := range []string{"", "TS-CONTROL-CANDIDATE-PREPARATION-V1\x00", "TS-PRELIMINARY-TRANSFER-SCOPE-V1\x00"} {
		raw, err := CanonicalPlan(p)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := signer.SignCanonicalMaterial(append([]byte(domain), raw...))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(signedPlan{Payload: raw, Signature: sig.Bytes()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyPlan(public, wire); err == nil {
			t.Fatal("foreign signature domain accepted")
		}
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"scope tampering": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"globalElectionFloor":11`), []byte(`"globalElectionFloor":12`), 1)
		},
		"duplicate field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
		},
		"unknown field": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":1`), []byte(`"version":1,"extra":true`), 1)
		},
		"alias":      func(b []byte) []byte { return bytes.Replace(b, []byte(`"version":1`), []byte(`"Version":1`), 1) },
		"whitespace": func(b []byte) []byte { return append(b, '\n') },
		"oversize":   func(b []byte) []byte { return bytes.Repeat([]byte("x"), MaximumBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyPlan(public, mutate(bytes.Clone(signed))); err == nil {
				t.Fatal("invalid wire accepted")
			}
		})
	}
	p.Source.ReceiptPublicKeyPEM = string(public)
	if _, err := SignPlan(signer, p); err == nil {
		t.Fatal("owner key authorized on host")
	}
}

func TestPlanRejectsIncompleteConflictingOrUnboundedEffects(t *testing.T) {
	for name, mutate := range map[string]func(*Plan){
		"ordinary mode":                     func(p *Plan) { p.Mode = "run" },
		"missing destination":               func(p *Plan) { p.Destinations = p.Destinations[:2] },
		"reordered regions":                 func(p *Plan) { p.Destinations[1], p.Destinations[2] = p.Destinations[2], p.Destinations[1] },
		"foreign host":                      func(p *Plan) { p.Destinations[1].NodeID = "fra-one" },
		"duplicate route":                   func(p *Plan) { p.Destinations[1].RouteURL = p.Destinations[0].RouteURL },
		"route credentials":                 func(p *Plan) { p.Destinations[1].RouteURL = "nats-route://user:secret@sfo.internal:6222" },
		"route query":                       func(p *Plan) { p.Destinations[1].RouteURL += "?token=secret" },
		"route port":                        func(p *Plan) { p.Destinations[1].RouteURL = "nats-route://sfo.internal:0" },
		"duplicate certificate":             func(p *Plan) { p.Destinations[1].CertificateSHA256 = p.Destinations[0].CertificateSHA256 },
		"source store reused":               func(p *Plan) { p.Destinations[0].StoreDir = p.Source.StoreDir },
		"capture nested in source":          func(p *Plan) { p.Source.CaptureDir = p.Source.StoreDir + "/copy" },
		"destination nested in source":      func(p *Plan) { p.Destinations[0].StagingDir = p.Source.StoreDir + "/staging" },
		"preliminary becomes authoritative": func(p *Plan) { p.Destinations[1].StoreDir = p.Destinations[1].PreliminaryStoreDir },
		"unbound bootstrap":                 func(p *Plan) { p.Destinations[0].BootstrapGrantSHA256 = strings.Repeat("f", 64) },
		"duplicate receipt key":             func(p *Plan) { p.Destinations[1].ReceiptPublicKeyPEM = p.Destinations[0].ReceiptPublicKeyPEM },
		"cross host source key":             func(p *Plan) { p.Destinations[1].ReceiptPublicKeyPEM = p.Source.ReceiptPublicKeyPEM },
		"duplicate bucket":                  func(p *Plan) { p.Destinations[1].Objects.BucketResourceID = p.Destinations[0].Objects.BucketResourceID },
		"wrong OCI region":                  func(p *Plan) { p.Destinations[1].Objects.OCIRegion = "eu-frankfurt-1" },
		"object traversal":                  func(p *Plan) { p.Destinations[1].Objects.Prefix = "control/../escape" },
		"missing ownership observation":     func(p *Plan) { p.Destinations[1].Objects.OwnershipObservationSHA256 = "" },
		"missing account":                   func(p *Plan) { p.Accounts = p.Accounts[:1] },
		"duplicate account":                 func(p *Plan) { p.Accounts[1].DestinationName = p.Accounts[0].DestinationName },
		"duplicate stream":                  func(p *Plan) { p.Accounts[0].Streams[1].Name = p.Accounts[0].Streams[0].Name },
		"missing stream inventory":          func(p *Plan) { p.Accounts[0].Streams = nil },
		"missing consumer config":           func(p *Plan) { p.Accounts[0].Streams[1].Consumers[0].FinalConfigSHA256 = "" },
		"duplicate consumer":                func(p *Plan) { s := &p.Accounts[0].Streams[1]; s.Consumers = append(s.Consumers, s.Consumers[0]) },
		"missing election floor":            func(p *Plan) { p.GlobalElectionFloor = 0 },
		"topology regression":               func(p *Plan) { p.TargetTopologyEpoch = p.SourceTopologyEpoch },
		"unbounded lifetime":                func(p *Plan) { p.ExpiresAt = p.IssuedAt.Add(25 * time.Hour) },
		"unbounded copy":                    func(p *Plan) { p.Limits.MaxStoreBytes = 1 << 40 },
		"unbounded files":                   func(p *Plan) { p.Limits.MaxStoreFiles = 1 << 30 },
		"inadequate transfer":               func(p *Plan) { p.Limits.MaxTransferBytes = p.Limits.MaxSnapshotBytes - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			p := testPlan(t)
			mutate(&p)
			if _, err := CanonicalPlan(p); err == nil {
				t.Fatal("invalid transition plan accepted")
			}
		})
	}
}

func FuzzVerifyPlan(f *testing.F) {
	signer, public := testKey(f)
	signed, err := SignPlan(signer, testPlan(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(public, signed)
	f.Add([]byte(`{}`), []byte(`{}`))
	f.Add([]byte("PUBLIC KEY"), []byte(`{"payload":null,"signature":""}`))
	f.Fuzz(func(t *testing.T, public, signed []byte) {
		v, err := VerifyPlan(public, signed)
		if err == nil {
			p, err := v.Plan()
			if err != nil || p.Validate() != nil || v.Digest() != Digest(signed) {
				t.Fatal("invalid verified plan")
			}
		}
	})
}
