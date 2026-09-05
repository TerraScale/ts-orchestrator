package storageplan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/candidatesync"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func key(t *testing.T) (*security.CommandSignatureSigner, []byte, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
}
func encode(t *testing.T, value any) []byte {
	t.Helper()
	b, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func fixture(t *testing.T) (planInput, []byte) {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	owner, public, private := key(t)
	source, sourcePublic, _ := key(t)
	h := strings.Repeat("a", 64)
	now := time.Now().UTC().Add(-time.Minute)
	cfg := configFixture(t)
	sourceBlock, _ := pem.Decode(sourcePublic)
	cfg.Membership.PublicKey = base64.StdEncoding.EncodeToString(sourceBlock.Bytes)
	cfg.Peers[0].MembershipPublicKey = cfg.Membership.PublicKey
	// Existing bootstrap configuration remains JSON v1 on its signed wire.
	cfgRaw, err := json.Marshal(cfg, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	spec := hostmanifest.ComponentSpec{Name: "orchestrator", Version: "1.0.0", ArtifactURL: "https://releases.example/orchestrator", SignatureURL: "https://releases.example/orchestrator.sig", Sha256: h, User: "terrascale-orchestrator", DataVolume: "/var/lib/terrascale/orchestrator", CPUWeight: 100, MemoryMaxBytes: 67108864, IOWeight: 100, Arguments: initialgrant.Arguments, Configuration: string(cfgRaw)}
	manifest, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := nodebootstrap.SignBootstrapGrant(owner, nodebootstrap.BootstrapGrant{Version: 1, GrantID: "initial", NodeID: cfg.NodeID, Manifest: manifest, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := initialgrant.VerifyProof(cfg.NodeID, public, grant)
	if err != nil || proof == nil {
		t.Fatal(err)
	}
	id := proof.Identity()
	p := controltransition.Plan{Version: 1, Mode: controltransition.Mode, EstateID: "launch", TransitionID: "first-r3", IssuedAt: now, ExpiresAt: now.Add(time.Hour), ClusterName: "control-r3", TrustBundleSHA256: h, SourceTopologyEpoch: 1, TargetTopologyEpoch: 2, GlobalElectionFloor: 5, RegionalElectionFloor: 1, Source: controltransition.Source{NodeID: cfg.NodeID, ServerName: cfg.Broker.ServerName, BootstrapGrantSHA256: id.GrantSHA256, InitialManifestSHA256: id.ManifestSHA256, CaptureManifestSHA256: h, LaunchSHA256: id.LaunchSHA256, StoreScopeSHA256: id.StoreScopeSHA256, ProfileSHA256: cfg.ProfileSHA256, StoreDir: cfg.Broker.StoreDir, CaptureDir: "/data/capture", ArchiveDir: "/data/archive", ReceiptPublicKeyPEM: string(sourcePublic)}, Limits: controltransition.Limits{MaxStoreBytes: 64 << 20, MaxStoreFiles: 10000, MaxSnapshotBytes: 8 << 20, MaxTransferBytes: 32 << 20, MaxRestoreBytes: 32 << 20}}
	input := planInput{OwnerPrivateKeyFile: write("private.pem", private), PublicKeyFile: write("public.pem", public), SourceBootstrapGrantFile: write("source.json", grant)}
	clear(private)
	signers := make([]*security.CommandSignatureSigner, 3)
	for i, region := range []string{"gru", "sfo", "fra"} {
		signer, pub, _ := key(t)
		signers[i] = signer
		d := controltransition.Destination{Region: region, NodeID: region + "-1", ServerName: region + "-r3", PreparedManifestSHA256: h, ActivationManifestSHA256: strings.Repeat("b", 64), RouteURL: "nats-route://" + region + ".internal:6222", CertificateSHA256: strings.Repeat(string(rune('d'+i)), 64), ReceiptPublicKeyPEM: string(pub), PreliminaryStoreDir: "/data/preliminary", StoreDir: "/data/r3", StagingDir: "/data/staging", Objects: controltransition.ObjectLocation{OCIRegion: []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i], Namespace: "tenancy", Bucket: region + "-control", BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.launch", OwnershipObservationSHA256: h, Prefix: "control-transitions/first-r3"}}
		signed := grant
		if i > 0 {
			ordinary := spec
			ordinary.Arguments = ""
			ordinary.Configuration = ""
			m, e := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{ordinary}})
			if e != nil {
				t.Fatal(e)
			}
			d.PreparedManifestSHA256 = controltransition.Digest(m)
			signed, err = nodebootstrap.SignBootstrapGrant(owner, nodebootstrap.BootstrapGrant{Version: 1, GrantID: region, NodeID: d.NodeID, Manifest: m, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
		}
		authority, e := nodebootstrap.NewBootstrapAuthority(d.NodeID, public, signed)
		if e != nil {
			t.Fatal(e)
		}
		d.BootstrapGrantSHA256 = authority.Digest()
		input.DestinationBootstrapGrantFiles = append(input.DestinationBootstrapGrantFiles, write(region+".json", signed))
		p.Destinations = append(p.Destinations, d)
	}
	request := preliminarycapture.Request{Version: 1, TransitionID: p.TransitionID, SourceNodeID: p.Source.NodeID, InitialGrantSHA256: id.GrantSHA256, StoreScopeSHA256: id.StoreScopeSHA256, ProfileSHA256: cfg.ProfileSHA256, ControlEpoch: 5, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	for i, account := range []string{cfg.Global.Account, cfg.Regional.Account} {
		request.Accounts = append(request.Accounts, preliminarycapture.AccountInventory{Account: account, Streams: []string{"EVENTS"}})
		p.Accounts = append(p.Accounts, controltransition.Account{Role: []string{"global", "gru-regional"}[i], SourceName: account, DestinationName: account, Streams: []controltransition.Stream{{Name: "EVENTS", SourceConfigSHA256: h, FinalConfigSHA256: h}}})
	}
	requestSigned, err := preliminarycapture.SignRequest(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	receipt := preliminarycapture.Receipt{Version: 1, Preliminary: true, TransitionID: p.TransitionID, RequestSHA256: controltransition.Digest(requestSigned), SourceNodeID: p.Source.NodeID, ControlEpoch: 5, CreatedAt: now.Add(time.Second)}
	for _, a := range request.Accounts {
		k, e := preliminarycapture.ObjectKey(a.Account, "EVENTS", 5)
		if e != nil {
			t.Fatal(e)
		}
		receipt.Objects = append(receipt.Objects, preliminarycapture.Object{Account: a.Account, Stream: "EVENTS", Key: k, SHA256: "sha256:" + h, Size: 1024, CreatedAt: now.Add(time.Second)})
	}
	receiptSigned, err := preliminarycapture.SignReceipt(source, receipt)
	if err != nil {
		t.Fatal(err)
	}
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: p.TransitionID, SourceNodeID: p.Source.NodeID, InitialGrantSHA256: id.GrantSHA256, StoreScopeSHA256: id.StoreScopeSHA256, ProfileSHA256: cfg.ProfileSHA256, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: requestSigned, CaptureReceipt: receiptSigned, RequestSHA256: receipt.RequestSHA256, ReceiptSHA256: controltransition.Digest(receiptSigned), PreparationGrantSHA256: h, Prefix: "preliminary/first-r3", MaxRestoreBytes: p.Limits.MaxRestoreBytes, MaxSnapshotBytes: p.Limits.MaxSnapshotBytes, MaxTotalBytes: p.Limits.MaxTransferBytes}
	for i, d := range p.Destinations {
		o := d.Objects
		scope.Destinations = append(scope.Destinations, preliminarytransfer.Destination{Region: d.Region, OCIRegion: o.OCIRegion, Namespace: o.Namespace, Bucket: o.Bucket, BucketResourceID: o.BucketResourceID, CompartmentID: o.CompartmentID, OwnershipGeneration: 1, OwnershipTags: map[string]string{"terrascale-managed": "orchestrator", "terrascale-region": d.Region}})
		for _, o := range receipt.Objects {
			scope.Objects = append(scope.Objects, preliminarytransfer.ObjectMapping{Region: d.Region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size})
		}
		if i > 0 {
			scope.Candidates = append(scope.Candidates, preliminarytransfer.Candidate{Region: d.Region, NodeID: d.NodeID, ServerName: d.ServerName, BootstrapGrantSHA256: d.BootstrapGrantSHA256, ManifestSHA256: d.PreparedManifestSHA256, ReceiptPublicKeyPEM: d.ReceiptPublicKeyPEM})
		}
	}
	signedScope, err := preliminarytransfer.SignScope(owner, scope)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := preliminarytransfer.VerifyScope(public, signedScope)
	if err != nil {
		t.Fatal(err)
	}
	input.PreliminaryScopeFile = write("scope.json", signedScope)
	p.PreliminaryScopeSHA256 = verified.Digest
	for i, c := range scope.Candidates {
		r := candidatesync.Receipt{Version: 1, PreliminaryOnly: true, ScopeSHA256: verified.Digest, NodeID: c.NodeID, Region: c.Region, PreparationGrantSHA256: scope.PreparationGrantSHA256, BootstrapGrantSHA256: c.BootstrapGrantSHA256, ManifestSHA256: c.ManifestSHA256, SourceReceiptSHA256: scope.ReceiptSHA256, CaptureEpoch: 5, CreatedAt: now.Add(2 * time.Second)}
		for _, o := range scope.Objects {
			if o.Region == c.Region {
				r.Objects = append(r.Objects, candidatesync.ObjectEvidence{Object: o, RestoreSHA256: h})
			}
		}
		raw, e := json.Marshal(r, jsonv1.DefaultOptionsV1())
		if e != nil {
			t.Fatal(e)
		}
		sig, e := signers[i+1].SignCanonicalMaterial(append([]byte("TS-CANDIDATE-PRELIMINARY-VERIFICATION-V1\x00"), raw...))
		if e != nil {
			t.Fatal(e)
		}
		signed := encode(t, struct {
			Payload   jsontext.Value `json:"payload"`
			Signature []byte         `json:"signature"`
		}{raw, sig.Bytes()})
		input.CandidateReceiptFiles = append(input.CandidateReceiptFiles, write(c.Region+"-receipt.json", signed))
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("fixture plan: %v", err)
	}
	input.Plan = p
	return input, public
}

func TestRunSignsOnlyBoundOriginalAndCandidateEvidence(t *testing.T) {
	input, public := fixture(t)
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, encode(t, input), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(t.Context(), path, &out); err != nil {
		t.Fatal(err)
	}
	plan, err := controltransition.VerifyPlan(public, out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Check(time.Now()) != nil {
		t.Fatal("output not live")
	}
	for name, mutate := range map[string]func(*planInput){
		"source store":    func(i *planInput) { i.Plan.Source.StoreDir = "/data/foreign" },
		"source manifest": func(i *planInput) { i.Plan.Source.InitialManifestSHA256 = strings.Repeat("f", 64) },
		"source account":  func(i *planInput) { i.Plan.Accounts[0].SourceName = "OTHER" },
		"destination order": func(i *planInput) {
			i.DestinationBootstrapGrantFiles[1], i.DestinationBootstrapGrantFiles[2] = i.DestinationBootstrapGrantFiles[2], i.DestinationBootstrapGrantFiles[1]
		},
		"receipt order": func(i *planInput) {
			i.CandidateReceiptFiles[0], i.CandidateReceiptFiles[1] = i.CandidateReceiptFiles[1], i.CandidateReceiptFiles[0]
		},
		"missing receipt": func(i *planInput) { i.CandidateReceiptFiles = i.CandidateReceiptFiles[:1] },
		"scope":           func(i *planInput) { i.Plan.PreliminaryScopeSHA256 = strings.Repeat("f", 64) },
		"expiry": func(i *planInput) {
			i.Plan.IssuedAt = time.Now().Add(-2 * time.Hour)
			i.Plan.ExpiresAt = time.Now().Add(-time.Hour)
		},
		"signer": func(i *planInput) {
			_, _, private := key(t)
			i.OwnerPrivateKeyFile = filepath.Join(t.TempDir(), "foreign.pem")
			if err := os.WriteFile(i.OwnerPrivateKeyFile, private, 0600); err != nil {
				t.Fatal(err)
			}
			clear(private)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed planInput
			if err := json.Unmarshal(encode(t, input), &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := os.WriteFile(path, encode(t, changed), 0600); err != nil {
				t.Fatal(err)
			}
			out.Reset()
			if err := Run(t.Context(), path, &out); err == nil || out.Len() != 0 {
				t.Fatal("invalid input emitted plan", err)
			}
		})
	}
	if err := os.WriteFile(path, encode(t, input), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out.Reset()
	if err := Run(ctx, path, &out); !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal(err)
	}
	if err := Run(t.Context(), path, shortWriter{}); err == nil {
		t.Fatal("short write accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

var _ io.Writer = shortWriter{}

func configFixture(t *testing.T) initialgrant.Config {
	t.Helper()
	publicKey := func() string {
		k, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		defer k.Wipe()
		p, err := k.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	membership := base64.StdEncoding.EncodeToString(raw)
	digest := strings.Repeat("a", 64)
	tls := initialgrant.TLSFiles{CAFile: "/keys/ca.pem", CASHA256: digest, CertificateFile: "/keys/cert.pem", CertificateSHA256: digest, KeyFile: "/keys/key.pem"}
	connection := func() initialgrant.Connection {
		return initialgrant.Connection{NKeySeedFile: "/keys/user.seed", PublicNKey: publicKey(), TLS: tls}
	}
	regional, global, rp, gp := connection(), connection(), connection(), connection()
	config := initialgrant.Config{Version: 1, Mode: initialgrant.Mode, Role: "seed", NodeID: "gru-1", Cell: "gru", Instance: "gru-1", SeedInstance: "gru-1", ProfileSHA256: digest,
		Broker:   initialgrant.Broker{Configuration: `{}`, ServerName: "gru-1", StoreDir: "/data/broker", Endpoint: "tls://localhost:4222", StorageBudgetBytes: 4 << 30, TLS: tls},
		Regional: initialgrant.Store{Account: "GRU_CONTROL", Provisioner: &rp, Runtime: regional}, Global: &initialgrant.Store{Account: "GLOBAL_CONTROL", Provisioner: &gp, Runtime: global},
		Membership: initialgrant.Membership{SigningKeyFile: "/keys/member.key", PublicKey: membership, PinsFile: "/keys/pins.json", PinsSHA256: digest},
		Peers:      []initialgrant.Peer{{Instance: "gru-1", RegionalPublicNKey: regional.PublicNKey, GlobalPublicNKey: global.PublicNKey, MembershipPublicKey: membership}}}
	reader := nodeauthority.ReaderConfig{Endpoint: config.Broker.Endpoint, ServerName: config.Broker.ServerName, Account: config.Regional.Account, NKeySeedFile: "/reader/user.seed", PublicNKey: publicKey(), CAFile: "/reader/ca.pem", CASHA256: digest, CertificateFile: "/reader/client.pem", CertificateSHA256: digest, KeyFile: "/reader/client.key"}
	config.AuthorityReader = reader
	config.Peers[0].AuthorityReaderPublicNKey = reader.PublicNKey
	if err = config.Validate(); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestRunRefusesAmbiguousInputAndUnsafeFilesWithoutOutput(t *testing.T) {
	input, _ := fixture(t)
	raw := encode(t, input)
	path := filepath.Join(t.TempDir(), "input.json")
	for name, alter := range map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"publicKeyFile":`), []byte(`"publicKeyFile":"ignored","publicKeyFile":`), 1)
		},
		"case alias": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"publicKeyFile":`), []byte(`"PublicKeyFile":`), 1)
		},
		"nested unknown": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"source":{`), []byte(`"source":{"extra":true,`), 1)
		},
		"trailing": func(b []byte) []byte { return append(bytes.Clone(b), []byte(`{}`)...) },
		"null plan": func(b []byte) []byte {
			var i map[string]jsontext.Value
			if err := json.Unmarshal(b, &i); err != nil {
				t.Fatal(err)
			}
			i["plan"] = jsontext.Value("null")
			return encode(t, i)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, alter(raw), 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := Run(t.Context(), path, &out); err == nil || out.Len() != 0 {
				t.Fatal("ambiguous input emitted plan", err)
			}
		})
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run(t.Context(), path, &out); err == nil || out.Len() != 0 {
		t.Fatal("public input accepted", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := Run(t.Context(), link, &out); err == nil || out.Len() != 0 {
		t.Fatal("symlink input accepted", err)
	}
}
