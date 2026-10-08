package bootstrapmaterial

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func interRegionFixture(t *testing.T) (string, string, InterRegionConfig, time.Time) {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	material := filepath.Join(root, "material")
	if _, err := Generate(material, testConfig(), now); err != nil {
		t.Fatal(err)
	}
	topology := natscell.HubAndSpoke("gru", []string{"sfo", "fra"}).WithSpokeParent("fra", "sfo")
	nextSecond()
	return material, filepath.Join(root, "interregion"), InterRegionConfig{Topology: topology, ListenPort: 7422}, now
}

// nextSecond waits for the next whole second: brokers take only a cell
// claim issued strictly later than the one it replaces.
func nextSecond() { time.Sleep(time.Until(time.Unix(time.Now().Unix()+1, 0))) }

func TestInterRegionMaterialMatchesTheContract(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	record, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{}, now)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadInterRegion(directory)
	if err != nil || loaded.LedgerDigest != record.LedgerDigest || len(loaded.LedgerDigest) != 64 {
		t.Fatalf("load = %+v, %v", loaded, err)
	}
	names := make([]string, 0, len(record.Files))
	for _, file := range record.Files {
		names = append(names, file.Name)
		// The CA key and child seeds are never published.
		if owner := file.Name == "interregion-ca.key" || file.Name == "child-sfo.seed"; owner != (file.Purpose == "owner-only") {
			t.Errorf("%s has purpose %q", file.Name, file.Purpose)
		}
		if info, err := os.Lstat(filepath.Join(directory, file.Name)); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s is not owner-only: %v", file.Name, err)
		}
	}
	if !slices.Equal(names, []string{"cell-interregion.jwt", "child-sfo.seed", "interregion-ca.key", "interregion-ca.pem",
		"interregion-tls-controller-a-cert.pem", "interregion-tls-controller-a-key.pem",
		"interregion-tls-controller-b-cert.pem", "interregion-tls-controller-b-key.pem",
		"interregion-tls-controller-c-cert.pem", "interregion-tls-controller-c-key.pem",
		"interregion.jwt", "leaf-sfo.creds", "system-interregion.jwt"}) {
		t.Fatalf("files = %v", names)
	}
	base, err := Load(material)
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) *jwt.AccountClaims {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		claim, err := jwt.DecodeAccountClaims(string(raw))
		if err != nil || claim.Issuer != base.Public.OperatorNKey {
			t.Fatalf("%s = %+v, %v", name, claim, err)
		}
		return claim
	}
	interregion, cell, system := read("interregion.jwt"), read("cell-interregion.jwt"), read("system-interregion.jwt")
	// The reissued cell account keeps the host and role signers.
	baseRaw, err := os.ReadFile(filepath.Join(material, "cell.jwt"))
	if err != nil {
		t.Fatal(err)
	}
	baseCell, err := jwt.DecodeAccountClaims(string(baseRaw))
	if err != nil || len(baseCell.SigningKeys) != 2 {
		t.Fatalf("material cell account %+v: %v", baseCell, err)
	}
	contract := natscell.InterRegionContract{Cell: "gru", Peers: []string{"fra", "sfo"}, GlobalHome: "gru",
		Subtrees: map[string][]string{"sfo": {"fra", "sfo"}}}
	if err := contract.VerifyClaims(system, cell, interregion, 1); err != nil {
		t.Fatalf("issued claims fail the startup check: %v", err)
	}
	if !interregion.Limits.DisallowBearer || cell.Limits.LeafNodeConn != 0 || system.Limits.LeafNodeConn != 0 ||
		cell.Subject != base.Public.CellAccountNKey || !reflect.DeepEqual(cell.SigningKeys, baseCell.SigningKeys) ||
		interregion.Subject != record.InterRegionAccountNKey || interregion.Expires != base.ExpiresAt.Unix() {
		t.Fatalf("claims: interregion %+v cell %+v", interregion.Limits, cell.Limits)
	}
	if err := natscell.ValidateLeafCredentials(filepath.Join(directory, "leaf-sfo.creds"),
		record.InterRegionAccountNKey); err != nil {
		t.Fatal(err)
	}

	// Immutable: the same request returns the same material; any other is refused.
	again, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{}, now.Add(time.Minute))
	if err != nil || again.LedgerDigest != record.LedgerDigest {
		t.Fatalf("regenerate = %v", err)
	}
	other := cfg
	other.Topology = natscell.HubAndSpoke("gru", []string{"sfo", "fra"})
	if _, err := GenerateInterRegion(material, directory, other, InterRegionInputs{}, now); err == nil {
		t.Fatal("material for another topology replaced existing material")
	}

	// Any changed byte fails loading.
	path := filepath.Join(directory, "leaf-sfo.creds")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body[:len(body)-1], 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInterRegion(directory); err == nil {
		t.Fatal("tampered interregion material loaded")
	}
}

func TestInterRegionConfigNeedsAPortExactlyWithChildren(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	for name, mutate := range map[string]func(*InterRegionConfig){
		"no port with children": func(c *InterRegionConfig) { c.ListenPort = 0 },
		"port out of range":     func(c *InterRegionConfig) { c.ListenPort = 70000 },
		"region not in tree":    func(c *InterRegionConfig) { c.Topology = natscell.HubAndSpoke("sfo", []string{"fra"}) },
		"cyclic tree": func(c *InterRegionConfig) {
			c.Topology = natscell.LeafTopology{Hub: "gru", Parents: map[string]string{"sfo": "fra", "fra": "sfo"}}
		},
		"port on a leaf region": func(c *InterRegionConfig) {
			c.Topology = natscell.HubAndSpoke("sfo", []string{"gru"})
		},
	} {
		candidate := cfg
		mutate(&candidate)
		if _, err := GenerateInterRegion(material, directory+"-"+strings.ReplaceAll(name, " ", "-"), candidate,
			InterRegionInputs{}, now); err == nil {
			t.Errorf("%s: interregion material issued", name)
		}
	}
	// ts-reviewer 13256: never inside (or around) the controller material.
	for _, inside := range []string{filepath.Join(material, "interregion"), material, filepath.Dir(material)} {
		if _, err := GenerateInterRegion(material, inside, cfg, InterRegionInputs{}, now); err == nil {
			t.Errorf("interregion material issued at %s", inside)
		}
	}
	if _, err := Load(material); err != nil {
		t.Fatalf("controller material damaged: %v", err)
	}
}

// TestWideTreeMaterialIsRefusedBeforeWriting pins the 64 KiB JWT limit: a
// hub with 63 direct children needs a larger interregion account than the
// server reads, so nothing is written, while a narrower tree still fits.
func TestWideTreeMaterialIsRefusedBeforeWriting(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	spokes := make([]string, 0, 63)
	for index := range 63 {
		spokes = append(spokes, "r"+strings.Repeat("x", index/26)+string(rune('a'+index%26)))
	}
	cfg.Topology = natscell.HubAndSpoke("gru", spokes)
	if _, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{}, now); err == nil ||
		!strings.Contains(err.Error(), "limit") {
		t.Fatalf("wide tree = %v", err)
	}
	if _, err := os.Lstat(directory); !os.IsNotExist(err) {
		t.Fatalf("refused material left a directory: %v", err)
	}
	cfg.Topology = natscell.HubAndSpoke("gru", spokes[:8])
	if _, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{}, now); err != nil {
		t.Fatalf("eight children = %v", err)
	}
	if _, err := LoadInterRegion(directory); err != nil {
		t.Fatal(err)
	}
}

func receipt(t *testing.T, mutate func(map[string]any)) ([]byte, string) {
	t.Helper()
	document := map[string]any{
		"schema_version": 1, "kind": PrivatePeerReceiptKind, "status": PrivatePeerReceiptPass,
		"readback_expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		"allowed_tcp_ports":   []int{4222, 7422},
		"cells": map[string]any{"gru": map[string]any{"subnet_cidr": "10.251.0.0/24", "vcn_id": "x"},
			"sfo": map[string]any{"subnet_cidr": "10.252.0.0/24"}},
		"dataplane_reachability": "not_tested",
	}
	if mutate != nil {
		mutate(document)
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	return wire, hex.EncodeToString(sum[:])
}

func TestLeafRemotePrivateURLsComeFromTheReviewedReceipt(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	parent, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{}, now)
	if err != nil {
		t.Fatal(err)
	}
	// The child's private copy of its credentials.
	body, err := os.ReadFile(filepath.Join(directory, "leaf-sfo.creds"))
	if err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(t.TempDir(), "gru-leaf.creds")
	if err := os.WriteFile(creds, body, 0o600); err != nil {
		t.Fatal(err)
	}
	tls := natscell.TLSFiles{CAFile: "ca.pem", CertFile: "cert.pem", KeyFile: "key.pem"}
	wire, reviewed := receipt(t, nil)
	remote, err := LeafRemote(parent, "sfo", 0, Readback{wire, reviewed}, Readback{}, creds, tls, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if remote.Peer != "gru" || remote.PeerAccount != parent.InterRegionAccountNKey ||
		remote.ServerName != "leaf.gru.interregion.terrascale.internal" || !slices.Equal(remote.URLs,
		[]string{"nats-leaf://10.251.0.10:7422", "nats-leaf://10.251.0.11:7422", "nats-leaf://10.251.0.12:7422"}) {
		t.Fatalf("remote = %+v", remote)
	}
	// Each child broker starts at the parent controller of its own index.
	if remote, err := LeafRemote(parent, "sfo", 2, Readback{wire, reviewed}, Readback{}, creds, tls, time.Now()); err != nil ||
		!slices.Equal(remote.URLs, []string{"nats-leaf://10.251.0.12:7422", "nats-leaf://10.251.0.10:7422",
			"nats-leaf://10.251.0.11:7422"}) {
		t.Fatalf("controller-c remote = %+v, %v", remote, err)
	}
	cases := map[string]func() ([]byte, string, string, string){
		"unreviewed receipt": func() ([]byte, string, string, string) {
			other, _ := receipt(t, func(d map[string]any) { d["dataplane_reachability"] = "ok" })
			return other, reviewed, "sfo", creds
		},
		"failed readback": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) { d["status"] = "configuration_readback_fail" })
			return w, d, "sfo", creds
		},
		"expired readback": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) {
				d["readback_expires_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
			})
			return w, d, "sfo", creds
		},
		"leaf port not allowed": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) { d["allowed_tcp_ports"] = []int{4222} })
			return w, d, "sfo", creds
		},
		"controllers outside the peered subnet": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) {
				d["cells"].(map[string]any)["gru"] = map[string]any{"subnet_cidr": "10.9.0.0/24"}
			})
			return w, d, "sfo", creds
		},
		"another peering": func() ([]byte, string, string, string) {
			w, d := receipt(t, func(d map[string]any) {
				cells := d["cells"].(map[string]any)
				cells["fra"] = cells["sfo"]
				delete(cells, "sfo")
			})
			return w, d, "sfo", creds
		},
		"child that does not dial the parent": func() ([]byte, string, string, string) {
			return wire, reviewed, "fra", creds
		},
		"credentials not issued by the parent": func() ([]byte, string, string, string) {
			forged := filepath.Join(t.TempDir(), "forged.creds")
			if err := os.WriteFile(forged, append(body[:len(body)-2], 'x', '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			return wire, reviewed, "sfo", forged
		},
	}
	for name, input := range cases {
		document, digest, child, path := input()
		if _, err := LeafRemote(parent, child, 0, Readback{document, digest}, Readback{}, path, tls, time.Now()); err == nil {
			t.Errorf("%s: leaf remote accepted", name)
		}
	}
	// The parent's inventory must still match its ledger digest and be
	// unexpired: a controller address edited after issue (even one inside
	// the peered subnet) and expired material are refused.
	edited := parent
	edited.Slots = slices.Clone(parent.Slots)
	edited.Slots[0].PrivateIP = "10.251.0.99"
	if _, err := LeafRemote(edited, "sfo", 0, Readback{wire, reviewed}, Readback{}, creds, tls, time.Now()); err == nil {
		t.Error("a parent inventory edited after issue was accepted")
	}
	if _, err := LeafRemote(parent, "sfo", 0, Readback{wire, reviewed}, Readback{}, creds, tls, parent.ExpiresAt); err == nil {
		t.Error("expired parent material was accepted")
	}
}

// The reissued cell claim starts from the one the brokers hold: its signers
// and limits survive, it is newer, and it still passes the contract. A claim
// of another account or operator is refused.
func TestInterRegionCellClaimStartsFromTheBrokersClaim(t *testing.T) {
	material, directory, cfg, now := interRegionFixture(t)
	read := func(name string) []byte {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(material, name))
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	operator, err := nkeys.FromSeed(read("issuer-operator.seed"))
	if err != nil {
		t.Fatal(err)
	}
	held, err := jwt.DecodeAccountClaims(string(read("cell.jwt")))
	if err != nil {
		t.Fatal(err)
	}
	held.Limits.JetStreamLimits.Streams = 77
	heldRaw, err := held.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	otherOperator, _ := nkeys.CreateOperator()
	forged, err := held.Encode(otherOperator)
	if err != nil {
		t.Fatal(err)
	}
	nextSecond()
	for name, claim := range map[string]string{"another account": string(read("system.jwt")), "another operator": forged} {
		if _, err := GenerateInterRegion(material, directory+"-"+strings.ReplaceAll(name, " ", "-"), cfg,
			InterRegionInputs{CellJWT: claim}, now); err == nil {
			t.Errorf("%s: interregion material issued", name)
		}
	}
	record, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{CellJWT: heldRaw}, now)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(name string) *jwt.AccountClaims {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := jwt.DecodeAccountClaims(string(body))
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	cell := claim("cell-interregion.jwt")
	if cell.IssuedAt <= held.IssuedAt || len(cell.SigningKeys) != 2 || !reflect.DeepEqual(cell.SigningKeys, held.SigningKeys) ||
		cell.Limits.JetStreamLimits.Streams != 77 || cell.Expires != held.Expires || record.CellJWTSHA256 != digest([]byte(heldRaw)) {
		t.Fatalf("cell claim %+v, record %s", cell, record.CellJWTSHA256)
	}
	contract := natscell.InterRegionContract{Cell: "gru", Peers: []string{"fra", "sfo"}, GlobalHome: "gru",
		Subtrees: map[string][]string{"sfo": {"fra", "sfo"}}}
	if err := contract.VerifyClaims(claim("system-interregion.jwt"), cell, claim("interregion.jwt"), 1); err != nil {
		t.Fatal(err)
	}
	// Immutable: other inputs are refused, the same ones return it.
	if _, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{}, now); err == nil {
		t.Fatal("material reissued from the material's cell.jwt")
	}
	if again, err := GenerateInterRegion(material, directory, cfg, InterRegionInputs{CellJWT: heldRaw}, now); err != nil ||
		again.LedgerDigest != record.LedgerDigest {
		t.Fatalf("rerun = %v", err)
	}
}

type linkedRegion struct {
	material, directory string
	record              InterRegionRecord
}

// linkedRegions issues gru's interregion material as the hub of a gru/sfo
// tree and sfo's as its child, with gru's interregion CA.
func linkedRegions(t *testing.T) (linkedRegion, linkedRegion, time.Time) {
	t.Helper()
	root := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	sfoConfig := testConfig()
	sfoConfig.Region, sfoConfig.Cell, sfoConfig.ClusterID, sfoConfig.SubnetCIDR = "us-sanjose-1", "sfo", "00000000000000000000000002", "10.252.0.0/24"
	sfoConfig.Slots = []Slot{{"controller-a", "10.252.0.10"}, {"controller-b", "10.252.0.11"}, {"controller-c", "10.252.0.12"}}
	gru := linkedRegion{material: filepath.Join(root, "gru"), directory: filepath.Join(root, "gru-interregion")}
	sfo := linkedRegion{material: filepath.Join(root, "sfo"), directory: filepath.Join(root, "sfo-interregion")}
	for _, region := range []struct {
		directory string
		cfg       Config
	}{{gru.material, testConfig()}, {sfo.material, sfoConfig}} {
		if _, err := Generate(region.directory, region.cfg, now); err != nil {
			t.Fatal(err)
		}
	}
	nextSecond()
	topology := natscell.HubAndSpoke("gru", []string{"sfo"})
	var err error
	if gru.record, err = GenerateInterRegion(gru.material, gru.directory, InterRegionConfig{Topology: topology, ListenPort: 7422},
		InterRegionInputs{}, now); err != nil {
		t.Fatal(err)
	}
	if sfo.record, err = GenerateInterRegion(sfo.material, sfo.directory, InterRegionConfig{Topology: topology},
		hubCA(t, gru), now); err != nil {
		t.Fatal(err)
	}
	return gru, sfo, now
}

func hubCA(t *testing.T, hub linkedRegion) InterRegionInputs {
	t.Helper()
	cert, err := os.ReadFile(filepath.Join(hub.directory, "interregion-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return InterRegionInputs{CACert: cert, CAKeyFile: filepath.Join(hub.directory, "interregion-ca.key")}
}

// The hub's slot certificates serve and dial, the child's only dial, all
// under the one name-constrained CA the hub created, and they complete
// mutual TLS as the leaf listener and remote use them.
func TestInterRegionTLSChainsToTheHubCA(t *testing.T) {
	gru, sfo, _ := linkedRegions(t)
	read := func(region linkedRegion, name string) []byte {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(region.directory, name))
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	caPEM := read(gru, "interregion-ca.pem")
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !ca.IsCA || !ca.MaxPathLenZero || !ca.PermittedDNSDomainsCritical ||
		!slices.Equal(ca.PermittedDNSDomains, []string{".interregion.terrascale.internal"}) ||
		!bytes.Equal(caPEM, read(sfo, "interregion-ca.pem")) {
		t.Fatalf("interregion CA %+v: %v", ca, err)
	}
	if _, err := os.Lstat(filepath.Join(sfo.directory, "interregion-ca.key")); !os.IsNotExist(err) {
		t.Fatalf("the child holds the CA key: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	pairs := map[string]tls.Certificate{}
	for _, region := range []struct {
		linkedRegion
		server bool
	}{{gru, true}, {sfo, false}} {
		for _, slot := range region.record.Slots {
			prefix := "interregion-tls-" + slot.Name
			pair, err := tls.X509KeyPair(read(region.linkedRegion, prefix+"-cert.pem"), read(region.linkedRegion, prefix+"-key.pem"))
			if err != nil {
				t.Fatalf("%s %s: %v", region.record.Cell, slot.Name, err)
			}
			name := InterRegionLeafName(region.record.Cell)
			_, client := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
			_, server := pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if client != nil || (server == nil) != region.server {
				t.Fatalf("%s %s: client %v, server %v", region.record.Cell, slot.Name, client, server)
			}
			pairs[region.record.Cell+"/"+slot.Name] = pair
		}
	}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	server := tls.Server(serverConn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pairs["gru/controller-a"]},
		ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(t.Context()) }()
	client := tls.Client(clientConn, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pairs["sfo/controller-b"]},
		RootCAs: roots, ServerName: "leaf.gru.interregion.terrascale.internal"})
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Only the hub creates the CA; every other region signs with exactly the
// hub's, whose key must be owner-only.
func TestInterRegionChildNeedsTheHubsCA(t *testing.T) {
	gru, sfo, now := linkedRegions(t)
	topology := natscell.HubAndSpoke("gru", []string{"sfo"})
	child := InterRegionConfig{Topology: topology}
	inputs := hubCA(t, gru)
	if again, err := GenerateInterRegion(sfo.material, sfo.directory, child, inputs, now); err != nil ||
		again.LedgerDigest != sfo.record.LedgerDigest {
		t.Fatalf("rerun = %v", err)
	}
	keyPEM, err := os.ReadFile(inputs.CAKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, body []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, body, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	otherCA, otherKey, _, _, err := interRegionCertificate(&x509.Certificate{IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InterRegionInputs){
		"no CA":                   func(in *InterRegionInputs) { *in = InterRegionInputs{} },
		"group-readable CA key":   func(in *InterRegionInputs) { in.CAKeyFile = write("ca.key", keyPEM, 0o640) },
		"another key":             func(in *InterRegionInputs) { in.CAKeyFile = write("ca.key", otherKey, 0o600) },
		"unconstrained CA":        func(in *InterRegionInputs) { in.CACert, in.CAKeyFile = otherCA, write("ca.key", otherKey, 0o600) },
		"CA with trailing data":   func(in *InterRegionInputs) { in.CACert = append(slices.Clone(in.CACert), "junk"...) },
		"another CA on the rerun": func(in *InterRegionInputs) { in.CACert = otherCA },
	} {
		candidate := hubCA(t, gru)
		mutate(&candidate)
		target := sfo.directory + "-" + strings.ReplaceAll(name, " ", "-")
		if name == "another CA on the rerun" {
			target = sfo.directory
		}
		if _, err := GenerateInterRegion(sfo.material, target, child, candidate, now); err == nil {
			t.Errorf("%s: child material issued", name)
		}
	}
	nextSecond()
	if _, err := GenerateInterRegion(gru.material, gru.directory+"-again", InterRegionConfig{Topology: topology, ListenPort: 7422},
		inputs, now); err == nil {
		t.Error("the hub took another CA")
	}
}

// netbirdReadback is a reviewed NetBird inventory in which every gru
// controller has one connected gru-servers peer (slot a also a replaced,
// disconnected revision) and sfo's servers may reach gru's on 7422.
func netbirdReadback(t *testing.T, mutate func(*manager.Inventory)) Readback {
	t.Helper()
	servers := []string{"gru-servers"}
	inventory := manager.Inventory{Account: manager.InventoryAccount{NetworkRange: "10.200.0.0/16"},
		Peers: []manager.InventoryPeer{
			{Name: "ts-gru-1", IP: "10.200.0.11", ConnectionIP: "10.251.0.10", Connected: true, Groups: servers},
			{Name: "ts-gru-1-old", IP: "10.200.0.99", ConnectionIP: "10.251.0.10", Groups: servers},
			{Name: "ts-gru-2", IP: "10.200.0.12", ConnectionIP: "10.251.0.11", Connected: true, Groups: servers},
			{Name: "ts-gru-3", IP: "10.200.0.13", ConnectionIP: "10.251.0.12", Connected: true, Groups: servers},
			{Name: "ts-sfo-1", IP: "10.200.1.11", ConnectionIP: "10.252.0.10", Connected: true, Groups: []string{"sfo-servers"}},
		},
		Policies: []manager.InventoryPolicy{{Name: "sfo-servers-to-gru-servers-fabric", Enabled: true,
			Rules: []manager.InventoryRule{{Name: "sfo-servers-to-gru-servers-fabric", Enabled: true, Action: "accept",
				Protocol: "tcp", Ports: []string{"7422", "9443"}, Sources: []string{"sfo-servers"}, Destinations: servers}}}},
	}
	if mutate != nil {
		mutate(&inventory)
	}
	wire, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	return Readback{wire, digest(wire)}
}

// childCredentials is the child's private copy of the parent's
// leaf-<child>.creds.
func childCredentials(t *testing.T, parent linkedRegion, child string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(parent.directory, "leaf-"+child+".creds"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "leaf.creds")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// NetBird addresses follow the private ones, in the same rotation, only
// from a reviewed inventory that admits every parent controller; any other
// inventory is refused rather than dropped.
func TestLeafRemoteFallsBackToReviewedNetBirdAddresses(t *testing.T) {
	gru, _, _ := linkedRegions(t)
	creds := childCredentials(t, gru, "sfo")
	wire, reviewed := receipt(t, nil)
	private := Readback{wire, reviewed}
	tls := natscell.TLSFiles{CAFile: "ca.pem", CertFile: "cert.pem", KeyFile: "key.pem"}
	remote, err := LeafRemote(gru.record, "sfo", 1, private, netbirdReadback(t, nil), creds, tls, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(remote.URLs, []string{"nats-leaf://10.251.0.11:7422", "nats-leaf://10.251.0.12:7422",
		"nats-leaf://10.251.0.10:7422", "nats-leaf://10.200.0.12:7422", "nats-leaf://10.200.0.13:7422",
		"nats-leaf://10.200.0.11:7422"}) || remote.ServerName != "leaf.gru.interregion.terrascale.internal" {
		t.Fatalf("remote = %+v", remote)
	}
	unreviewed := netbirdReadback(t, nil)
	unreviewed.SHA256 = strings.Repeat("0", 64)
	cases := map[string]Readback{"unreviewed inventory": unreviewed}
	for name, mutate := range map[string]func(*manager.Inventory){
		"another network range":           func(i *manager.Inventory) { i.Account.NetworkRange = "100.64.0.0/10" },
		"controller peer disconnected":    func(i *manager.Inventory) { i.Peers[2].Connected = false },
		"controller peer missing":         func(i *manager.Inventory) { i.Peers = i.Peers[:3] },
		"peer registered from elsewhere":  func(i *manager.Inventory) { i.Peers[3].ConnectionIP = "10.251.0.99" },
		"peer outside the servers group":  func(i *manager.Inventory) { i.Peers[2].Groups = []string{"sfo-servers"} },
		"two connected peers":             func(i *manager.Inventory) { i.Peers[1].Connected = true },
		"NetBird address outside range":   func(i *manager.Inventory) { i.Peers[0].IP = "100.64.0.1" },
		"no fabric policy":                func(i *manager.Inventory) { i.Policies = nil },
		"fabric policy disabled":          func(i *manager.Inventory) { i.Policies[0].Enabled = false },
		"fabric policy without leaf port": func(i *manager.Inventory) { i.Policies[0].Rules[0].Ports = []string{"9443"} },
		"fabric policy of another child":  func(i *manager.Inventory) { i.Policies[0].Name = "fra-servers-to-gru-servers-fabric" },
	} {
		cases[name] = netbirdReadback(t, mutate)
	}
	for name, netbird := range cases {
		if remote, err := LeafRemote(gru.record, "sfo", 1, private, netbird, creds, tls, time.Now()); err == nil {
			t.Errorf("%s: remote %v accepted", name, remote.URLs)
		}
	}
}

// The rendered blocks of the hub and the child pass the broker's startup
// check, with every file at its installed path.
func TestRenderInterRegionPassesTheBrokerCheck(t *testing.T) {
	gru, sfo, _ := linkedRegions(t)
	const installed = "/var/lib/terrascale-orchestrator-secrets"
	now := time.Now()
	hub, err := RenderInterRegion(gru.record, "controller-b", installed, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	gruTLS := natscell.TLSFiles{CAFile: installed + "/interregion-ca.pem",
		CertFile: installed + "/interregion-tls-controller-b-cert.pem", KeyFile: installed + "/interregion-tls-controller-b-key.pem"}
	if !hub.Enabled || hub.AccountJWTFile != installed+"/interregion.jwt" || hub.GlobalHome != "gru" ||
		!slices.Equal(hub.Peers, []string{"sfo"}) || len(hub.Remotes) != 0 || hub.Topology == nil ||
		!reflect.DeepEqual(hub.Listen, &natscell.LeafListen{Host: "0.0.0.0", Port: 7422, TLS: gruTLS}) ||
		!reflect.DeepEqual(hub.Subtrees, map[string][]string{"sfo": {"sfo"}}) || hub.Validate("gru") != nil {
		t.Fatalf("hub block = %+v", hub)
	}
	wire, reviewed := receipt(t, nil)
	link := &ParentLink{Record: gru.record, Receipt: Readback{wire, reviewed}, NetBird: netbirdReadback(t, nil),
		CredentialsFile: childCredentials(t, gru, "sfo")}
	child, err := RenderInterRegion(sfo.record, "controller-c", installed, link, now)
	if err != nil {
		t.Fatal(err)
	}
	want := natscell.LeafRemote{Peer: "gru", URLs: []string{"nats-leaf://10.251.0.12:7422", "nats-leaf://10.251.0.10:7422",
		"nats-leaf://10.251.0.11:7422", "nats-leaf://10.200.0.13:7422", "nats-leaf://10.200.0.11:7422",
		"nats-leaf://10.200.0.12:7422"}, CredentialsFile: installed + "/leaf-gru.creds",
		PeerAccount: gru.record.InterRegionAccountNKey, ServerName: "leaf.gru.interregion.terrascale.internal",
		TLS: natscell.TLSFiles{CAFile: installed + "/interregion-ca.pem",
			CertFile: installed + "/interregion-tls-controller-c-cert.pem", KeyFile: installed + "/interregion-tls-controller-c-key.pem"}}
	if child.Listen != nil || len(child.Subtrees) != 0 || child.GlobalHome != "gru" || len(child.Remotes) != 1 ||
		!reflect.DeepEqual(child.Remotes[0], want) || child.Validate("sfo") != nil {
		t.Fatalf("child block = %+v", child)
	}
	for name, render := range map[string]func() error{
		"child without its parent": func() error {
			_, err := RenderInterRegion(sfo.record, "controller-a", installed, nil, now)
			return err
		},
		"hub with a parent": func() error {
			_, err := RenderInterRegion(gru.record, "controller-a", installed, link, now)
			return err
		},
		"unknown slot": func() error {
			_, err := RenderInterRegion(gru.record, "controller-d", installed, nil, now)
			return err
		},
		"relative directory": func() error {
			_, err := RenderInterRegion(gru.record, "controller-a", "secrets", nil, now)
			return err
		},
		"expired material": func() error {
			_, err := RenderInterRegion(gru.record, "controller-a", installed, nil, gru.record.ExpiresAt)
			return err
		},
	} {
		if render() == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}
