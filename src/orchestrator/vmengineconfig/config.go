// Package vmengineconfig renders explicitly declared production-mode TerraBase
// configuration for VM qualification. It grants no membership or readiness.
package vmengineconfig

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

// Contract identifies the inspected producer parser, not a published release.
const Contract = "terrabase-worktree-config-981772331888c0036fcbf7714fd8ba96215aa4b4803a91834cdcddde8e17941e"
const ServiceUser = "terrascale-terrabase"
const CertificatePath = "/etc/terrascale/terrabase/server.pem"
const PrivateKeyPath = "/etc/terrascale/terrabase/key.pem"
const CAPath = "/etc/terrascale/terrabase/ca.pem"
const dataRoot = "/var/lib/terrascale/terrabase"

var ulid = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var environment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,96}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Declaration contains nonsecret, explicit qualification assignments. Artifact
// binding prevents reusing a declaration with a different engine binary.
type Declaration struct {
	Version        int        `json:"version"`
	Contract       string     `json:"contract"`
	ArtifactSHA256 string     `json:"artifactSha256"`
	Release        string     `json:"release"`
	Environment    string     `json:"environment"`
	Cluster        string     `json:"cluster"`
	Generation     uint64     `json:"generation"`
	Epoch          uint64     `json:"epoch"`
	Hosts          []Host     `json:"hosts"`
	Databases      []Database `json:"databases"`
	Limits         Limits     `json:"limits"`
}

type Host struct {
	NodeID          string `json:"nodeId"`
	Member          string `json:"member"`
	CertificateFile string `json:"certificateFile"`
	PrivateKeyFile  string `json:"privateKeyFile"`
	CAFile          string `json:"caFile"`
}

type Database struct {
	Tenant          string   `json:"tenant"`
	Project         string   `json:"project"`
	Database        string   `json:"database"`
	Region          string   `json:"region"`
	AllowedRegions  []string `json:"allowedRegions"`
	EncryptionKey   string   `json:"encryptionKey"`
	MaxStorageBytes uint64   `json:"maxStorageBytes"`
	MaxDocuments    uint64   `json:"maxDocuments"`
	MaxInflight     uint64   `json:"maxInflight"`
}

type Limits struct {
	MaxMessageBytes           uint64 `json:"maxMessageBytes"`
	MaxInflight               uint64 `json:"maxInflight"`
	RequestTimeoutMillis      uint64 `json:"requestTimeoutMillis"`
	TLSHandshakeTimeoutMillis uint64 `json:"tlsHandshakeTimeoutMillis"`
	ShutdownGraceMillis       uint64 `json:"shutdownGraceMillis"`
}

// Binding comes from the verified VM network plan, never the declaration.
type Binding struct{ NodeID, Region, Address string }

// Material keeps validated configuration and credential bytes together. The
// private fields prevent callers from substituting unchecked seed material.
type Material struct {
	nodeID, address, settings, artifact, release string
	certificate, privateKey, ca                  []byte
}

func (m *Material) Address() string { return m.address }

func IsTLSPath(path string) bool {
	return path == CertificatePath || path == PrivateKeyPath || path == CAPath
}

func (m *Material) Clear() {
	if m == nil {
		return
	}
	clear(m.privateKey)
	*m = Material{}
}

func (m *Material) Clone() *Material {
	if m == nil {
		return nil
	}
	copy := *m
	copy.certificate, copy.privateKey, copy.ca = bytes.Clone(m.certificate), bytes.Clone(m.privateKey), bytes.Clone(m.ca)
	return &copy
}

func (m *Material) Files() map[string][]byte {
	return map[string][]byte{CertificatePath: bytes.Clone(m.certificate), PrivateKeyPath: bytes.Clone(m.privateKey), CAPath: bytes.Clone(m.ca)}
}

// Apply is called before the owner signs the complete host launch manifest.
func (m *Material) Apply(manifest hostmanifest.HostManifest) (hostmanifest.HostManifest, error) {
	if m == nil || m.settings == "" {
		return manifest, errors.New("vmengineconfig: material missing")
	}
	manifest.Components = slices.Clone(manifest.Components)
	found := false
	for i, c := range manifest.Components {
		if c.Name != "terrabase" {
			continue
		}
		if found || c.Sha256 != m.artifact || c.Version != m.release || c.DataVolume != dataRoot || c.User != ServiceUser || c.Configuration != "" || c.Arguments != "" {
			return manifest, errors.New("vmengineconfig: engine manifest differs from declaration")
		}
		found = true
		c.Arguments, c.Configuration = "--config @config", m.settings
		var err error
		manifest.Components[i], err = hostmanifest.NewComponentSpec(c)
		if err != nil {
			return manifest, err
		}
	}
	if !found {
		return manifest, errors.New("vmengineconfig: engine component missing")
	}
	return manifest, nil
}

func (m *Material) ValidateManifest(nodeID, address string, manifest hostmanifest.HostManifest) error {
	if m == nil || m.nodeID != nodeID || m.address != address || m.settings == "" || len(m.privateKey) == 0 {
		return errors.New("vmengineconfig: engine material belongs to another guest")
	}
	found := 0
	for _, c := range manifest.Components {
		if c.Name == "terrabase" {
			found++
			planned, err := bootstrap.PlanControlLaunchManifest(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{c}})
			if err != nil || c.Version != planned.Components[0].Version || !strings.HasSuffix(c.ArtifactURL, "/releases/terrabase/"+m.release+"/terrabase") || c.Configuration != m.settings || c.Arguments != "--config @config" || c.Sha256 != m.artifact || c.User != ServiceUser || c.DataVolume != dataRoot {
				return errors.New("vmengineconfig: signed engine configuration differs")
			}
		}
	}
	if found != 1 {
		return errors.New("vmengineconfig: engine component inventory differs")
	}
	return nil
}

func Load(path, artifact, release string, bindings []Binding) (map[string]*Material, error) {
	raw, err := initialgrant.ReadMaterialFile(path, 1<<20, false)
	if err != nil {
		return nil, errors.New("vmengineconfig: declaration read refused")
	}
	var d Declaration
	if err := json.Unmarshal(raw, &d, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("vmengineconfig: invalid declaration JSON")
	}
	return prepare(d, artifact, release, bindings)
}

func validate(d Declaration, artifact, release string, bindings []Binding) (map[string]Binding, error) {
	bad := errors.New("vmengineconfig: explicit production identities, placement, release, or bounds invalid")
	if d.Version != 1 || d.Contract != Contract || !digest.MatchString(artifact) || d.ArtifactSHA256 != artifact || d.Release != release || len(release) == 0 || len(release) > 128 || !environment.MatchString(d.Environment) || !ulid.MatchString(d.Cluster) || d.Generation == 0 || d.Epoch == 0 || d.Generation > math.MaxInt64 || d.Epoch > math.MaxInt64 {
		return nil, bad
	}
	for _, r := range release {
		if r < 33 || r > 126 || r == '"' || r == '\\' {
			return nil, bad
		}
	}
	if len(bindings) < 2 || len(bindings) > 6 || len(d.Hosts) != len(bindings) || len(d.Databases) == 0 || len(d.Databases) > 1024 {
		return nil, bad
	}
	nodes, addresses, regions := map[string]Binding{}, map[string]bool{}, map[string]int{}
	for _, b := range bindings {
		ip, err := netip.ParseAddr(b.Address)
		if err != nil || !ip.Is4() || !ip.IsPrivate() || b.NodeID == "" || nodes[b.NodeID].NodeID != "" || addresses[b.Address] || !slices.Contains([]string{"GRU", "SFO", "FRA"}, b.Region) {
			return nil, bad
		}
		nodes[b.NodeID], addresses[b.Address] = b, true
		regions[b.Region]++
	}
	for _, count := range regions {
		if count != 2 {
			return nil, bad
		}
	}
	members, hosts := map[string]bool{}, map[string]bool{}
	for _, h := range d.Hosts {
		if nodes[h.NodeID].NodeID == "" || hosts[h.NodeID] || !ulid.MatchString(h.Member) || members[h.Member] {
			return nil, bad
		}
		hosts[h.NodeID], members[h.Member] = true, true
	}
	projects, databases := map[string]string{}, map[string]bool{}
	for _, db := range d.Databases {
		if !ulid.MatchString(db.Tenant) || !ulid.MatchString(db.Project) || !ulid.MatchString(db.Database) || !ulid.MatchString(db.EncryptionKey) || databases[db.Database] || regions[db.Region] != 2 || projects[db.Project] != "" && projects[db.Project] != db.Tenant || db.MaxStorageBytes == 0 || db.MaxStorageBytes > 1<<50 || db.MaxDocuments == 0 || db.MaxDocuments > 1_000_000_000 || db.MaxInflight == 0 || db.MaxInflight > 1_000_000 {
			return nil, bad
		}
		allowed := map[string]bool{}
		for _, region := range db.AllowedRegions {
			if allowed[region] || !slices.Contains([]string{"GRU", "SFO", "FRA"}, region) {
				return nil, bad
			}
			allowed[region] = true
		}
		// The current engine schema has one placement for the whole catalog.
		// Never render a database into a topology outside its explicit lock.
		for region := range regions {
			if !allowed[region] {
				return nil, errors.New("vmengineconfig: shared engine placement exceeds a database residency lock")
			}
		}
		projects[db.Project], databases[db.Database] = db.Tenant, true
	}
	l := d.Limits
	if l.MaxMessageBytes < 1024 || l.MaxMessageBytes > 16<<20 || l.MaxInflight == 0 || l.MaxInflight > 4096 || l.RequestTimeoutMillis < 100 || l.RequestTimeoutMillis > 300000 || l.TLSHandshakeTimeoutMillis < 100 || l.TLSHandshakeTimeoutMillis > 30000 || l.ShutdownGraceMillis < 100 || l.ShutdownGraceMillis > 300000 {
		return nil, bad
	}
	return nodes, nil
}

func render(d Declaration, h Host, nodes map[string]Binding) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "mode = \"production\"\n[environment]\nname = %q\ncluster = %q\nmember = %q\n", d.Environment, d.Cluster, h.Member)
	for _, db := range d.Databases {
		fmt.Fprintf(&b, "\n[[databases]]\ntenant = %q\nproject = %q\ndatabase = %q\nregion = %q\nlocation = %q\npolicy_journal = %q\nbackup_root = %q\nencryption_provider = \"oci-vault\"\nencryption_key = %q\nenabled = true\n[databases.quotas]\nmax_storage_bytes = %d\nmax_documents = %d\nmax_inflight = %d\n", db.Tenant, db.Project, db.Database, db.Region, dataRoot+"/databases/"+db.Database, dataRoot+"/policies/"+db.Database, dataRoot+"/backups/"+db.Database, db.EncryptionKey, db.MaxStorageBytes, db.MaxDocuments, db.MaxInflight)
	}
	fmt.Fprintf(&b, "\n[placement]\ngeneration = %d\nepoch = %d\n", d.Generation, d.Epoch)
	for _, region := range []string{"GRU", "SFO", "FRA"} {
		var seats []string
		for _, host := range d.Hosts {
			if nodes[host.NodeID].Region == region {
				seats = append(seats, host.Member)
			}
		}
		if len(seats) == 0 {
			continue
		}
		slices.Sort(seats)
		fmt.Fprintf(&b, "[[placement.regions]]\nregion = %q\nmembers = [%q, %q]\n", region, seats[0], seats[1])
	}
	l := d.Limits
	fmt.Fprintf(&b, "\n[transport]\ntbep_listen = \"127.0.0.1:8421\"\nquic_listen = %q\nmetrics_listen = \"127.0.0.1:8423\"\nserver_certificate = %q\nserver_private_key = %q\nclient_ca = %q\nmax_message_bytes = %d\nmax_inflight = %d\nrequest_timeout_millis = %d\ntls_handshake_timeout_millis = %d\nshutdown_grace_millis = %d\n", nodes[h.NodeID].Address+":8422", CertificatePath, PrivateKeyPath, CAPath, l.MaxMessageBytes, l.MaxInflight, l.RequestTimeoutMillis, l.TLSHandshakeTimeoutMillis, l.ShutdownGraceMillis)
	for _, peer := range d.Hosts {
		if peer.NodeID == h.NodeID {
			continue
		}
		fmt.Fprintf(&b, "[[transport.peers]]\nmember = %q\nendpoint = %q\nspiffe_identity = %q\n", peer.Member, nodes[peer.NodeID].Address+":8422", identity(d, peer))
	}
	fmt.Fprintf(&b, "\n[release]\nrelease = %q\ncapabilities = [\"production\", \"tbep\", \"quic\", \"metrics\", \"oci-vault\"]\n", d.Release)
	if b.Len() > hostmanifest.MaximumConfigurationBytes {
		return "", errors.New("vmengineconfig: rendered configuration exceeds engine bound")
	}
	return b.String(), nil
}

func identity(d Declaration, h Host) string {
	return "spiffe://terrascale.tech/" + d.Environment + "/terrabase-member/" + d.Cluster + "/" + h.Member
}
