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
	"net/url"
	"regexp"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
)

// Contract identifies the inspected producer parser, not a published release.
const Contract = "terrabase-worktree-config-bafba567958b96de5c63563e85ed975f9f681ba1e0b74eeb99eb5af46089c21b"
const ServiceUser = "terrascale-terrabase"
const CertificatePath = "/etc/terrascale/terrabase/server.pem"
const PrivateKeyPath = "/etc/terrascale/terrabase/key.pem"
const CAPath = "/etc/terrascale/terrabase/ca.pem"
const ObserverCertificatePath = "/etc/terrascale/engine-observer/client.pem"
const ObserverPrivateKeyPath = "/etc/terrascale/engine-observer/client.key"
const ObserverCAPath = "/etc/terrascale/engine-observer/ca.pem"
const dataRoot = "/var/lib/terrascale/terrabase"

var ulid = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var environment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,96}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Declaration contains nonsecret, explicit qualification assignments. Artifact
// binding prevents reusing a declaration with a different engine binary.
type Declaration struct {
	BackupDisk      BackupDisk       `json:"backupDisk"`
	TransitionTrust *TransitionTrust `json:"transitionTrust,omitempty"`
	Version         int              `json:"version"`
	Contract        string           `json:"contract"`
	ArtifactSHA256  string           `json:"artifactSha256"`
	Release         string           `json:"release"`
	Environment     string           `json:"environment"`
	Cluster         string           `json:"cluster"`
	Generation      uint64           `json:"generation"`
	Epoch           uint64           `json:"epoch"`
	Hosts           []Host           `json:"hosts"`
	Databases       []Database       `json:"databases"`
	Limits          Limits           `json:"limits"`
	Keys            *Keys            `json:"keys,omitempty"`
	PublicAPI       *PublicAPI       `json:"publicApi,omitempty"`
}

// BackupDisk declares disk reserved per database and across one member. Half
// of each stream is reserved for rotation/restore; this is unrelated to RAM.
type BackupDisk struct {
	StagingBytesPerStream   uint64 `json:"stagingBytesPerStream"`
	InventoryBytesPerStream uint64 `json:"inventoryBytesPerStream"`
	TotalStagingBytes       uint64 `json:"totalStagingBytes"`
}

type Host struct {
	DatabaseHost            *DatabaseHostCredentials  `json:"databaseHost,omitempty"`
	EngineControl           *EngineControlCredentials `json:"engineControl,omitempty"`
	OrchestratorPrincipals  []string                  `json:"orchestratorPrincipals,omitempty"`
	ObserverCertificateFile string                    `json:"observerCertificateFile"`
	ObserverPrivateKeyFile  string                    `json:"observerPrivateKeyFile"`
	ObserverIdentity        string                    `json:"observerIdentity"`
	ObserverDatabase        string                    `json:"observerDatabase"`
	NodeID                  string                    `json:"nodeId"`
	Member                  string                    `json:"member"`
	CertificateFile         string                    `json:"certificateFile"`
	PrivateKeyFile          string                    `json:"privateKeyFile"`
	CAFile                  string                    `json:"caFile"`
}

type Database struct {
	Tenant          string        `json:"tenant"`
	Project         string        `json:"project"`
	Database        string        `json:"database"`
	Region          string        `json:"region"`
	AllowedRegions  []string      `json:"allowedRegions"`
	SelectedRegions []string      `json:"selectedRegions"`
	EncryptionKey   string        `json:"encryptionKey"`
	MaxStorageBytes uint64        `json:"maxStorageBytes"`
	MaxDocuments    uint64        `json:"maxDocuments"`
	MaxInflight     uint64        `json:"maxInflight"`
	Backup          *BackupConfig `json:"backup,omitempty"`
	BYOK            *BYOKConfig   `json:"byok,omitempty"`
}

// BYOKConfig carries customer-owned provider references. It intentionally has
// no credential fields; workload identity and key leases are delivered by the
// orchestrator at runtime.
type BYOKConfig struct {
	BackupEndpoint   string `json:"backupEndpoint"`
	BackupBucket     string `json:"backupBucket"`
	BackupRegion     string `json:"backupRegion"`
	BackupRoleARN    string `json:"backupRoleArn"`
	BackupExternalID string `json:"backupExternalId,omitempty"`
	KeyProvider      string `json:"keyProvider"`
	KeyID            string `json:"keyId"`
	KeyRegion        string `json:"keyRegion"`
	KeyEndpoint      string `json:"keyEndpoint,omitempty"`
}

type BackupDestination struct {
	Provider             string   `json:"provider"`
	Endpoint             string   `json:"endpoint"`
	SigningRegion        string   `json:"signingRegion"`
	Bucket               string   `json:"bucket"`
	VerifiedGeography    string   `json:"verifiedGeography"`
	PermittedGeographies []string `json:"permittedGeographies"`
	PlacementRevision    string   `json:"placementRevision"`
	AccessKeyFile        string   `json:"accessKeyFile"`
	SecretKeyFile        string   `json:"secretKeyFile"`
	MaxArtifactBytes     uint64   `json:"maxArtifactBytes"`
	MaxPointBytes        uint64   `json:"maxPointBytes"`
}
type BackupConfig struct {
	PolicyRevision string              `json:"policyRevision"`
	RetentionDays  uint8               `json:"retentionDays"`
	Destinations   []BackupDestination `json:"destinations"`
}

type Keys struct {
	Socket          string `json:"socket"`
	OrchestratorUID uint32 `json:"orchestratorUid"`
	SocketGID       uint32 `json:"socketGid"`
}

const publicAPIBootstrapKeyPath = "/etc/terrascale/public-api/bootstrap.key"

type PublicAPI struct {
	Identity         *PublicIdentity `json:"identity,omitempty"`
	Listen           string          `json:"listen"`
	DataRoot         string          `json:"dataRoot"`
	BootstrapKeyFile string          `json:"bootstrapKeyFile,omitempty"`
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
	cell                                         string
	certificate, privateKey, ca                  []byte
	observerCertificate, observerPrivateKey      []byte
	observation                                  tbep.FileConfig
	controlFiles                                 map[string][]byte
	identityFiles                                map[string][]byte
	databaseFiles                                map[string][]byte
	backupFiles                                  map[string][]byte
	databaseAuthorization                        databaseadmission.BrokerGrant
	transitionFiles                              map[string][]byte
	controlAuthorization                         ControlNATSAuthorization
}

func (m *Material) Address() string { return m.address }

func IsTLSPath(path string) bool {
	return path == CertificatePath || path == PrivateKeyPath || path == CAPath
}

func (m *Material) Clear() {
	if m == nil {
		return
	}
	for _, raw := range m.identityFiles {
		clear(raw)
	}
	for _, raw := range m.backupFiles {
		clear(raw)
	}
	m.backupFiles = nil
	for _, raw := range m.databaseFiles {
		clear(raw)
	}
	clear(m.privateKey)
	clear(m.observerPrivateKey)
	for _, data := range m.controlFiles {
		clear(data)
	}
	*m = Material{}
}

func (m *Material) Clone() *Material {
	if m == nil {
		return nil
	}
	copy := *m
	copy.controlFiles = m.ControlFiles()
	copy.identityFiles = m.IdentityFiles()
	copy.databaseFiles = m.DatabaseFiles()
	copy.backupFiles = m.BackupFiles()
	copy.transitionFiles = m.TransitionFiles()
	copy.controlAuthorization = m.ControlAuthorization()
	copy.certificate, copy.privateKey, copy.ca = bytes.Clone(m.certificate), bytes.Clone(m.privateKey), bytes.Clone(m.ca)
	copy.observerCertificate, copy.observerPrivateKey = bytes.Clone(m.observerCertificate), bytes.Clone(m.observerPrivateKey)
	return &copy
}

func (m *Material) Files() map[string][]byte {
	return map[string][]byte{CertificatePath: bytes.Clone(m.certificate), PrivateKeyPath: bytes.Clone(m.privateKey), CAPath: bytes.Clone(m.ca)}
}

func (m *Material) Observation() tbep.FileConfig { return m.observation }

func (m *Material) ObserverFiles() map[string][]byte {
	return map[string][]byte{ObserverCertificatePath: bytes.Clone(m.observerCertificate), ObserverPrivateKeyPath: bytes.Clone(m.observerPrivateKey), ObserverCAPath: bytes.Clone(m.ca)}
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
	manifest, err := m.applyControlManifest(manifest)
	if err != nil {
		return manifest, err
	}
	return m.applyDatabaseManifest(manifest)
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
	if err := m.validateControlManifest(manifest); err != nil {
		return err
	}
	return m.validateDatabaseManifest(manifest)
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
	if d.Keys == nil || d.Keys.Socket == "" || d.Keys.OrchestratorUID == 0 || d.Keys.SocketGID == 0 || d.Version != 1 || d.Contract != Contract || !digest.MatchString(artifact) || d.ArtifactSHA256 != artifact || d.Release != release || len(release) == 0 || len(release) > 128 || !environment.MatchString(d.Environment) || !ulid.MatchString(d.Cluster) || d.Generation == 0 || d.Epoch == 0 || d.Generation > math.MaxInt64 || d.Epoch > math.MaxInt64 {
		return nil, bad
	}
	activeBackupBytes := d.BackupDisk.StagingBytesPerStream / 2
	if activeBackupBytes <= 2<<20 || d.BackupDisk.InventoryBytesPerStream < 4<<20 || d.BackupDisk.TotalStagingBytes > math.MaxInt64 || d.BackupDisk.InventoryBytesPerStream > d.BackupDisk.TotalStagingBytes || d.BackupDisk.StagingBytesPerStream > d.BackupDisk.TotalStagingBytes-d.BackupDisk.InventoryBytesPerStream {
		return nil, bad
	}
	for _, r := range release {
		if r < 33 || r > 126 || r == '"' || r == '\\' {
			return nil, bad
		}
	}
	for _, db := range d.Databases {
		if db.Backup == nil {
			continue
		}
		if db.Backup.PolicyRevision == "" || db.Backup.RetentionDays == 0 || len(db.Backup.Destinations) == 0 {
			return nil, bad
		}
		for _, dest := range db.Backup.Destinations {
			if dest.Provider != "oci" && dest.Provider != "tigris" || dest.Endpoint == "" || dest.SigningRegion == "" || dest.Bucket == "" || dest.VerifiedGeography == "" || len(dest.PermittedGeographies) == 0 || dest.PlacementRevision == "" || dest.AccessKeyFile == "" || dest.SecretKeyFile == "" || dest.MaxArtifactBytes < 16<<20 || dest.MaxArtifactBytes > 256<<20 || dest.MaxPointBytes < dest.MaxArtifactBytes || dest.MaxPointBytes < activeBackupBytes {
				return nil, bad
			}
			if !slices.Contains(db.SelectedRegions, db.Region) || !slices.Contains(dest.PermittedGeographies, dest.VerifiedGeography) {
				return nil, bad
			}
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
		principals := map[string]bool{}
		for _, principal := range h.OrchestratorPrincipals {
			uri, err := url.Parse(principal)
			if err != nil || uri.Scheme != "spiffe" || uri.Host != "terrascale.tech" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || !strings.HasPrefix(uri.Path, "/"+d.Environment+"/") || len(principal) > 128 || strings.ContainsAny(principal, "\r\n\t") || principal == h.ObserverIdentity || principals[principal] {
				return nil, bad
			}
			for _, member := range d.Hosts {
				if principal == identity(d, member) || principal == member.ObserverIdentity {
					return nil, bad
				}
			}
			principals[principal] = true
		}
		if len(principals) > 32 {
			return nil, bad
		}
		hosts[h.NodeID], members[h.Member] = true, true
	}
	projects, databases := map[string]string{}, map[string]bool{}
	for _, db := range d.Databases {
		if !ulid.MatchString(db.Tenant) || !ulid.MatchString(db.Project) || !ulid.MatchString(db.Database) || !ulid.MatchString(db.EncryptionKey) || databases[db.Database] || regions[db.Region] != 2 || projects[db.Project] != "" && projects[db.Project] != db.Tenant || db.MaxStorageBytes == 0 || db.MaxStorageBytes > activeBackupBytes-(2<<20) || db.MaxStorageBytes > 1<<50 || db.MaxDocuments == 0 || db.MaxDocuments > 1_000_000_000 || db.MaxInflight == 0 || db.MaxInflight > 1_000_000 {
			return nil, bad
		}
		if db.BYOK != nil {
			if err := ValidateBYOKConfig(db.BYOK); err != nil {
				return nil, bad
			}
			if db.Backup == nil {
				return nil, bad
			}
		}
		if len(db.SelectedRegions) == 0 || len(db.SelectedRegions) > 3 {
			return nil, bad
		}
		selected := map[string]bool{}
		for _, region := range db.SelectedRegions {
			if selected[region] || !slices.Contains([]string{"GRU", "SFO", "FRA"}, region) || regions[region] != 2 {
				return nil, bad
			}
			selected[region] = true
		}
		if !selected[db.Region] {
			return nil, bad
		}
		allowed := map[string]bool{}
		for _, region := range db.AllowedRegions {
			if allowed[region] || !slices.Contains([]string{"GRU", "SFO", "FRA"}, region) {
				return nil, bad
			}
			allowed[region] = true
		}
		for region := range selected {
			if !allowed[region] {
				return nil, bad
			}
		}
		projects[db.Project], databases[db.Database] = db.Tenant, true
	}
	for _, h := range d.Hosts {
		region := nodes[h.NodeID].Region
		localDatabases := 0
		bound := false
		for _, db := range d.Databases {
			if !slices.Contains(db.SelectedRegions, region) {
				continue
			}
			localDatabases++
			if db.Database == h.ObserverDatabase {
				bound = true
			}
		}
		// Division checks the aggregate reservation without overflowing a
		// multiplication. Idle members reserve one stream for admission.
		if uint64(max(localDatabases, 1)) > d.BackupDisk.TotalStagingBytes/(d.BackupDisk.StagingBytesPerStream+d.BackupDisk.InventoryBytesPerStream) {
			return nil, bad
		}
		if (localDatabases == 0 && (h.ObserverDatabase != "" || h.DatabaseHost == nil)) || (localDatabases > 0 && !bound) {
			return nil, bad
		}
	}
	l := d.Limits
	if l.MaxMessageBytes < 1024 || l.MaxMessageBytes > 16<<20 || l.MaxInflight == 0 || l.MaxInflight > 4096 || l.RequestTimeoutMillis < 100 || l.RequestTimeoutMillis > 300000 || l.TLSHandshakeTimeoutMillis < 100 || l.TLSHandshakeTimeoutMillis > 30000 || l.ShutdownGraceMillis < 100 || l.ShutdownGraceMillis > 300000 {
		return nil, bad
	}
	return nodes, nil
}

// ValidateBYOKConfig admits only provider references. Secret material is
// deliberately not part of BYOKConfig and therefore cannot be serialized into
// a signed declaration or rendered engine configuration.
func ValidateBYOKConfig(b *BYOKConfig) error {
	if b == nil {
		return errors.New("vmengineconfig: missing BYOK configuration")
	}
	validHTTPS := func(value string, limit int) bool {
		u, err := url.Parse(value)
		return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
	}
	validReference := func(value string, limit int) bool {
		return value != "" && len(value) <= limit && !strings.ContainsAny(value, "\r\n\x00")
	}
	if b.KeyProvider != "aws-kms" {
		return errors.New("vmengineconfig: unsupported BYOK provider")
	}
	if !validHTTPS(b.BackupEndpoint, 2048) || !environment.MatchString(b.BackupBucket) || len(b.BackupBucket) > 63 || !environment.MatchString(b.BackupRegion) || len(b.BackupRegion) > 64 || !strings.HasPrefix(b.BackupRoleARN, "arn:") || !validReference(b.BackupRoleARN, 512) || b.BackupExternalID != "" && !validReference(b.BackupExternalID, 256) || !slices.Contains([]string{"oci-vault", "aws-kms", "azure-key-vault", "customer-kms"}, b.KeyProvider) || !validReference(b.KeyID, 512) || !environment.MatchString(b.KeyRegion) || len(b.KeyRegion) > 64 || b.KeyEndpoint != "" && !validHTTPS(b.KeyEndpoint, 2048) {
		return errors.New("vmengineconfig: invalid BYOK provider reference")
	}
	return nil
}

func render(d Declaration, h Host, nodes map[string]Binding) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "mode = \"production\"\n[environment]\nname = %q\ncluster = %q\nmember = %q\n", d.Environment, d.Cluster, h.Member)
	fmt.Fprintf(&b, "\n[backup_disk]\nstaging_bytes_per_stream = %d\ninventory_bytes_per_stream = %d\ntotal_staging_bytes = %d\n", d.BackupDisk.StagingBytesPerStream, d.BackupDisk.InventoryBytesPerStream, d.BackupDisk.TotalStagingBytes)
	localRegion := nodes[h.NodeID].Region
	for _, db := range d.Databases {
		enabled := slices.Contains(db.SelectedRegions, localRegion)
		renderedRegion := db.Region
		if enabled {
			renderedRegion = localRegion
		}
		selected := slices.Clone(db.SelectedRegions)
		slices.Sort(selected)
		fmt.Fprintf(&b, "\n[[databases]]\ntenant = %q\nproject = %q\ndatabase = %q\nregion = %q\nselected_regions = [", db.Tenant, db.Project, db.Database, renderedRegion)
		for i, region := range selected {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", region)
		}
		encryptionProvider := "oci-vault"
		if db.BYOK != nil {
			// TerraBase uses one provider-neutral customer lease adapter; the
			// concrete cloud provider remains an admitted reference in BYOK.
			encryptionProvider = "customer-kms"
		}
		fmt.Fprintf(&b, "]\nlocation = %q\npolicy_journal = %q\nbackup_root = %q\nencryption_provider = %q\nencryption_key = %q\nenabled = %t\n[databases.quotas]\nmax_storage_bytes = %d\nmax_documents = %d\nmax_inflight = %d\n", dataRoot+"/databases/"+db.Database, dataRoot+"/policies/"+db.Database, dataRoot+"/backups/"+db.Database, encryptionProvider, db.EncryptionKey, enabled, db.MaxStorageBytes, db.MaxDocuments, db.MaxInflight)
		if db.BYOK != nil {
			byok := db.BYOK
			fmt.Fprintf(&b, "[databases.byok]\nbackup_endpoint = %q\nbackup_bucket = %q\nbackup_region = %q\nbackup_role_arn = %q\n", byok.BackupEndpoint, byok.BackupBucket, byok.BackupRegion, byok.BackupRoleARN)
			if byok.BackupExternalID != "" {
				fmt.Fprintf(&b, "backup_external_id = %q\n", byok.BackupExternalID)
			}
			fmt.Fprintf(&b, "key_provider = %q\nkey_id = %q\nkey_region = %q\n", byok.KeyProvider, byok.KeyID, byok.KeyRegion)
			if byok.KeyEndpoint != "" {
				fmt.Fprintf(&b, "key_endpoint = %q\n", byok.KeyEndpoint)
			}
		}
		if db.Backup != nil {
			fmt.Fprintf(&b, "[databases.backup]\npolicy_revision = %q\nretention_days = %d\n", db.Backup.PolicyRevision, db.Backup.RetentionDays)
			for i, d := range db.Backup.Destinations {
				provider, endpoint, signingRegion, bucket := d.Provider, d.Endpoint, d.SigningRegion, d.Bucket
				accessKeyFile, secretKeyFile := backupPath(db.Database, i, "access"), backupPath(db.Database, i, "secret")
				if db.BYOK != nil && i == 0 {
					// Customer S3 credentials are delivered lazily through the
					// workload identity adapter. Empty paths keep secret material
					// out of the declaration and host seed.
					provider = "customer-s3"
					endpoint = db.BYOK.BackupEndpoint
					signingRegion = db.BYOK.BackupRegion
					bucket = db.BYOK.BackupBucket
					accessKeyFile, secretKeyFile = "", ""
				}
				fmt.Fprintf(&b, "[[databases.backup.destinations]]\nprovider = %q\nendpoint = %q\nsigning_region = %q\nbucket = %q\nverified_geography = %q\npermitted_geographies = %q\nplacement_revision = %q\naccess_key_file = %q\nsecret_key_file = %q\nmax_artifact_bytes = %d\nmax_point_bytes = %d\n", provider, endpoint, signingRegion, bucket, d.VerifiedGeography, d.PermittedGeographies, d.PlacementRevision, accessKeyFile, secretKeyFile, d.MaxArtifactBytes, d.MaxPointBytes)
			}
		}
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
	fmt.Fprintf(&b, "\n[control]\nproposal_journal = %q\norchestrator_principals = [", dataRoot+"/proposals.sqlite")
	principals := slices.Clone(h.OrchestratorPrincipals)
	slices.Sort(principals)
	for i, principal := range principals {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", principal)
	}
	fmt.Fprintf(&b, "]\nobserver_principals = [%q]\n", h.ObserverIdentity)
	if err := validateTransitionTrust(d.TransitionTrust); err != nil {
		return "", err
	}
	if d.TransitionTrust != nil && d.TransitionTrust.ReceiptKeyID != "" {
		fmt.Fprintf(&b, "receipt_signing_key_file = %q\nreceipt_signing_key_id = %q\n", receiptSignerPath, d.TransitionTrust.ReceiptKeyID)
	}
	if d.TransitionTrust != nil && d.TransitionTrust.ExportCursorKeyFile != "" {
		fmt.Fprintf(&b, "export_cursor_key_file = %q\n", exportCursorKeyPath)
	}
	renderTransitionTrust(&b, d.TransitionTrust)
	renderDatabaseAdmission(&b, h.DatabaseHost)
	l := d.Limits
	fmt.Fprintf(&b, "\n[transport]\ntbep_listen = \"127.0.0.1:8421\"\nquic_listen = %q\nmetrics_listen = \"127.0.0.1:8423\"\nserver_certificate = %q\nserver_private_key = %q\nclient_ca = %q\nmax_message_bytes = %d\nmax_inflight = %d\nrequest_timeout_millis = %d\ntls_handshake_timeout_millis = %d\nshutdown_grace_millis = %d\n", nodes[h.NodeID].Address+":8422", CertificatePath, PrivateKeyPath, CAPath, l.MaxMessageBytes, l.MaxInflight, l.RequestTimeoutMillis, l.TLSHandshakeTimeoutMillis, l.ShutdownGraceMillis)
	for _, peer := range d.Hosts {
		if peer.NodeID == h.NodeID {
			continue
		}
		fmt.Fprintf(&b, "[[transport.peers]]\nmember = %q\nendpoint = %q\nspiffe_identity = %q\n", peer.Member, nodes[peer.NodeID].Address+":8422", identity(d, peer))
	}
	fmt.Fprintf(&b, "\n[release]\nrelease = %q\ncapabilities = [\"production\", \"tbep\", \"quic\", \"metrics\", \"oci-vault\"]\n", d.Release)
	fmt.Fprintf(&b, "\n[keys]\nsocket = %q\norchestrator_uid = %d\nsocket_gid = %d\n", d.Keys.Socket, d.Keys.OrchestratorUID, d.Keys.SocketGID)
	if d.PublicAPI != nil {
		fmt.Fprintf(&b, "\n[public_api]\nlisten = %q\ndata_root = %q\n", d.PublicAPI.Listen, d.PublicAPI.DataRoot)
		if d.PublicAPI.BootstrapKeyFile != "" {
			fmt.Fprintf(&b, "bootstrap_key_file = %q\n", publicAPIBootstrapKeyPath)
		}
	}
	if d.PublicAPI != nil {
		if err := renderPublicIdentity(&b, d.PublicAPI.Identity); err != nil {
			return "", err
		}
	}
	if b.Len() > hostmanifest.MaximumConfigurationBytes {
		return "", errors.New("vmengineconfig: rendered configuration exceeds engine bound")
	}
	return b.String(), nil
}

func identity(d Declaration, h Host) string {
	return "spiffe://terrascale.tech/" + d.Environment + "/terrabase-member/" + d.Cluster + "/" + h.Member
}
