package vmcontrolseed

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/runmaterial"
)

const RunArguments = "run --config @config"

var runTargetPattern = regexp.MustCompile(`^/etc/terrascale/[A-Za-z0-9_./-]+$`)

// RunDeclaration is owner input for the post-promotion production stage. It
// never grants permission to run ordinary global journals on initial GRU R1.
// The existing signed host command binds the complete manifest and generation;
// actual authority and topology are checked by the production runtime.
type RunDeclaration struct {
	Version int            `json:"version"`
	Hosts   []RunAdmission `json:"hosts"`
}
type RunFile struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}
type RunConnection struct {
	Endpoint   string                  `json:"endpoint"`
	ServerName string                  `json:"serverName"`
	Account    string                  `json:"account"`
	Connection initialgrant.Connection `json:"connection"`
}
type RunAdmission struct {
	HostID     string             `json:"hostId"`
	Generation uint64             `json:"generation"`
	Settings   map[string]string  `json:"settings"`
	Regional   RunConnection      `json:"regional"`
	Global     *RunConnection     `json:"global,omitempty"`
	Files      map[string]RunFile `json:"files"`
}
type RunMaterial struct {
	Manifest            hostmanifest.HostManifest
	ExpectedManifestSHA string
	Generation          uint64
	Files               map[string][]byte
	Regional            RunConnection
	Global              *RunConnection
	HostID              string
	manifestSHA         string
	identitySHA         string
	fileDigests         map[string]string
}

func LoadRunDeclaration(path string) (RunDeclaration, error) {
	raw, err := initialgrant.ReadMaterialFile(path, 1<<20, false)
	if err != nil {
		return RunDeclaration{}, errors.New("vmcontrolseed: run declaration read refused")
	}
	var declaration RunDeclaration
	if json.Unmarshal(raw, &declaration, json.RejectUnknownMembers(true)) != nil || declaration.Version != 1 || len(declaration.Hosts) == 0 || len(declaration.Hosts) > 3 {
		return RunDeclaration{}, errors.New("vmcontrolseed: invalid GRU run declaration")
	}
	seen := map[string]bool{}
	global := false
	for _, host := range declaration.Hosts {
		if !identifierPattern.MatchString(host.HostID) || !strings.HasPrefix(host.HostID, "gru-") || seen[host.HostID] || host.Generation == 0 || host.Generation > 1<<63-1 {
			return RunDeclaration{}, errors.New("vmcontrolseed: invalid run host or desired generation")
		}
		seen[host.HostID] = true
		global = global || host.Global != nil
	}
	if !global {
		return RunDeclaration{}, errors.New("vmcontrolseed: run declaration requires explicit GRU global authority credentials")
	}
	return declaration, nil
}

func (m *RunMaterial) Clear() {
	if m == nil {
		return
	}
	for _, data := range m.Files {
		clear(data)
	}
}
func (m *RunMaterial) Clone() *RunMaterial {
	if m == nil {
		return nil
	}
	out := *m
	out.Manifest.Components = slices.Clone(m.Manifest.Components)
	out.Files = map[string][]byte{}
	out.fileDigests = maps.Clone(m.fileDigests)
	for path, data := range m.Files {
		out.Files[path] = bytes.Clone(data)
	}
	if m.Global != nil {
		out.Global = new(*m.Global)
	}
	return &out
}

// RunManifest preserves the complete engine-applied run configuration and
// constructs a CAS handoff from this host's initial manifest. Credentials are
// separately admitted production identities; initial-only NKeys and TLS private
// keys cannot be reused. This function does not observe or manufacture a lease.
func (m Material) RunManifest(base hostmanifest.HostManifest, admission RunAdmission) (_ *RunMaterial, err error) {
	bad := errors.New("vmcontrolseed: production run admission differs from host, settings or protected material")
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if admission.HostID != m.HostID || admission.Generation == 0 || admission.Generation > 1<<63-1 || len(admission.Files) == 0 || len(admission.Files) > 128 {
		return nil, bad
	}
	initialConfig, err := initialgrant.ParseConfig([]byte(m.Settings))
	if err != nil {
		return nil, err
	}
	result := &RunMaterial{HostID: m.HostID, Generation: admission.Generation, Regional: admission.Regional, Global: admission.Global, Files: map[string][]byte{}, fileDigests: map[string]string{}}
	defer func() {
		if err != nil {
			result.Clear()
		}
	}()
	for target, file := range admission.Files {
		if !hostmanifest.SafeAbsolutePath(target) || !runTargetPattern.MatchString(target) || !hostmanifest.ValidDigest(file.SHA256) || m.Files[target] != nil || target == MembershipKeyPath || target == MembershipPinsPath {
			return nil, bad
		}
		raw, readErr := initialgrant.ReadMaterialFile(file.Source, 1<<20, true)
		if readErr != nil {
			return nil, bad
		}
		result.Files[target] = raw
		if digest(raw) != file.SHA256 {
			return nil, bad
		}
		result.fileDigests[target] = file.SHA256
	}
	if admission.Global == nil {
		for key := range admission.Settings {
			if strings.HasPrefix(key, "TS_ORCH_GLOBAL_NATS_") {
				return nil, bad
			}
		}
	}
	settings := maps.Clone(admission.Settings)
	if settings == nil {
		return nil, bad
	}
	for _, key := range []string{"TS_ORCH_PROVIDER", "TS_ORCH_PRODUCTION_RUNTIME_FILE", "TS_ORCH_REPLICAS"} {
		if settings[key] == "" {
			return nil, bad
		}
	}
	if settings["TS_ORCH_PROVIDER"] != "oci" || settings["TS_ORCH_REPLICAS"] != "3" {
		return nil, bad
	}
	if result.Files[settings["TS_ORCH_PRODUCTION_RUNTIME_FILE"]] == nil {
		return nil, bad
	}
	put := func(key, value string) bool {
		if old, ok := settings[key]; ok && old != value {
			return false
		}
		settings[key] = value
		return true
	}
	if !put("TS_ORCH_CELL", initialConfig.Cell) || !put("TS_ORCH_INSTANCE", initialConfig.Instance) || !put("TS_ORCH_MEMBERSHIP_SIGNING_KEY_FILE", MembershipKeyPath) || !put("TS_ORCH_MEMBERSHIP_PINS_FILE", MembershipPinsPath) {
		return nil, bad
	}
	for _, entry := range []struct {
		prefix     string
		connection *RunConnection
	}{{"TS_ORCH", &admission.Regional}, {"TS_ORCH_GLOBAL", admission.Global}} {
		if entry.connection == nil {
			continue
		}
		if validateRunConnection(*entry.connection, result.Files, m.Files) != nil {
			return nil, bad
		}
		c := entry.connection.Connection
		for key, value := range map[string]string{"_NATS_URL": entry.connection.Endpoint, "_NATS_NKEY_FILE": c.NKeySeedFile, "_NATS_TLS_CA_FILE": c.TLS.CAFile, "_NATS_TLS_CERT_FILE": c.TLS.CertificateFile, "_NATS_TLS_KEY_FILE": c.TLS.KeyFile} {
			if !put(entry.prefix+key, value) {
				return nil, bad
			}
		}
	}
	if admission.Global != nil && (admission.Global.Connection.PublicNKey == admission.Regional.Connection.PublicNKey || bytes.Equal(result.Files[admission.Global.Connection.TLS.KeyFile], result.Files[admission.Regional.Connection.TLS.KeyFile])) {
		return nil, bad
	}
	if broker, selected := settings["TS_ORCH_NATS_SERVER_CONFIG_FILE"]; selected && result.Files[broker] == nil {
		return nil, bad
	}
	inventoryPath, inventoryBytes, inventoryErr := runmaterial.Build(result.Files)
	if inventoryErr != nil {
		return nil, inventoryErr
	}
	if !put(runmaterial.Environment, inventoryPath) || result.Files[inventoryPath] != nil {
		return nil, bad
	}
	result.Files[inventoryPath] = inventoryBytes
	result.fileDigests[inventoryPath] = digest(inventoryBytes)
	base.Components = slices.Clone(base.Components)
	found := false
	for i, component := range base.Components {
		if component.Name != "orchestrator" {
			continue
		}
		if found || (component.Arguments != "" && component.Arguments != RunArguments) {
			return nil, bad
		}
		found = true
		prior := map[string]string{}
		if component.Configuration != "" && json.Unmarshal([]byte(component.Configuration), &prior) != nil {
			return nil, bad
		}
		for key, value := range prior {
			if !put(key, value) {
				return nil, bad
			}
		}
		raw, marshalErr := json.Marshal(settings, json.Deterministic(true))
		if marshalErr != nil {
			return nil, marshalErr
		}
		component.Arguments, component.Configuration = RunArguments, string(raw)
		base.Components[i] = component
	}
	if !found {
		return nil, bad
	}
	result.Manifest, err = bootstrap.PlanControlLaunchManifest(base)
	if err != nil {
		return nil, err
	}
	raw, err := hostmanifest.CanonicalHostManifestJSON(base)
	if err != nil {
		return nil, err
	}
	initial, err := m.LaunchManifest(raw)
	if err != nil {
		return nil, err
	}
	result.ExpectedManifestSHA, err = hostmanifest.HostManifestSha256(initial)
	if err != nil {
		return nil, err
	}
	result.manifestSHA, err = hostmanifest.HostManifestSha256(result.Manifest)
	if err != nil {
		return nil, err
	}
	result.identitySHA, err = result.identityDigest()
	return result, err
}

func validateRunConnection(c RunConnection, files, initial map[string][]byte) error {
	bad := errors.New("vmcontrolseed: production connection material invalid")
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || !identifierPattern.MatchString(c.ServerName) || c.Account == "" {
		return bad
	}
	conn := c.Connection
	if digest(files[conn.TLS.CAFile]) != conn.TLS.CASHA256 || digest(files[conn.TLS.CertificateFile]) != conn.TLS.CertificateSHA256 {
		return bad
	}
	pair, err := nkeys.FromSeed(files[conn.NKeySeedFile])
	if err != nil {
		return bad
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil || public != conn.PublicNKey || !nkeys.IsValidPublicUserKey(public) {
		return bad
	}
	identity, err := tls.X509KeyPair(files[conn.TLS.CertificateFile], files[conn.TLS.KeyFile])
	if err != nil || len(identity.Certificate) == 0 {
		return bad
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return bad
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(files[conn.TLS.CAFile]) {
		return bad
	}
	intermediates := x509.NewCertPool()
	for _, raw := range identity.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return bad
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return bad
	}
	for _, data := range initial {
		if block, _ := pem.Decode(data); block != nil && block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil && bytes.Equal(cert.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
				return bad
			}
		}
		if bytes.Equal(data, files[conn.NKeySeedFile]) || bytes.Equal(data, files[conn.TLS.KeyFile]) {
			return bad
		}
	}
	return nil
}

// ValidateStage rejects a mutated sideband or a different initial predecessor.
func (m *RunMaterial) ValidateStage(initial Material, manifest hostmanifest.HostManifest) error {
	bad := errors.New("vmcontrolseed: run sideband differs from admitted stage")
	if m == nil || initial.HostID != m.HostID || m.Generation == 0 || len(m.fileDigests) == 0 || len(m.Files) != len(m.fileDigests) {
		return bad
	}
	identity, err := m.identityDigest()
	if err != nil || identity != m.identitySHA {
		return bad
	}
	predecessor, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil || predecessor != m.ExpectedManifestSHA {
		return bad
	}
	final, err := hostmanifest.HostManifestSha256(m.Manifest)
	if err != nil || final != m.manifestSHA {
		return bad
	}
	for path, want := range m.fileDigests {
		if digest(m.Files[path]) != want {
			return bad
		}
	}
	return nil
}

func (m *RunMaterial) identityDigest() (string, error) {
	raw, err := json.Marshal(struct {
		HostID     string
		Generation uint64
		Regional   RunConnection
		Global     *RunConnection
	}{m.HostID, m.Generation, m.Regional, m.Global}, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}
