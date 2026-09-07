package vmengineconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentity"
)

const databaseDirectory = "/etc/terrascale/database"
const databaseNKeyPath = databaseDirectory + "/host.nkey"
const databaseLifecycleNKeyPath = databaseDirectory + "/lifecycle.nkey"
const databaseCertificatePath = databaseDirectory + "/nats-client.pem"
const databasePrivateKeyPath = databaseDirectory + "/nats-client.key"
const databaseCAPath = databaseDirectory + "/nats-ca.pem"

// DatabaseHostCredentials contains explicit inputs from the deployment issuer.
// Admission, lifecycle publication, and placement never share NKeys.
type DatabaseHostCredentials struct {
	DataRoot          string `json:"dataRoot"`
	NATSURL           string `json:"natsUrl"`
	NATSAccount       string `json:"natsAccount"`
	NKeyFile          string `json:"nkeyFile"`
	LifecycleNKeyFile string `json:"lifecycleNkeyFile"`
	CertificateFile   string `json:"certificateFile"`
	PrivateKeyFile    string `json:"privateKeyFile"`
	CAFile            string `json:"caFile"`
	CatalogPath       string `json:"catalogPath"`
	EngineSocket      string `json:"engineSocket"`
	IngressSocket     string `json:"ingressSocket"`
	IngressUID        uint32 `json:"ingressUid"`
}

func IsDatabasePath(path string) bool {
	return slices.Contains([]string{databaseadmission.HostFilePath, databaseadmission.BrokerGrantsPath, databaseNKeyPath, databaseLifecycleNKeyPath, databaseCertificatePath, databasePrivateKeyPath, databaseCAPath}, path)
}
func (m *Material) DatabaseFiles() map[string][]byte {
	out := map[string][]byte{}
	for path, raw := range m.databaseFiles {
		out[path] = bytes.Clone(raw)
	}
	return out
}
func prepareDatabase(m *Material, d Declaration, h Host, binding Binding) error {
	c := h.DatabaseHost
	if c == nil {
		return nil
	}
	bad := errors.New("vmengineconfig: database host admission material invalid")
	u, err := url.Parse(c.NATSURL)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || c.IngressUID == 0 {
		return bad
	}
	for _, path := range []string{c.CatalogPath, c.EngineSocket, c.IngressSocket} {
		if !hostmanifest.SafeAbsolutePath(path) {
			return bad
		}
	}
	if !hostmanifest.SafeAbsolutePath(c.DataRoot) || !strings.HasPrefix(c.DataRoot, dataRoot+"/") {
		return bad
	}
	if c.EngineSocket == c.IngressSocket || c.CatalogPath == c.EngineSocket || c.CatalogPath == c.IngressSocket {
		return bad
	}
	m.databaseFiles = map[string][]byte{}
	for _, file := range []struct {
		source, target string
		private        bool
	}{{c.NKeyFile, databaseNKeyPath, true}, {c.LifecycleNKeyFile, databaseLifecycleNKeyPath, true}, {c.CertificateFile, databaseCertificatePath, false}, {c.PrivateKeyFile, databasePrivateKeyPath, true}, {c.CAFile, databaseCAPath, false}} {
		raw, err := initialgrant.ReadMaterialFile(file.source, 64<<10, file.private)
		if err != nil {
			return bad
		}
		m.databaseFiles[file.target] = raw
	}
	leaf, err := validateClientMaterial(m.databaseFiles[databaseCertificatePath], m.databaseFiles[databasePrivateKeyPath], m.databaseFiles[databaseCAPath], "")
	if err != nil {
		return err
	}
	// The dedicated database TLS key cannot be a placement, engine, or observer key.
	for _, raw := range [][]byte{m.certificate, m.observerCertificate, m.controlFiles[controlNATSCertificatePath], m.controlFiles[controlCertificatePath]} {
		if len(raw) == 0 {
			continue
		}
		if sameCertificateKey(raw, leaf.RawSubjectPublicKeyInfo) {
			return bad
		}
	}
	publics := []string{}
	for _, path := range []string{databaseNKeyPath, databaseLifecycleNKeyPath} {
		pair, err := nkeys.FromSeed(m.databaseFiles[path])
		if err != nil {
			return bad
		}
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil || !nkeys.IsValidPublicUserKey(public) || public == m.controlAuthorization.PublicNKey || slices.Contains(publics, public) {
			return bad
		}
		publics = append(publics, public)
	}
	m.databaseAuthorization = databaseadmission.BrokerGrant{ServerIdentity: identity(d, h), PublicNKey: publics[0], LifecyclePublicNKey: publics[1], Account: c.NATSAccount}
	config := databaseadmission.HostFileConfig{Version: 1, Cell: strings.ToLower(binding.Region), Instance: h.NodeID, Environment: d.Environment, MemberID: h.Member, ServerIdentity: identity(d, h), CatalogPath: c.CatalogPath, EngineSocket: c.EngineSocket, EngineUID: serviceidentity.TerraBaseUID, IngressSocket: c.IngressSocket, IngressUID: c.IngressUID, NATSURL: c.NATSURL, NKeyFile: databaseNKeyPath, LifecycleNKeyFile: databaseLifecycleNKeyPath, TLS: placementpublisher.TLSFiles{CertificateFile: databaseCertificatePath, PrivateKeyFile: databasePrivateKeyPath, TrustBundleFile: databaseCAPath}}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	m.databaseFiles[databaseadmission.HostFilePath] = raw
	return nil
}
func (m *Material) applyDatabaseManifest(manifest hostmanifest.HostManifest) (hostmanifest.HostManifest, error) {
	if len(m.databaseFiles) == 0 {
		return manifest, nil
	}
	var config databaseadmission.HostFileConfig
	if json.Unmarshal(m.databaseFiles[databaseadmission.HostFilePath], &config) != nil {
		return manifest, errors.New("vmengineconfig: database host config missing")
	}
	found := false
	for i, c := range manifest.Components {
		if c.Name != "orchestrator" {
			continue
		}
		if found || c.User != serviceidentity.Orchestrator || (c.Arguments != "" && c.Arguments != "run --config @config") {
			return manifest, errors.New("vmengineconfig: database host requires canonical orchestrator")
		}
		found = true
		settings := map[string]string{}
		if c.Configuration != "" && json.Unmarshal([]byte(c.Configuration), &settings) != nil {
			return manifest, errors.New("vmengineconfig: database host run settings invalid")
		}
		for key, value := range map[string]string{databaseadmission.HostFileEnvironment: databaseadmission.HostFilePath, databaseadmission.BrokerGrantsEnvironment: databaseadmission.BrokerGrantsPath, "TS_ORCH_CELL": config.Cell, "TS_ORCH_INSTANCE": config.Instance, "TS_ORCH_KEY_LEASE_SOCKET_FILE": serviceidentity.SocketPath, "TS_ORCH_KEY_LEASE_CATALOG_FILE": config.CatalogPath, "TS_ORCH_KEY_LEASE_ENVIRONMENT": config.Environment, "TS_ORCH_KEY_LEASE_PEER_UID": strconv.Itoa(serviceidentity.TerraBaseUID), "TS_ORCH_KEY_LEASE_SOCKET_GID": strconv.Itoa(serviceidentity.SocketGID)} {
			if previous, ok := settings[key]; ok && previous != value {
				return manifest, errors.New("vmengineconfig: database host environment differs")
			}
			settings[key] = value
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			return manifest, err
		}
		c.Configuration = string(raw)
		c.Arguments = "run --config @config"
		manifest.Components[i], err = hostmanifest.NewComponentSpec(c)
		if err != nil {
			return manifest, err
		}
	}
	if !found {
		return manifest, errors.New("vmengineconfig: database host orchestrator missing")
	}
	return manifest, nil
}
func (m *Material) validateDatabaseManifest(manifest hostmanifest.HostManifest) error {
	if len(m.databaseFiles) == 0 {
		return nil
	}
	copy := manifest
	copy.Components = slices.Clone(manifest.Components)
	applied, err := m.applyDatabaseManifest(copy)
	if err != nil {
		return err
	}
	for i, c := range manifest.Components {
		var original, next map[string]string
		if c.Name != "orchestrator" {
			continue
		}
		if json.Unmarshal([]byte(c.Configuration), &original) != nil || json.Unmarshal([]byte(applied.Components[i].Configuration), &next) != nil || !maps.Equal(original, next) || c.Arguments != applied.Components[i].Arguments {
			return errors.New("vmengineconfig: signed database host settings differ")
		}
	}
	return nil
}

func sameCertificateKey(raw, public []byte) bool {
	block, _ := pem.Decode(raw)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return err == nil && bytes.Equal(cert.RawSubjectPublicKeyInfo, public)
}

func renderDatabaseAdmission(out *strings.Builder, c *DatabaseHostCredentials) {
	if c == nil {
		return
	}
	fmt.Fprintf(out, "\n[member_admission]\ndata_root = %q\nsocket = %q\nallowed_uid = %d\nsocket_gid = %d\n", c.DataRoot, c.EngineSocket, serviceidentity.OrchestratorUID, serviceidentity.SocketGID)
}
