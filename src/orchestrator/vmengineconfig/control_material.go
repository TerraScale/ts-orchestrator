package vmengineconfig

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

const controlDirectory = "/etc/terrascale/placement"
const controlCertificatePath = controlDirectory + "/engine-client.pem"
const controlPrivateKeyPath = controlDirectory + "/engine-client.key"
const controlCAPath = controlDirectory + "/engine-ca.pem"
const controlNKeyPath = controlDirectory + "/host.nkey"
const controlNATSCertificatePath = controlDirectory + "/nats-client.pem"
const controlNATSPrivateKeyPath = controlDirectory + "/nats-client.key"
const controlNATSCAPath = controlDirectory + "/nats-ca.pem"

// EngineControlCredentials are explicit admitted references. They are separate
// from read-only observation, member transport, and global authority identities.
type EngineControlCredentials struct {
	Identity            string `json:"identity"`
	CertificateFile     string `json:"certificateFile"`
	PrivateKeyFile      string `json:"privateKeyFile"`
	NATSURL             string `json:"natsUrl"`
	NKeyFile            string `json:"nkeyFile"`
	NATSCertificateFile string `json:"natsCertificateFile"`
	NATSPrivateKeyFile  string `json:"natsPrivateKeyFile"`
	NATSCAFile          string `json:"natsCaFile"`
}

// ControlNATSAuthorization is a public exact-host grant for the global R3 broker
// renderer. No authority/journal publication subject or credential is included.
type ControlNATSAuthorization struct {
	PublicNKey         string
	Publish, Subscribe []string
}

func IsControlPath(path string) bool {
	return slices.Contains([]string{placementpublisher.HostFilePath, controlCertificatePath, controlPrivateKeyPath, controlCAPath, controlNKeyPath, controlNATSCertificatePath, controlNATSPrivateKeyPath, controlNATSCAPath}, path)
}
func (m *Material) ControlFiles() map[string][]byte {
	result := make(map[string][]byte, len(m.controlFiles))
	for path, data := range m.controlFiles {
		result[path] = bytes.Clone(data)
	}
	return result
}
func (m *Material) ControlAuthorization() ControlNATSAuthorization {
	grant := m.controlAuthorization
	grant.Publish = slices.Clone(grant.Publish)
	grant.Subscribe = slices.Clone(grant.Subscribe)
	return grant
}
func validateClientMaterial(certificate, privateKey, ca []byte, expected string) (*x509.Certificate, error) {
	bad := errors.New("vmengineconfig: control client certificate binding invalid")
	pair, err := tls.X509KeyPair(certificate, privateKey)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, bad
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA {
		return nil, bad
	}
	if expected != "" && (len(leaf.URIs) != 1 || leaf.URIs[0].String() != expected) {
		return nil, bad
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, bad
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, bad
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, bad
	}
	return leaf, nil
}
func prepareControl(m *Material, d Declaration, h Host, binding Binding) error {
	if h.EngineControl == nil {
		return nil
	}
	control := h.EngineControl
	if !slices.Contains(h.OrchestratorPrincipals, control.Identity) {
		return errors.New("vmengineconfig: control principal is not explicitly admitted")
	}
	m.controlFiles = map[string][]byte{controlCAPath: bytes.Clone(m.ca)}
	for _, file := range []struct {
		source, target string
		private        bool
	}{
		{control.CertificateFile, controlCertificatePath, false}, {control.PrivateKeyFile, controlPrivateKeyPath, true}, {control.NKeyFile, controlNKeyPath, true},
		{control.NATSCertificateFile, controlNATSCertificatePath, false}, {control.NATSPrivateKeyFile, controlNATSPrivateKeyPath, true}, {control.NATSCAFile, controlNATSCAPath, false},
	} {
		raw, err := initialgrant.ReadMaterialFile(file.source, 64<<10, file.private)
		if err != nil {
			return errors.New("vmengineconfig: protected control material read refused")
		}
		m.controlFiles[file.target] = raw
	}
	engineLeaf, err := validateClientMaterial(m.controlFiles[controlCertificatePath], m.controlFiles[controlPrivateKeyPath], m.ca, control.Identity)
	if err != nil {
		return err
	}
	natsLeaf, err := validateClientMaterial(m.controlFiles[controlNATSCertificatePath], m.controlFiles[controlNATSPrivateKeyPath], m.controlFiles[controlNATSCAPath], "")
	if err != nil {
		return err
	}
	memberPair, err := tls.X509KeyPair(m.certificate, m.privateKey)
	if err != nil {
		return err
	}
	memberLeaf, err := x509.ParseCertificate(memberPair.Certificate[0])
	if err != nil {
		return err
	}
	observerPair, err := tls.X509KeyPair(m.observerCertificate, m.observerPrivateKey)
	if err != nil {
		return err
	}
	observerLeaf, err := x509.ParseCertificate(observerPair.Certificate[0])
	if err != nil {
		return err
	}
	keys := [][]byte{engineLeaf.RawSubjectPublicKeyInfo, natsLeaf.RawSubjectPublicKeyInfo, memberLeaf.RawSubjectPublicKeyInfo, observerLeaf.RawSubjectPublicKeyInfo}
	for i, key := range keys {
		for _, other := range keys[i+1:] {
			if bytes.Equal(key, other) {
				return errors.New("vmengineconfig: engine control, NATS, observation and member keys must be distinct")
			}
		}
	}
	pair, err := nkeys.FromSeed(m.controlFiles[controlNKeyPath])
	if err != nil {
		return errors.New("vmengineconfig: dedicated host NKey invalid")
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return errors.New("vmengineconfig: host control requires user NKey")
	}
	publish, subscribe, err := placementpublisher.HostPermissions(identity(d, h))
	if err != nil {
		return err
	}
	m.controlAuthorization = ControlNATSAuthorization{PublicNKey: public, Publish: publish, Subscribe: subscribe}
	config := placementpublisher.HostFileConfig{Version: 1, Cell: strings.ToLower(binding.Region), Instance: h.NodeID, NATSURL: control.NATSURL, NKeyFile: controlNKeyPath,
		NATSIdentity:   placementpublisher.TLSFiles{CertificateFile: controlNATSCertificatePath, PrivateKeyFile: controlNATSPrivateKeyPath, TrustBundleFile: controlNATSCAPath},
		EngineEndpoint: "127.0.0.1:8421", EngineIdentity: identity(d, h), EngineTLS: placementpublisher.TLSFiles{CertificateFile: controlCertificatePath, PrivateKeyFile: controlPrivateKeyPath, TrustBundleFile: controlCAPath}}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	if _, err := placementpublisher.ParseHostFile(raw, config.Cell, config.Instance); err != nil {
		return err
	}
	m.controlFiles[placementpublisher.HostFilePath] = raw
	return nil
}

func (m *Material) applyControlManifest(manifest hostmanifest.HostManifest) (hostmanifest.HostManifest, error) {
	if len(m.controlFiles) == 0 {
		return manifest, nil
	}
	config, err := placementpublisher.ParseHostFile(m.controlFiles[placementpublisher.HostFilePath], m.cell, m.nodeID)
	if err != nil {
		return manifest, err
	}
	found := false
	for i, component := range manifest.Components {
		if component.Name != "orchestrator" {
			continue
		}
		if found || (component.Arguments != "" && component.Arguments != "run --config @config") {
			return manifest, errors.New("vmengineconfig: control material requires the production run manifest")
		}
		found = true
		settings := map[string]string{}
		if component.Configuration != "" && json.Unmarshal([]byte(component.Configuration), &settings) != nil {
			return manifest, errors.New("vmengineconfig: orchestrator run settings invalid")
		}
		for key, value := range map[string]string{"TS_ORCH_PLACEMENT_HOST_FILE": placementpublisher.HostFilePath, "TS_ORCH_CELL": config.Cell, "TS_ORCH_INSTANCE": config.Instance} {
			if prior, exists := settings[key]; exists && prior != value {
				return manifest, errors.New("vmengineconfig: orchestrator control host setting differs")
			}
			settings[key] = value
		}
		raw, err := json.Marshal(settings)
		if err != nil {
			return manifest, err
		}
		component.Configuration = string(raw)
		component.Arguments = "run --config @config"
		manifest.Components[i], err = hostmanifest.NewComponentSpec(component)
		if err != nil {
			return manifest, err
		}
	}
	if !found {
		return manifest, errors.New("vmengineconfig: orchestrator component required for control material")
	}
	return manifest, nil
}
func (m *Material) validateControlManifest(manifest hostmanifest.HostManifest) error {
	if len(m.controlFiles) == 0 {
		return nil
	}
	found := 0
	for _, component := range manifest.Components {
		if component.Name != "orchestrator" {
			continue
		}
		found++
		var settings map[string]string
		if component.Arguments != "run --config @config" || json.Unmarshal([]byte(component.Configuration), &settings) != nil || settings["TS_ORCH_PLACEMENT_HOST_FILE"] != placementpublisher.HostFilePath || settings["TS_ORCH_CELL"] != m.cell || settings["TS_ORCH_INSTANCE"] != m.nodeID {
			return errors.New("vmengineconfig: signed host control configuration differs")
		}
	}
	if found != 1 {
		return errors.New("vmengineconfig: signed control host inventory differs")
	}
	return nil
}
