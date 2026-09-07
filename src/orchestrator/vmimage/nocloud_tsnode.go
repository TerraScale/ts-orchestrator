package vmimage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"time"

	"github.com/nats-io/nkeys"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
	"terrascale.tech/orchestrator/src/orchestrator/tsnodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

const (
	maxTSNodeBinaryBytes        = MaxServiceBinaryBytes
	maxDesiredManifestBytes     = 64 << 10
	maxArtifactCACertificate    = 64 << 10
	tsNodeNATSDirectory         = "/etc/terrascale/ts-node-nats"
	tsNodeNKeyPath              = tsNodeNATSDirectory + "/user.seed"
	tsNodeTLSCAPath             = tsNodeNATSDirectory + "/ca.pem"
	tsNodeTLSCertPath           = tsNodeNATSDirectory + "/client.pem"
	tsNodeTLSKeyPath            = tsNodeNATSDirectory + "/client.key"
	tsNodeConfigPath            = "/etc/terrascale/ts-node.json"
	tsNodeStateDirectory        = "/var/lib/terrascale/ts-node"
	desiredHostManifestPath     = tsNodeStateDirectory + "/manifest.json"
	tsNodeBootstrapDirectory    = "/opt/terrascale/bootstrap"
	tsNodeBootstrapBinaryPath   = tsNodeBootstrapDirectory + "/ts-node"
	tsNodeBootstrapDigestPath   = tsNodeBootstrapDirectory + "/ts-node.sha256"
	tsNodeBootstrapKeyPath      = tsNodeBootstrapDirectory + "/ts-node.pub"
	tsNodeBootstrapManifestPath = tsNodeBootstrapDirectory + "/manifest.json"
	tsNodeBootstrapSigPath      = tsNodeBootstrapDirectory + "/ts-node.sig"
	tsNodeBootstrapScriptPath   = tsNodeBootstrapDirectory + "/bootstrap.sh"
	artifactCAPath              = "/usr/local/share/ca-certificates/terrascale-vmqual-artifact-ca.crt"
	cloudHostsTemplatePath      = "/etc/cloud/templates/hosts.debian.tmpl"
	artifactReleaseHost         = "releases.terrascale.tech"
	artifactReleasePort         = "8443"
)

// TSNodeConfig is the bounded qualification configuration for the production
// host agent. Paths and the release key are derived by vmimage and cannot be
// redirected by a caller.
type TSNodeConfig struct {
	engineObservation *tbep.FileConfig
	AuthorityReader   nodeauthority.ReaderConfig
	AuthorityBucket   string
	CommandTrustKeys  []TSNodeCommandTrust
	NodeID            string
	NATSURL           string
	HeartbeatInterval time.Duration
	ReconcileInterval time.Duration
}

func buildTSNodeBootstrapScript(tsNode tsNodeBootstrapMaterial) string {
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("set -eu\n")
	script.WriteString("/usr/bin/cloud-init single --name update_etc_hosts --frequency always\n")
	if len(tsNode.ca) != 0 {
		script.WriteString("/usr/sbin/update-ca-certificates\n")
	}
	script.WriteString("/usr/bin/sha256sum --check --strict " + tsNodeBootstrapDigestPath + "\n")
	script.WriteString("/usr/bin/openssl pkeyutl -verify -pubin -inkey " + tsNodeBootstrapKeyPath + " -rawin -in " + tsNodeBootstrapBinaryPath + " -sigfile " + tsNodeBootstrapSigPath + "\n")
	script.WriteString("/usr/bin/install -d -o root -g root -m 0700 " + tsNodeStateDirectory + "\n")
	script.WriteString("/usr/bin/install -o root -g root -m 0600 " + tsNodeBootstrapManifestPath + " " + desiredHostManifestPath + "\n")
	versionDirectory := "/opt/terrascale/ts-node/" + tsNode.version
	script.WriteString("/usr/bin/install -d -o root -g root -m 0755 " + versionDirectory + "\n")
	script.WriteString("/usr/bin/install -o root -g root -m 0755 " + tsNodeBootstrapBinaryPath + " " + versionDirectory + "/ts-node\n")
	script.WriteString("/usr/bin/install -o root -g root -m 0444 " + tsNodeBootstrapSigPath + " " + versionDirectory + "/ts-node.sig\n")
	script.WriteString("/usr/bin/ln -sfnT " + versionDirectory + " /opt/terrascale/ts-node/current\n")
	script.WriteString("/usr/bin/systemctl daemon-reload\n")
	script.WriteString(chronyBootstrapScript())
	script.WriteString(membershipOwnershipBootstrap())
	script.WriteString(controllerOwnershipBootstrap(tsNode.commandTrustFiles))
	script.WriteString(engineOwnershipBootstrap(tsNode.commandTrustFiles))
	script.WriteString("/usr/bin/systemctl enable --now " + tsnodebootstrap.UnitName + "\n")
	script.WriteString("/usr/bin/rm -f " + tsNodeBootstrapBinaryPath + " " + tsNodeBootstrapSigPath + " " + tsNodeBootstrapKeyPath + " " + tsNodeBootstrapDigestPath + " " + tsNodeBootstrapManifestPath + " " + tsNodeBootstrapScriptPath + "\n")
	script.WriteString("/usr/bin/rmdir " + tsNodeBootstrapDirectory + "\n")
	return script.String()
}

// TSNodeNATSIdentity holds one admitted guest identity. It is copied into
// root-only files in the private guest disk, never cloud-init user data.
type TSNodeNATSIdentity struct {
	NKeySeed       []byte
	TLSCA          []byte
	TLSCertificate []byte
	TLSPrivateKey  []byte
}

// TSNodeBootstrap is the only production bootstrap material admitted into a
// NoCloud seed. Orchestrator and TerraBase remain desired-manifest artifacts
// fetched and reconciled by the running ts-node.
type TSNodeBootstrap struct {
	Engine                       *vmengineconfig.Material
	Controller                   *vmcontrolseed.Material
	ControllerRun                *vmcontrolseed.RunMaterial
	Candidate                    *vmcandidateseed.Material
	InitialGrant                 *TSNodeInitialGrant
	MembershipIdentityPrivateKey []byte
	MembershipPins               map[string]string
	NATSIdentity                 *TSNodeNATSIdentity
	Version                      string
	Binary                       []byte
	SHA256                       string
	Signature                    []byte
	ReleasePublicKey             ed25519.PublicKey
	Config                       TSNodeConfig
	DesiredHostManifest          []byte
	ArtifactCACertificate        []byte
	ArtifactHostAddress          string
}

type tsNodeBootstrapMaterial struct {
	commandTrustFiles []NoCloudRootFile
	membershipPrivate []byte
	membershipPins    []byte
	identity          *TSNodeNATSIdentity
	version           string
	digest            string
	binary            []byte
	signature         []byte
	publicKeyPEM      []byte
	config            []byte
	launchManifest    []byte
	manifest          []byte
	ca                []byte
	hostAddress       string
	unit              string
	desired           hostmanifest.HostManifest
}

type tsNodeConfigurationFile struct {
	EngineObservation             *tbep.FileConfig           `json:"engineObservation,omitempty"`
	AuthorityReader               nodeauthority.ReaderConfig `json:"authorityReader"`
	BootstrapBeforeNATS           bool                       `json:"bootstrapBeforeNats"`
	BootstrapGrantFile            string                     `json:"bootstrapGrantFile"`
	BootstrapPublicKeyFile        string                     `json:"bootstrapPublicKeyFile"`
	AuthorityBucket               string                     `json:"authorityBucket"`
	CommandTrustKeys              []tsNodeCommandTrustFile   `json:"commandTrustKeys"`
	NodeID                        string                     `json:"nodeId"`
	NATSURL                       string                     `json:"natsUrl"`
	NATSNKeyFile                  string                     `json:"natsNkeyFile"`
	NATSTLSCAFile                 string                     `json:"natsTlsCaFile"`
	NATSTLSCertFile               string                     `json:"natsTlsCertFile"`
	NATSTLSKeyFile                string                     `json:"natsTlsKeyFile"`
	ReleasePublicKey              string                     `json:"releasePublicKey"`
	ManifestPath                  string                     `json:"manifestPath"`
	InstallRoot                   string                     `json:"installRoot"`
	UnitDir                       string                     `json:"unitDir"`
	DataVolumeRoot                string                     `json:"dataVolumeRoot"`
	ChronycBinary                 string                     `json:"chronycBinary"`
	SystemctlBinary               string                     `json:"systemctlBinary"`
	UseraddBinary                 string                     `json:"useraddBinary"`
	HeartbeatIntervalMilliseconds int64                      `json:"heartbeatIntervalMilliseconds"`
	ReconcileIntervalMilliseconds int64                      `json:"reconcileIntervalMilliseconds"`
}

func canonicalTSNodeBootstrap(input TSNodeBootstrap, architecture Architecture) (tsNodeBootstrapMaterial, error) {
	if !namePattern.MatchString(input.Version) || len(input.Version) > 128 || reservedReleaseVersion(input.Version) {
		return tsNodeBootstrapMaterial{}, errors.New("vmimage: ts-node bootstrap version is invalid")
	}
	if len(input.Binary) == 0 || len(input.Binary) > maxTSNodeBinaryBytes {
		return tsNodeBootstrapMaterial{}, errors.New("vmimage: ts-node bootstrap binary size is invalid")
	}
	if err := validateStaticELF(input.Binary, architecture); err != nil {
		return tsNodeBootstrapMaterial{}, fmt.Errorf("vmimage: ts-node bootstrap binary: %w", err)
	}
	if !validDigest(input.SHA256) {
		return tsNodeBootstrapMaterial{}, errors.New("vmimage: ts-node bootstrap digest is invalid")
	}
	digest := sha256.Sum256(input.Binary)
	if hex.EncodeToString(digest[:]) != input.SHA256 {
		return tsNodeBootstrapMaterial{}, errors.New("vmimage: ts-node bootstrap binary does not match its digest")
	}
	if len(input.ReleasePublicKey) != ed25519.PublicKeySize || len(input.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(input.ReleasePublicKey, input.Binary, input.Signature) {
		return tsNodeBootstrapMaterial{}, errors.New("vmimage: ts-node bootstrap signature is invalid")
	}
	grantFiles, err := canonicalInitialGrant(input)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	_, commandFiles, err := canonicalCommandTrust(input.Config)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	commandFiles = append(commandFiles, grantFiles...)
	controllerFiles, err := canonicalControllerBootstrap(input)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	commandFiles = append(commandFiles, controllerFiles...)
	candidateFiles, err := canonicalCandidateBootstrap(input)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	commandFiles = append(commandFiles, candidateFiles...)
	engineFiles, err := canonicalEngineBootstrap(input)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	commandFiles = append(commandFiles, engineFiles...)
	memberPrivate, memberPins, err := canonicalMembershipBootstrap(input)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	identity, err := canonicalTSNodeNATSIdentity(input.NATSIdentity, input.Config.NodeID)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	if input.Engine != nil {
		observation := input.Engine.Observation()
		input.Config.engineObservation = nil
		if observation != (tbep.FileConfig{}) {
			input.Config.engineObservation = &observation
		}
	}
	config, err := canonicalTSNodeConfig(input.Config, input.ReleasePublicKey)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	manifest, desired, err := canonicalDesiredHostManifest(input.DesiredHostManifest)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	ca, err := canonicalArtifactCA(input.ArtifactCACertificate)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	hostAddress, err := canonicalArtifactHostAddress(input.ArtifactHostAddress)
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(input.ReleasePublicKey)
	if err != nil {
		return tsNodeBootstrapMaterial{}, fmt.Errorf("vmimage: encode ts-node release key: %w", err)
	}
	unit, err := tsnodebootstrap.RenderSystemdUnit(tsnodebootstrap.ProductionConfig())
	if err != nil {
		return tsNodeBootstrapMaterial{}, fmt.Errorf("vmimage: render ts-node unit: %w", err)
	}
	baseURL := "https://" + artifactReleaseHost + ":" + artifactReleasePort + "/releases/ts-node/" + input.Version + "/ts-node"
	launchManifest, err := hostmanifest.CanonicalHostManifestJSON(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{{
		Name: hostmanifest.TsNodeComponentName, Version: input.Version, ArtifactURL: baseURL,
		SignatureURL: baseURL + ".sig", Sha256: input.SHA256, User: "terrascale-ts-node",
		DataVolume: tsNodeStateDirectory, CPUWeight: 100, MemoryMaxBytes: 512 << 20, IOWeight: 100,
	}}})
	if err != nil {
		return tsNodeBootstrapMaterial{}, err
	}
	return tsNodeBootstrapMaterial{
		membershipPrivate: memberPrivate, membershipPins: memberPins, commandTrustFiles: commandFiles,
		identity: identity, version: input.Version, digest: input.SHA256, binary: append([]byte(nil), input.Binary...),
		signature:    append([]byte(nil), input.Signature...),
		publicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER}),
		config:       config, manifest: manifest, ca: ca, hostAddress: hostAddress, unit: unit,
		desired: desired, launchManifest: launchManifest,
	}, nil
}

func reservedReleaseVersion(version string) bool {
	switch version {
	case "bootstrap.sh", "current", "manifest.json", "previous", "terrascale-ts-node.service", "ts-node", "ts-node.pub", "ts-node.sha256", "ts-node.sig":
		return true
	default:
		return false
	}
}

func canonicalTSNodeConfig(config TSNodeConfig, publicKey ed25519.PublicKey) ([]byte, error) {
	if _, err := hostagent.NewNodeId(config.NodeID); err != nil {
		return nil, errors.New("vmimage: ts-node node id is invalid")
	}
	parsed, err := url.Parse(config.NATSURL)
	if err != nil || parsed.Scheme != "tls" || parsed.Opaque != "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("vmimage: ts-node NATS URL must be a canonical private IPv4 endpoint")
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	address, addressErr := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || addressErr != nil || portErr != nil || !address.Is4() || !address.IsPrivate() ||
		port != 4222 || strconv.Itoa(port) != portText || parsed.Host != address.String()+":"+portText ||
		config.NATSURL != "tls://"+parsed.Host {
		return nil, errors.New("vmimage: ts-node NATS URL must be a canonical private IPv4 endpoint")
	}
	for _, interval := range []time.Duration{config.HeartbeatInterval, config.ReconcileInterval} {
		if interval < 100*time.Millisecond || interval > 5*time.Minute || interval%time.Millisecond != 0 {
			return nil, errors.New("vmimage: ts-node intervals must be explicit whole milliseconds between 100ms and 5m")
		}
	}
	trustRefs, _, err := canonicalCommandTrust(config)
	if err != nil {
		return nil, err
	}
	if err := config.AuthorityReader.Validate(); err != nil {
		return nil, err
	}
	wire := tsNodeConfigurationFile{EngineObservation: config.engineObservation, AuthorityReader: config.AuthorityReader,
		BootstrapBeforeNATS: true,
		BootstrapGrantFile:  BootstrapGrantPath, BootstrapPublicKeyFile: BootstrapPublicKeyPath,
		AuthorityBucket: config.AuthorityBucket, CommandTrustKeys: trustRefs,
		NodeID: config.NodeID, NATSURL: config.NATSURL,
		NATSNKeyFile: tsNodeNKeyPath, NATSTLSCAFile: tsNodeTLSCAPath, NATSTLSCertFile: tsNodeTLSCertPath, NATSTLSKeyFile: tsNodeTLSKeyPath,
		ReleasePublicKey: hex.EncodeToString(publicKey), ManifestPath: desiredHostManifestPath,
		InstallRoot: "/opt/terrascale", UnitDir: "/etc/systemd/system", DataVolumeRoot: "/var/lib/terrascale",
		ChronycBinary: "/usr/bin/chronyc", SystemctlBinary: "/usr/bin/systemctl", UseraddBinary: "/usr/sbin/useradd",
		HeartbeatIntervalMilliseconds: config.HeartbeatInterval.Milliseconds(),
		ReconcileIntervalMilliseconds: config.ReconcileInterval.Milliseconds(),
	}
	return json.Marshal(wire)
}

func canonicalDesiredHostManifest(data []byte) ([]byte, hostmanifest.HostManifest, error) {
	if len(data) == 0 || len(data) > maxDesiredManifestBytes {
		return nil, hostmanifest.HostManifest{}, errors.New("vmimage: desired host manifest size is invalid")
	}
	manifest, err := hostmanifest.ParseHostManifest(data)
	if err != nil {
		return nil, hostmanifest.HostManifest{}, fmt.Errorf("vmimage: desired host manifest is invalid: %w", err)
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, hostmanifest.HostManifest{}, errors.New("vmimage: desired host manifest is not canonical JSON")
	}
	wantNames := []string{"orchestrator", "terrabase"}
	if len(manifest.Components) != len(wantNames) {
		return nil, hostmanifest.HostManifest{}, errors.New("vmimage: desired host manifest must contain exactly orchestrator and terrabase")
	}
	for index, component := range manifest.Components {
		if component.Name != wantNames[index] || reservedReleaseVersion(component.Version) ||
			component.User != "terrascale-"+component.Name ||
			component.DataVolume != "/var/lib/terrascale/"+component.Name ||
			component.CPUWeight != 100 || component.MemoryMaxBytes != 128<<20 || component.IOWeight != 100 || component.NeedsNetlink {
			return nil, hostmanifest.HostManifest{}, errors.New("vmimage: desired host manifest does not match the production component profile")
		}
		releaseVersion := component.Version
		if strings.HasPrefix(component.Version, "ctl-") {
			parts := strings.Split(component.ArtifactURL, "/")
			if len(parts) != 7 || !namePattern.MatchString(parts[5]) || reservedReleaseVersion(parts[5]) {
				return nil, hostmanifest.HostManifest{}, errors.New("vmimage: invalid configured artifact URL")
			}
			releaseVersion = parts[5]
			planned, err := bootstrap.PlanControlLaunchManifest(hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{component}})
			if err != nil || planned.Components[0].Version != component.Version {
				return nil, hostmanifest.HostManifest{}, errors.New("vmimage: invalid configured launch revision")
			}
		}
		artifactPath := "/releases/" + component.Name + "/" + releaseVersion + "/" + component.Name
		baseURL := "https://" + artifactReleaseHost + ":" + artifactReleasePort
		if component.ArtifactURL != baseURL+artifactPath || component.SignatureURL != baseURL+artifactPath+".sig" {
			return nil, hostmanifest.HostManifest{}, errors.New("vmimage: desired artifacts must use the canonical TerraScale release URLs")
		}
	}
	return canonical, manifest, nil
}

func canonicalArtifactCA(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) > maxArtifactCACertificate {
		return nil, errors.New("vmimage: artifact CA certificate is too large")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("vmimage: artifact CA must contain exactly one certificate and no private key")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("vmimage: artifact CA is not a valid certificate-signing CA")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), nil
}

func canonicalArtifactHostAddress(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", errors.New("vmimage: artifact host address must be canonical private IPv4")
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != value {
		return "", errors.New("vmimage: artifact host address must be canonical private IPv4")
	}
	return value, nil
}

func canonicalTSNodeNATSIdentity(input *TSNodeNATSIdentity, nodeID string) (*TSNodeNATSIdentity, error) {
	invalid := func() (*TSNodeNATSIdentity, error) {
		return nil, errors.New("vmimage: ts-node requires a bounded user NKey and matching trusted guest mTLS identity")
	}
	if input == nil {
		return invalid()
	}
	for _, part := range [][]byte{input.NKeySeed, input.TLSCA, input.TLSCertificate, input.TLSPrivateKey} {
		if len(part) == 0 || len(part) > 64<<10 {
			return invalid()
		}
	}
	if len(input.NKeySeed) > 4096 {
		return invalid()
	}
	user, err := nkeys.FromSeed(bytes.TrimSpace(input.NKeySeed))
	if err != nil {
		return invalid()
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return invalid()
	}
	pair, err := tls.X509KeyPair(input.TLSCertificate, input.TLSPrivateKey)
	if err != nil || len(pair.Certificate) == 0 {
		return invalid()
	}
	caBlock, rest := pem.Decode(input.TLSCA)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return invalid()
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return invalid()
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || len(leaf.URIs) != 1 {
		return invalid()
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return invalid()
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return invalid()
	}
	uri := leaf.URIs[0]
	parts := strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")
	if uri.Scheme != "spiffe" || uri.Host != "vmqual.terrascale.test" || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" || uri.RawPath != "" || len(parts) != 3 || !namePattern.MatchString(parts[0]) || parts[1] != "ts-node" || parts[2] != nodeID {
		return invalid()
	}
	return &TSNodeNATSIdentity{NKeySeed: append([]byte(nil), input.NKeySeed...), TLSCA: append([]byte(nil), input.TLSCA...), TLSCertificate: append([]byte(nil), input.TLSCertificate...), TLSPrivateKey: append([]byte(nil), input.TLSPrivateKey...)}, nil
}
