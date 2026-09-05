package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/nats-io/nats.go"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const bootstrapControlConfigEnvironment = "TS_ORCH_CONTROL_CONFIG_FILE"

type bootstrapControlCredentials struct {
	URL             string `json:"url"`
	CAFile          string `json:"caFile"`
	CertificateFile string `json:"certificateFile"`
	PrivateKeyFile  string `json:"privateKeyFile"`
	NKeySeedFile    string `json:"nkeySeedFile"`
}
type bootstrapControlRegion struct {
	Code                  string `json:"code"`
	OCIRegion             string `json:"ociRegion"`
	MemberCount           int    `json:"memberCount"`
	HostStore             string `json:"hostStore"`
	AuthorityStore        string `json:"authorityStore"`
	CommandCandidateID    string `json:"commandCandidateId"`
	CommandSigningKeyFile string `json:"commandSigningKeyFile"`
}
type bootstrapControlMember struct {
	HostID              string                       `json:"hostId"`
	Region              string                       `json:"region"`
	Index               int                          `json:"index"`
	Architecture        runtimeplan.HostArchitecture `json:"architecture"`
	Instance            string                       `json:"instance"`
	ServerName          string                       `json:"serverName"`
	MembershipPublicKey string                       `json:"membershipPublicKey"`
	Store               string                       `json:"store"`
}

// UnmarshalJSON requires an explicit architecture because arm64 is enum zero.
func (member *bootstrapControlMember) UnmarshalJSON(data []byte) error {
	type plain bootstrapControlMember
	var decoded plain
	wire := struct {
		*plain
		Architecture *runtimeplan.HostArchitecture `json:"architecture"`
	}{plain: &decoded}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if wire.Architecture == nil || (*wire.Architecture != runtimeplan.HostArchitectureArm64 && *wire.Architecture != runtimeplan.HostArchitectureX64) {
		return errors.New("control: explicit architecture must be 0 (arm64) or 1 (amd64)")
	}
	decoded.Architecture = *wire.Architecture
	*member = bootstrapControlMember(decoded)
	return nil
}

type bootstrapControlAction struct {
	bootstrap.ControlRuntimeActionPlan
	RevokedStore string `json:"revokedStore,omitempty"`
}
type bootstrapControlConfig struct {
	Version         int                                    `json:"version"`
	Generation      int64                                  `json:"generation"`
	CompartmentName string                                 `json:"compartmentName"`
	ReceiptFile     string                                 `json:"receiptFile"`
	Stores          map[string]bootstrapControlCredentials `json:"stores"`
	Regions         []bootstrapControlRegion               `json:"regions"`
	Members         []bootstrapControlMember               `json:"members"`
	Seeds           []bootstrapControlHostSeed             `json:"seeds"`
	Activations     []bootstrapControlActivation           `json:"activations"`
	Actions         []bootstrapControlAction               `json:"actions"`
}
type loadedBootstrapControl struct {
	declaration bootstrapControlConfig
	stores      map[string]bootstrap.ControlNATSStore
	signers     map[string]*security.CommandSignatureSigner
	members     []bootstrap.ControlRuntimeMember
	actions     []bootstrap.ControlRuntimeActionPlan
	activations map[string]loadedControlActivation
	seeds       map[string]map[int]string
}

func readBootstrapControlFile(path string, private bool, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("control: credential/config path must be absolute and clean")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("control: required credential/config file unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || (private && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("control: file must be bounded, regular and owner-private")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("control: file must belong to current owner")
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}
func loadBootstrapControlCredentials(ref bootstrapControlCredentials) (bootstrap.ControlNATSStore, error) {
	parsed, err := url.Parse(ref.URL)
	if err != nil || parsed.Scheme != "tls" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return bootstrap.ControlNATSStore{}, errors.New("control: canonical TLS NATS authority required")
	}
	ca, err := readBootstrapControlFile(ref.CAFile, false, 1<<20)
	if err != nil {
		return bootstrap.ControlNATSStore{}, err
	}
	cert, err := readBootstrapControlFile(ref.CertificateFile, false, 1<<20)
	if err != nil {
		return bootstrap.ControlNATSStore{}, err
	}
	key, err := readBootstrapControlFile(ref.PrivateKeyFile, true, 64<<10)
	if err != nil {
		return bootstrap.ControlNATSStore{}, err
	}
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return bootstrap.ControlNATSStore{}, errors.New("control: invalid TLS client identity")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return bootstrap.ControlNATSStore{}, errors.New("control: invalid NATS CA")
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil {
		return bootstrap.ControlNATSStore{}, errors.New("control: invalid client certificate")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range identity.Certificate[1:] {
		certificate, err := x509.ParseCertificate(raw)
		if err != nil {
			return bootstrap.ControlNATSStore{}, err
		}
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return bootstrap.ControlNATSStore{}, errors.New("control: client identity is not valid under declared CA")
	}
	seed, err := readBootstrapControlFile(ref.NKeySeedFile, true, 4096)
	if err != nil {
		return bootstrap.ControlNATSStore{}, err
	}
	pair, err := nkeys.FromSeed(bytes.TrimSpace(seed))
	if err != nil {
		return bootstrap.ControlNATSStore{}, errors.New("control: invalid NKey seed")
	}
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return bootstrap.ControlNATSStore{}, errors.New("control: NKey must be user identity")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: parsed.Hostname(), RootCAs: roots, Certificates: []tls.Certificate{identity}}
	return bootstrap.ControlNATSStore{URL: ref.URL, Options: []nats.Option{nats.Secure(config), nats.Nkey(public, pair.Sign), nats.NoReconnect()}}, nil
}

func loadBootstrapControl(lookup envLookup) (loadedBootstrapControl, error) {
	var result loadedBootstrapControl
	if lookup == nil {
		return result, errors.New("control: environment lookup required")
	}
	path, ok := lookup(bootstrapControlConfigEnvironment)
	if !ok || path == "" {
		return result, errors.New("control: set " + bootstrapControlConfigEnvironment)
	}
	raw, err := readBootstrapControlFile(path, true, 4<<20)
	if err != nil {
		return result, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result.declaration) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return result, errors.New("control: malformed runtime configuration")
	}
	config := result.declaration
	if config.Version != 1 || config.Generation <= 0 || config.CompartmentName != "terrascale" || !filepath.IsAbs(config.ReceiptFile) || filepath.Clean(config.ReceiptFile) != config.ReceiptFile || len(config.Regions) == 0 {
		return result, errors.New("control: invalid runtime declaration scope")
	}
	result.stores = map[string]bootstrap.ControlNATSStore{}
	result.signers = map[string]*security.CommandSignatureSigner{}
	var stores []string
	for name, ref := range config.Stores {
		store, err := loadBootstrapControlCredentials(ref)
		if err != nil {
			return result, err
		}
		result.stores[name] = store
		stores = append(stores, name)
	}
	estateSpec, err := loadReconcileEstate(lookup)
	if err != nil {
		return result, err
	}
	regions := map[string]bootstrapControlRegion{}
	for _, region := range config.Regions {
		declared := false
		for _, entry := range estateSpec.Regions {
			if entry.Code == region.Code && entry.OCIName == region.OCIRegion && int(entry.Members.Count) == region.MemberCount {
				declared = true
			}
		}
		if !declared {
			return result, errors.New("control: regional bindings differ from declared estate")
		}
		if !validAddRegionCode(region.Code) || region.MemberCount < 1 || region.MemberCount > 1024 || region.OCIRegion == "" || region.CommandCandidateID == "" || regions[region.Code].Code != "" {
			return result, errors.New("control: invalid regional declaration")
		}
		if _, ok := result.stores[region.HostStore]; !ok {
			return result, errors.New("control: missing host NATS store")
		}
		if _, ok := result.stores[region.AuthorityStore]; !ok {
			return result, errors.New("control: missing regional authority store")
		}
		if _, err := readBootstrapControlFile(region.CommandSigningKeyFile, true, 64<<10); err != nil {
			return result, err
		}
		signer, err := security.LoadCommandSignatureSignerPEM(region.CommandSigningKeyFile)
		if err != nil {
			return result, err
		}
		result.signers[region.Code] = signer
		regions[region.Code] = region
	}
	slots := map[string]bool{}
	for _, member := range config.Members {
		region, ok := regions[member.Region]
		if !ok || member.Index < 1 || member.Index > region.MemberCount || !strings.HasPrefix(member.HostID, member.Region+"-") || (member.Architecture != runtimeplan.HostArchitectureArm64 && member.Architecture != runtimeplan.HostArchitectureX64) {
			return result, errors.New("control: invalid logical member declaration")
		}
		node, err := hostagent.NewNodeId(member.HostID)
		if err != nil {
			return result, err
		}
		_ = node
		slot := member.Region + "/" + strconv.Itoa(member.Index)
		if slots[slot] {
			return result, errors.New("control: duplicate member slot")
		}
		slots[slot] = true
		result.members = append(result.members, bootstrap.ControlRuntimeMember{MemberID: member.HostID, HostID: member.HostID, Region: member.Region, Instance: member.Instance, ServerName: member.ServerName, IdentityPublicKey: member.MembershipPublicKey, Store: member.Store})
	}
	for _, region := range config.Regions {
		admitted := false
		for _, member := range config.Members {
			if member.Region == region.Code && region.CommandCandidateID == member.Region+"-controller-"+member.Instance {
				admitted = true
			}
		}
		if !admitted {
			return result, errors.New("control: command authority candidate is not an admitted regional member")
		}
	}
	for _, source := range config.Actions {
		plan := source.ControlRuntimeActionPlan
		if plan.RevokedCredential != nil {
			return result, errors.New("control: use credential file references")
		}
		if source.RevokedStore != "" {
			store, ok := result.stores[source.RevokedStore]
			if !ok {
				return result, errors.New("control: missing revocation credential")
			}
			plan.RevokedCredential = &store
		}
		result.actions = append(result.actions, plan)
	}
	result.activations = map[string]loadedControlActivation{}
	for _, input := range config.Activations {
		if _, exists := result.activations[input.HostID]; exists {
			return result, errors.New("control: duplicate activation grant")
		}
		activation, err := loadControlActivation(input)
		if err != nil {
			return result, err
		}
		allowed, err := hostmanifest.HostManifestSha256(activation.grant.Manifest)
		if err != nil {
			return result, err
		}
		matched := false
		for _, plan := range result.actions {
			for _, handoff := range plan.Handoffs {
				desired, err := hostmanifest.HostManifestSha256(handoff.Manifest)
				if err != nil {
					return result, err
				}
				if handoff.MemberID == input.HostID && desired == allowed {
					matched = true
				}
			}
		}
		for _, seed := range config.Seeds {
			if seed.HostID == input.HostID {
				matched = true
			}
		}
		if !matched {
			return result, errors.New("control: activation grant does not match an admitted host handoff or seed")
		}
		result.activations[input.HostID] = activation
	}
	if err := bootstrap.ValidateControlRuntimeDeclarations(stores, result.members, result.actions); err != nil {
		return result, err
	}
	if err := prepareBootstrapControlSeeds(lookup, &result); err != nil {
		return result, err
	}
	return result, nil
}
