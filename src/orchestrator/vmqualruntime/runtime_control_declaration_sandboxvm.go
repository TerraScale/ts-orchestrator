//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const qualificationControlDomain = "TS-VM-CONTROL-DECLARATION-V1\x00"

var errQualificationControlDeclaration = errors.New("vmqual: signed control declaration differs from admitted run, artifacts or identities")

type qualificationControlFile struct {
	Source string `json:"source"`
	SHA256 string `json:"sha256"`
}

// The protected outer declaration pins the independently supplied owner key and
// signed payload bytes. Neither a key embedded in a bundle nor guest liveness
// establishes owner authorization.
type qualificationControlDeclaration struct {
	OwnerKey  qualificationControlFile `json:"ownerKey"`
	Payload   qualificationControlFile `json:"payload"`
	Signature []byte                   `json:"signature"`
}
type qualificationControlStoreDeclaration struct {
	Reader nodeauthority.ReaderConfig          `json:"reader"`
	Files  map[string]qualificationControlFile `json:"files"`
}
type qualificationControlMemberDeclaration struct {
	Member        bootstrap.ControlRuntimeMember `json:"member"`
	Generation    int64                          `json:"generation"`
	MembershipKey qualificationControlFile       `json:"membershipKey"`
}
type qualificationControlActionDeclaration struct {
	Plan         bootstrap.ControlRuntimeActionPlan `json:"plan"`
	RevokedStore string                             `json:"revokedStore,omitempty"`
}
type qualificationControlCandidateDeclaration struct {
	NodeID                   string                   `json:"nodeId"`
	Bundle                   qualificationControlFile `json:"bundle"`
	PrivateMaterialDirectory string                   `json:"privateMaterialDirectory"`
	PlanSHA256               string                   `json:"planSha256"`
}
type qualificationControlPayload struct {
	Version    int                                             `json:"version"`
	RunID      string                                          `json:"runId"`
	IssuedAt   time.Time                                       `json:"issuedAt"`
	ExpiresAt  time.Time                                       `json:"expiresAt"`
	Artifacts  []vmimage.GuestArtifact                         `json:"artifacts"`
	Stores     map[string]qualificationControlStoreDeclaration `json:"stores"`
	Members    []qualificationControlMemberDeclaration         `json:"members"`
	Regions    []bootstrap.ControlRegionBinding                `json:"regions"`
	Actions    []qualificationControlActionDeclaration         `json:"actions"`
	Candidates []qualificationControlCandidateDeclaration      `json:"candidates"`
}
type qualificationControlAdmission struct {
	source             *qualificationAdmittedControlSource
	candidates         map[string]vmcandidateseed.Material
	candidateManifests map[string][]byte
	memberships        map[string]*qualificationMembershipIdentity
	releases           []func()
}

func (a *qualificationControlAdmission) Clear() {
	if a == nil {
		return
	}
	for _, m := range a.candidates {
		m.Clear()
	}
	for _, m := range a.memberships {
		clear(m.PrivatePEM)
	}
	for _, release := range a.releases {
		release()
	}
	a.releases = nil
}
func readQualificationControlFile(ref qualificationControlFile, private bool, limit int64) ([]byte, error) {
	raw, err := bootstrapcredentials.ReadFile(ref.Source, private, limit)
	if err != nil {
		return nil, errQualificationControlDeclaration
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != ref.SHA256 {
		clear(raw)
		return nil, errQualificationControlDeclaration
	}
	return raw, nil
}
func loadQualificationControlDeclaration(path string, plan vmnet.NetworkPlan, architecture vmimage.Architecture, artifacts map[string]vmimage.GuestArtifact) (_ *qualificationControlAdmission, err error) {
	raw, err := bootstrapcredentials.ReadFile(path, true, 64<<10)
	if err != nil {
		return nil, errQualificationControlDeclaration
	}
	defer clear(raw)
	var declaration qualificationControlDeclaration
	if json.Unmarshal(raw, &declaration, json.RejectUnknownMembers(true)) != nil {
		return nil, errQualificationControlDeclaration
	}
	public, err := readQualificationControlFile(declaration.OwnerKey, false, 64<<10)
	if err != nil {
		return nil, err
	}
	payload, err := readQualificationControlFile(declaration.Payload, false, 4<<20)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 || len(block.Headers) != 0 {
		return nil, errQualificationControlDeclaration
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errQualificationControlDeclaration
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	digest := sha256.Sum256(append([]byte(qualificationControlDomain), payload...))
	if !ok || key.Curve != elliptic.P256() || !ecdsa.VerifyASN1(key, digest[:], declaration.Signature) {
		return nil, errQualificationControlDeclaration
	}
	var admitted qualificationControlPayload
	if json.Unmarshal(payload, &admitted, json.RejectUnknownMembers(true)) != nil {
		return nil, errQualificationControlDeclaration
	}
	now := time.Now().UTC()
	if plan.Validate() != nil || admitted.Version != 1 || admitted.RunID != plan.RunID || admitted.IssuedAt.IsZero() || now.Before(admitted.IssuedAt) || !now.Before(admitted.ExpiresAt) || admitted.ExpiresAt.Sub(admitted.IssuedAt) > 24*time.Hour || len(admitted.Artifacts) != 3 || len(artifacts) != 3 || len(admitted.Stores) == 0 || len(admitted.Stores) > 32 || len(admitted.Actions) == 0 || len(admitted.Actions) > 128 {
		return nil, errQualificationControlDeclaration
	}
	seenArtifacts := map[string]bool{}
	for _, artifact := range admitted.Artifacts {
		expected, ok := artifacts[artifact.Component]
		if !ok || artifact != expected || artifact.Architecture != architecture || seenArtifacts[artifact.Component] {
			return nil, errQualificationControlDeclaration
		}
		seenArtifacts[artifact.Component] = true
	}
	result := &qualificationControlAdmission{source: &qualificationAdmittedControlSource{config: bootstrap.NATSControlRuntimeConfig{Stores: map[string]bootstrap.ControlNATSStore{}}, admissions: map[string]qualificationControlHostAdmission{}, expectedStoreServers: map[string]string{}, admittedIssuedAt: admitted.IssuedAt, admittedExpiresAt: admitted.ExpiresAt}, candidates: map[string]vmcandidateseed.Material{}, candidateManifests: map[string][]byte{}, memberships: map[string]*qualificationMembershipIdentity{}}
	defer func() {
		if err != nil {
			result.Clear()
		}
	}()
	guests := map[string]string{}
	addresses := map[string]bool{}
	for _, region := range plan.Regions {
		if string(region.Code) == "IAD" {
			continue
		}
		for _, guest := range region.Guests {
			guests[guest.ID] = strings.ToLower(string(region.Code))
			addresses[guest.Address] = true
		}
	}
	if len(admitted.Members) != len(guests) || len(admitted.Regions) != 3 {
		return nil, errQualificationControlDeclaration
	}
	for name, store := range admitted.Stores {
		endpoint, parseErr := url.Parse(store.Reader.Endpoint)
		if name == "" || parseErr != nil || !addresses[endpoint.Hostname()] {
			return nil, errQualificationControlDeclaration
		}
		configured, release, loadErr := loadQualificationControlStore(store)
		if loadErr != nil {
			return nil, loadErr
		}
		result.releases = append(result.releases, release)
		result.source.config.Stores[name] = configured
		result.source.expectedStoreServers[name] = store.Reader.ServerName
	}
	members := map[string]string{}
	membersByHost := map[string]bootstrap.ControlRuntimeMember{}
	arch := runtimeplan.HostArchitectureX64
	if architecture == vmimage.ARM64 {
		arch = runtimeplan.HostArchitectureArm64
	} else if architecture != vmimage.AMD64 {
		return nil, errQualificationControlDeclaration
	}
	for _, entry := range admitted.Members {
		member := entry.Member
		if guests[member.HostID] != member.Region || member.Region == "" || entry.Generation <= 0 || result.memberships[member.HostID] != nil || members[member.MemberID] != "" || !strings.HasPrefix(member.MemberID, "ocid1.instance.") || member.Instance != member.HostID || member.ServerName == "" {
			return nil, errQualificationControlDeclaration
		}
		if _, ok := result.source.config.Stores[member.Store]; !ok {
			return nil, errQualificationControlDeclaration
		}
		private, loadErr := readQualificationControlFile(entry.MembershipKey, true, 64<<10)
		if loadErr != nil {
			return nil, loadErr
		}
		id, pin, loadErr := directory.RegionalRuntimeMembershipPublicKeyFromPEM(private)
		if loadErr != nil || pin != member.IdentityPublicKey {
			clear(private)
			return nil, errQualificationControlDeclaration
		}
		result.memberships[member.HostID] = &qualificationMembershipIdentity{PrivatePEM: private, KeyID: id, PublicKey: pin}
		result.source.admissions[member.HostID] = qualificationControlHostAdmission{Architecture: arch, Generation: entry.Generation}
		result.source.config.Members = append(result.source.config.Members, member)
		members[member.MemberID] = member.Region
		membersByHost[member.HostID] = member
	}
	bound := map[string]bool{}
	regions := map[string]bool{}
	for _, region := range admitted.Regions {
		if region.Code != "gru" && region.Code != "sfo" && region.Code != "fra" || regions[region.Code] || region.OCIRegion == "" || !strings.HasPrefix(region.CompartmentID, "ocid1.compartment.") || len(region.MemberIDs) != 2 {
			return nil, errQualificationControlDeclaration
		}
		regions[region.Code] = true
		for _, id := range region.MemberIDs {
			if members[id] != region.Code || bound[id] {
				return nil, errQualificationControlDeclaration
			}
			bound[id] = true
		}
	}
	if len(bound) != len(members) {
		return nil, errQualificationControlDeclaration
	}
	result.source.regions = admitted.Regions
	for _, action := range admitted.Actions {
		if !regions[action.Plan.Region] || action.Plan.RevokedCredential != nil {
			return nil, errQualificationControlDeclaration
		}
		for _, check := range action.Plan.Checks {
			if check.AuthorityTerm != 0 || check.AuthorityCandidateID != "" || check.AuthorityLeaseID != "" {
				return nil, errQualificationControlDeclaration
			}
		}
		for _, handoff := range action.Plan.Handoffs {
			if members[handoff.MemberID] == "" || validateQualificationManifestArtifacts(handoff.Manifest, artifacts) != nil {
				return nil, errQualificationControlDeclaration
			}
		}
		if action.RevokedStore != "" {
			store, ok := result.source.config.Stores[action.RevokedStore]
			if !ok {
				return nil, errQualificationControlDeclaration
			}
			action.Plan.RevokedCredential = new(store)
		}
		result.source.config.Actions = append(result.source.config.Actions, action.Plan)
	}
	if len(admitted.Candidates) != 2 {
		return nil, errQualificationControlDeclaration
	}
	candidateRegions := map[string]bool{}
	var preparation []byte
	candidatePlan := ""
	for _, candidate := range admitted.Candidates {
		region := guests[candidate.NodeID]
		if region != "sfo" && region != "fra" || candidateRegions[region] {
			return nil, errQualificationControlDeclaration
		}
		bundle, loadErr := readQualificationControlFile(candidate.Bundle, false, 2<<20)
		if loadErr != nil {
			return nil, loadErr
		}
		material, loadErr := vmcandidateseed.Load(candidate.PrivateMaterialDirectory, candidate.NodeID, bundle)
		if loadErr != nil {
			return nil, loadErr
		}
		result.candidates[candidate.NodeID] = material
		if material.PlanSHA256 != candidate.PlanSHA256 || material.Config.ServerName != membersByHost[candidate.NodeID].ServerName || !bytes.Equal(material.PublicKeyPEM, public) {
			return nil, errQualificationControlDeclaration
		}
		if preparation == nil {
			preparation = material.PreparationGrant
			candidatePlan = material.PlanSHA256
		} else if !bytes.Equal(preparation, material.PreparationGrant) || candidatePlan != material.PlanSHA256 {
			return nil, errQualificationControlDeclaration
		}
		var document struct {
			Candidates []struct {
				NodeID   string         `json:"nodeId"`
				Manifest jsontext.Value `json:"manifest"`
			} `json:"candidates"`
		}
		if json.Unmarshal(bundle, &document) != nil {
			return nil, errQualificationControlDeclaration
		}
		for _, entry := range document.Candidates {
			if entry.NodeID == candidate.NodeID {
				manifest, parseErr := hostmanifest.ParseHostManifest(entry.Manifest)
				if parseErr != nil || validateQualificationManifestArtifacts(manifest, artifacts) != nil {
					return nil, errQualificationControlDeclaration
				}
				result.candidateManifests[candidate.NodeID] = bytes.Clone(entry.Manifest)
			}
		}
		candidateRegions[region] = true
	}
	return result, nil
}
func validateQualificationManifestArtifacts(manifest hostmanifest.HostManifest, artifacts map[string]vmimage.GuestArtifact) error {
	if len(manifest.Components) != 2 {
		return errQualificationControlDeclaration
	}
	planned, err := bootstrap.PlanControlLaunchManifest(manifest)
	if err != nil {
		return errQualificationControlDeclaration
	}
	for i, component := range manifest.Components {
		artifact, ok := artifacts[component.Name]
		if !ok || component.Name == "ts-node" || component.Version != planned.Components[i].Version || component.Sha256 != artifact.SHA256 || component.ArtifactURL != artifact.Source || component.SignatureURL != artifact.Source+".sig" {
			return errQualificationControlDeclaration
		}
	}
	return nil
}
func loadQualificationControlStore(declaration qualificationControlStoreDeclaration) (bootstrap.ControlNATSStore, func(), error) {
	bad := func() (bootstrap.ControlNATSStore, func(), error) {
		return bootstrap.ControlNATSStore{}, nil, errQualificationControlDeclaration
	}
	reader := declaration.Reader
	if reader.Validate() != nil || len(declaration.Files) != 4 {
		return bad()
	}
	files := map[string][]byte{}
	defer func() {
		for _, raw := range files {
			clear(raw)
		}
	}()
	for _, path := range []string{reader.NKeySeedFile, reader.CAFile, reader.CertificateFile, reader.KeyFile} {
		ref, ok := declaration.Files[path]
		if !ok {
			return bad()
		}
		raw, err := readQualificationControlFile(ref, path == reader.NKeySeedFile || path == reader.KeyFile, 64<<10)
		if err != nil {
			return bad()
		}
		files[path] = raw
	}
	digest := func(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
	if digest(files[reader.CAFile]) != reader.CASHA256 || digest(files[reader.CertificateFile]) != reader.CertificateSHA256 {
		return bad()
	}
	pair, err := nkeys.FromSeed(files[reader.NKeySeedFile])
	if err != nil {
		return bad()
	}
	public, err := pair.PublicKey()
	if err != nil || public != reader.PublicNKey {
		pair.Wipe()
		return bad()
	}
	roots := x509.NewCertPool()
	cert, err := tls.X509KeyPair(files[reader.CertificateFile], files[reader.KeyFile])
	if err != nil || !roots.AppendCertsFromPEM(files[reader.CAFile]) {
		pair.Wipe()
		return bad()
	}
	endpoint, _ := url.Parse(reader.Endpoint)
	options := []nats.Option{nats.Nkey(public, pair.Sign), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: endpoint.Hostname()})}
	return bootstrap.ControlNATSStore{URL: reader.Endpoint, Options: options}, pair.Wipe, nil
}
