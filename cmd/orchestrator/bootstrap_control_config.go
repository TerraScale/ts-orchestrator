package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const bootstrapControlConfigEnvironment = "TS_ORCH_CONTROL_CONFIG_FILE"

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
	Version         int                                       `json:"version"`
	Generation      int64                                     `json:"generation"`
	CompartmentName string                                    `json:"compartmentName"`
	ReceiptFile     string                                    `json:"receiptFile"`
	Stores          map[string]bootstrapcredentials.Reference `json:"stores"`
	Regions         []bootstrapControlRegion                  `json:"regions"`
	Members         []bootstrapControlMember                  `json:"members"`
	Seeds           []bootstrapControlHostSeed                `json:"seeds"`
	Activations     []bootstrapControlActivation              `json:"activations"`
	Actions         []bootstrapControlAction                  `json:"actions"`
}
type loadedBootstrapControl struct {
	credentialOwners []*bootstrapcredentials.Credentials
	storeIdentities  map[string]bootstrapcredentials.Identity
	declaration      bootstrapControlConfig
	stores           map[string]bootstrap.ControlNATSStore
	signers          map[string]*security.CommandSignatureSigner
	members          []bootstrap.ControlRuntimeMember
	actions          []bootstrap.ControlRuntimeActionPlan
	activations      map[string]loadedControlActivation
	seeds            map[string]map[int]string
	workerCounts     map[string]int
	workerSeeds      map[string]map[int]string
}

func loadBootstrapControl(lookup envLookup) (result loadedBootstrapControl, resultErr error) {
	defer func() {
		if resultErr != nil {
			result.closeCredentials()
		}
	}()
	if lookup == nil {
		return result, errors.New("control: environment lookup required")
	}
	path, ok := lookup(bootstrapControlConfigEnvironment)
	if !ok || path == "" {
		return result, errors.New("control: set " + bootstrapControlConfigEnvironment)
	}
	raw, err := bootstrapcredentials.ReadFile(path, true, 4<<20)
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
	result.storeIdentities = map[string]bootstrapcredentials.Identity{}
	result.signers = map[string]*security.CommandSignatureSigner{}
	var stores []string
	for name, ref := range config.Stores {
		credentials, err := bootstrapcredentials.Load(ref)
		if err != nil {
			return result, err
		}
		result.credentialOwners = append(result.credentialOwners, credentials)
		result.storeIdentities[name] = credentials.PublicIdentity()
		result.stores[name] = bootstrap.ControlNATSStore{URL: credentials.URL, Options: credentials.Options}
		stores = append(stores, name)
	}
	estateSpec, err := loadReconcileEstate(lookup)
	if err != nil {
		return result, err
	}
	result.workerCounts = make(map[string]int, len(estateSpec.Regions))
	for _, entry := range estateSpec.Regions {
		result.workerCounts[entry.Code] = int(entry.Workers.Count)
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
		signingBytes, err := bootstrapcredentials.ReadFile(region.CommandSigningKeyFile, true, 64<<10)
		if err != nil {
			return result, err
		}
		signer, err := security.ParseCommandSignatureSignerPEM(signingBytes)
		clear(signingBytes)
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
		result.activations[input.HostID] = activation
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

func (c *loadedBootstrapControl) closeCredentials() {
	if c == nil {
		return
	}
	for _, owner := range c.credentialOwners {
		_ = owner.Close()
	}
	for _, signer := range c.signers {
		_ = signer.Close()
	}
	for _, activation := range c.activations {
		if activation.signer != nil {
			_ = activation.signer.Close()
		}
	}
}
