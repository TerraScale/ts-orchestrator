package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

type bootstrapControlReceipt struct {
	Generation        int64                            `json:"generation"`
	DeclarationSHA256 string                           `json:"declarationSha256"`
	Regions           []bootstrap.ControlRegionBinding `json:"regions"`
}
type bootstrapControlProvider struct {
	*bootstrap.ProviderControlPlane
	connections []*nats.Conn
}

func (p *bootstrapControlProvider) Close() {
	for _, connection := range p.connections {
		connection.Close()
	}
}
func closeBootstrapControlMachine(machine *bootstrap.ControlStateMachine) {
	if machine != nil {
		if closer, ok := machine.Provider.(interface{ Close() }); ok {
			closer.Close()
		}
	}
}

type bootstrapControlAdmission struct {
	provision   provider.BootstrapRequest
	loaded      loadedBootstrapControl
	credentials provider.BootstrapCredentials
	cloudflare  *cloudflare.Client
	regions     []bootstrapControlRegion
}
type bootstrapControlFactory struct {
	Validate  func(context.Context, envLookup, string) (*bootstrapControlAdmission, error)
	Construct func(context.Context, *bootstrapControlAdmission, string) (*bootstrap.ControlStateMachine, error)
}

func newBootstrapControlFactory() *bootstrapControlFactory {
	return &bootstrapControlFactory{Validate: validateBootstrapControlConfiguration, Construct: newBootstrapControlMachine}
}

// Validation retains the admitted declaration and credentials through OCI
// provisioning, so construction cannot silently reload a different seed.
func validateBootstrapControlConfiguration(ctx context.Context, lookup envLookup, region string) (*bootstrapControlAdmission, error) {
	if ctx == nil {
		return nil, errors.New("control: caller context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	loaded, err := loadBootstrapControl(lookup)
	if err != nil {
		return nil, err
	}
	credentials, cf, err := bootstrapControlProviderCredentials(lookup, loaded.declaration.Regions)
	if err != nil {
		return nil, err
	}
	seeds, ok := loaded.seeds[region]
	if !ok {
		return nil, errors.New("control: provisioned region is outside admitted seed")
	}
	regions, err := selectBootstrapControlStage(&loaded, region)
	if err != nil {
		return nil, err
	}
	return &bootstrapControlAdmission{provision: provider.BootstrapRequest{HostCloudInit: seeds}, loaded: loaded, credentials: credentials, cloudflare: cf, regions: regions}, nil
}
func bootstrapControlProviderCredentials(lookup envLookup, regions []bootstrapControlRegion) (provider.BootstrapCredentials, *cloudflare.Client, error) {
	credentials, err := provider.BootstrapCredentialsFromEnv(lookup)
	if err != nil {
		return credentials, nil, err
	}
	for _, region := range regions {
		if _, err := provider.BootstrapControlTransport(credentials, region.OCIRegion, provider.OCIServiceCore); err != nil {
			return credentials, nil, err
		}
	}
	token, err := addRegionRequiredEnv(lookup, addRegionCFTokenEnvironment)
	if err != nil {
		return credentials, nil, err
	}
	zone, err := addRegionRequiredEnv(lookup, addRegionCFZoneEnvironment)
	if err != nil {
		return credentials, nil, err
	}
	account, err := addRegionRequiredEnv(lookup, addRegionCFAccountEnvironment)
	if err != nil {
		return credentials, nil, err
	}
	return credentials, cloudflare.NewClient(token, zone, account), nil
}
func newBootstrapControlMachine(ctx context.Context, admission *bootstrapControlAdmission, journalPath string) (*bootstrap.ControlStateMachine, error) {
	if ctx == nil || admission == nil {
		return nil, errors.New("control: validated admission and caller context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	loaded, credentials, cf := admission.loaded, admission.credentials, admission.cloudflare
	journal, err := bootstrap.NewFileControlJournal(journalPath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	transports := map[string]*provider.OCIHTTPTransport{}
	actual := map[string]string{}
	architectures := map[string]string{}
	var bindings []bootstrap.ControlRegionBinding
	for _, region := range admission.regions {
		core, err := provider.BootstrapControlTransport(credentials, region.OCIRegion, provider.OCIServiceCore)
		if err != nil {
			return nil, err
		}
		identity, err := provider.BootstrapControlTransport(credentials, region.OCIRegion, provider.OCIServiceIdentity)
		if err != nil {
			return nil, err
		}
		compartment, members, err := provider.ReadBootstrapControlMembers(ctx, core, identity, credentials.TenancyOCID, loaded.declaration.CompartmentName, region.Code, region.MemberCount)
		if err != nil {
			return nil, err
		}
		binding := bootstrap.ControlRegionBinding{Code: region.Code, OCIRegion: region.OCIRegion, CompartmentID: compartment}
		for _, member := range members {
			binding.MemberIDs = append(binding.MemberIDs, member.ID)
			actual[region.Code+"/"+strconv.Itoa(member.Index)] = member.ID
			arch, ok := provider.ShapeArch(member.Shape)
			if !ok {
				return nil, errors.New("control: observed member architecture is unknown")
			}
			architectures[member.ID] = arch
		}
		transports[region.Code] = core
		bindings = append(bindings, binding)
	}
	intentDigest, err := bootstrapControlIntentDigest(loaded)
	if err != nil {
		return nil, err
	}
	replacements := map[string]string{}
	for _, member := range loaded.declaration.Members {
		id := actual[member.Region+"/"+strconv.Itoa(member.Index)]
		if id == "" {
			continue
		}
		wanted := provider.MemberArchAMD64
		if member.Architecture == runtimeplan.HostArchitectureArm64 {
			wanted = provider.MemberArchArm64
		}
		if architectures[id] != wanted {
			return nil, errors.New("control: admitted host architecture differs from OCI receipt")
		}
		replacements[member.HostID] = id
	}
	if err := persistBootstrapControlReceipt(loaded.declaration.ReceiptFile, bootstrapControlReceipt{Generation: loaded.declaration.Generation, DeclarationSHA256: intentDigest, Regions: bindings}); err != nil {
		return nil, err
	}
	loaded.members = append([]bootstrap.ControlRuntimeMember(nil), loaded.members...)
	for i := range loaded.members {
		loaded.members[i].MemberID = replacements[loaded.members[i].HostID]
	}
	loaded.actions = append([]bootstrap.ControlRuntimeActionPlan(nil), loaded.actions...)
	for i := range loaded.actions {
		plan := &loaded.actions[i]
		plan.Handoffs = append([]bootstrap.ControlHostHandoff(nil), plan.Handoffs...)
		plan.Checks = append([]bootstrap.ControlStoreCheck(nil), plan.Checks...)
		for j := range plan.Handoffs {
			plan.Handoffs[j].MemberID = replacements[plan.Handoffs[j].MemberID]
		}
		for j := range plan.Checks {
			plan.Checks[j].Members = append([]string(nil), plan.Checks[j].Members...)
			for k, id := range plan.Checks[j].Members {
				plan.Checks[j].Members[k] = replacements[id]
			}
		}
	}
	connections := map[string]*nats.Conn{}
	owner := &bootstrapControlProvider{}
	fail := true
	defer func() {
		if fail {
			owner.Close()
		}
	}()
	connect := newBootstrapStoreConnector(loaded.stores, connections, owner)
	hosts := map[string]*hostcontrol.Client{}
	for _, declared := range admission.regions {
		region := declared
		connection, err := connect(ctx, region.HostStore)
		if err != nil {
			return nil, err
		}
		resolveAuthority := func(ctx context.Context, _ hostcontrol.Host) (delivery.RegionalCommandAuthority, error) {
			authorityConnection, err := connect(ctx, region.AuthorityStore)
			if err != nil {
				return delivery.RegionalCommandAuthority{}, err
			}
			return readBootstrapCommandAuthority(ctx, authorityConnection, region, loaded.declaration.Generation)
		}
		client, err := hostcontrol.New(hostcontrol.Config{Region: strings.ToUpper(region.Code), Connection: connection, SigningKey: loaded.signers[region.Code], Timeout: 30 * time.Second,
			ResolveHost: func(ctx context.Context, id string) (hostcontrol.Host, error) {
				if err := ctx.Err(); err != nil {
					return hostcontrol.Host{}, err
				}
				for _, member := range loaded.declaration.Members {
					if member.Region == region.Code && member.HostID == id {
						node, err := hostagent.NewNodeId(id)
						return hostcontrol.Host{NodeID: node, Region: strings.ToUpper(region.Code), Architecture: member.Architecture}, err
					}
				}
				return hostcontrol.Host{}, errors.New("control: host is outside admitted declaration")
			}, CommandAuthority: resolveAuthority, Authorize: func(ctx context.Context, host hostcontrol.Host) error {
				_, err := resolveAuthority(ctx, host)
				return err
			}})
		if err != nil {
			return nil, err
		}
		hosts[region.Code] = client
	}
	runtime, err := bootstrap.NewNATSControlRuntime(bootstrap.NATSControlRuntimeConfig{Hosts: hosts, Stores: loaded.stores, Members: loaded.members, Actions: loaded.actions})
	if err != nil {
		return nil, err
	}
	activationRuntime := &bootstrapActivationRuntime{NATSControlRuntime: runtime, plans: loaded.actions, grants: loaded.activations, clients: hosts, connections: connections, memberHosts: map[string]string{}, hostRegions: map[string]string{}, hostStores: map[string]string{}}
	for _, member := range loaded.members {
		activationRuntime.memberHosts[member.MemberID] = member.HostID
		activationRuntime.hostRegions[member.HostID] = member.Region
	}
	for _, region := range admission.regions {
		activationRuntime.hostStores[region.Code] = region.HostStore
	}
	controlProvider, err := bootstrap.NewProductionControlPlaneProvider(bootstrap.ProductionControlPlaneProviderConfig{Runtime: activationRuntime, Regions: bindings, OCI: transports, Cloudflare: cf})
	if err != nil {
		return nil, err
	}
	owner.ProviderControlPlane = controlProvider
	machine, err := bootstrap.NewControlStateMachine(owner, journal, bootstrap.RetryPolicy{MaxAttempts: 3})
	if err != nil {
		return nil, err
	}
	fail = false
	return machine, nil
}
func readBootstrapCommandAuthority(ctx context.Context, connection *nats.Conn, region bootstrapControlRegion, generation int64) (delivery.RegionalCommandAuthority, error) {
	var result delivery.RegionalCommandAuthority
	raw, _, err := nodeauthority.ReadLeaderKV(ctx, connection, "ORCH_LEADERS", "authority.regional")
	if err != nil {
		return result, err
	}
	var lease authority.RegionalAuthorityLeaseDocument
	now := time.Now().UTC()
	if json.Unmarshal(raw, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != region.Code+"-regional" || lease.CandidateId != region.CommandCandidateID || lease.IssuedAt.After(now.Add(time.Second)) || !lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond).After(now) {
		return result, errors.New("control: live admitted regional authority required")
	}
	return delivery.RegionalCommandAuthority{AuthorityID: lease.AuthorityId, Epoch: lease.Epoch, CandidateID: lease.CandidateId, LeaseID: lease.LeaseId, IssuedAt: lease.IssuedAt, ExpiresAt: lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond), DesiredGeneration: generation}, nil
}
func persistBootstrapControlReceipt(path string, next bootstrapControlReceipt) error {
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("control: invalid receipt lock")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	if next.Generation <= 0 || len(next.Regions) == 0 {
		return errors.New("control: invalid provider receipt")
	}
	if raw, err := readBootstrapControlFile(path, true, 1<<20); err == nil {
		var prior bootstrapControlReceipt
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&prior) != nil || decoder.Decode(&struct{}{}) != io.EOF || prior.Generation > next.Generation || (prior.Generation == next.Generation && !extendsBootstrapControlReceipt(prior, next)) {
			return errors.New("control: provider bindings changed within admitted generation")
		}
		if reflect.DeepEqual(prior, next) {
			directory, err := os.Open(filepath.Dir(path))
			if err != nil {
				return err
			}
			defer directory.Close()
			return directory.Sync()
		}
	} else if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".control-receipt-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func extendsBootstrapControlReceipt(prior, next bootstrapControlReceipt) bool {
	if prior.DeclarationSHA256 != next.DeclarationSHA256 {
		return false
	}
	for _, region := range prior.Regions {
		found := false
		for _, candidate := range next.Regions {
			if candidate.Code == region.Code && reflect.DeepEqual(region, candidate) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Only previous admitted regions and the current bring-up target need actual
// OCI receipts. A full launch declaration may include unprovisioned regions.
func selectBootstrapControlStage(loaded *loadedBootstrapControl, target string) ([]bootstrapControlRegion, error) {
	active := map[string]bool{target: true}
	if raw, err := readBootstrapControlFile(loaded.declaration.ReceiptFile, true, 1<<20); err == nil {
		var prior bootstrapControlReceipt
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&prior) != nil || decoder.Decode(&struct{}{}) != io.EOF || prior.Generation > loaded.declaration.Generation {
			return nil, errors.New("control: invalid prior admission receipt")
		}
		intentDigest, err := bootstrapControlIntentDigest(*loaded)
		if err != nil {
			return nil, err
		}
		if prior.Generation == loaded.declaration.Generation && prior.DeclarationSHA256 != intentDigest {
			return nil, errors.New("control: declaration changed within admitted generation")
		}
		for _, region := range prior.Regions {
			active[region.Code] = true
		}
	} else if _, statErr := os.Lstat(loaded.declaration.ReceiptFile); !os.IsNotExist(statErr) {
		return nil, err
	}
	var regions []bootstrapControlRegion
	for _, region := range loaded.declaration.Regions {
		if active[region.Code] {
			regions = append(regions, region)
		}
	}
	if len(regions) != len(active) {
		return nil, errors.New("control: requested or previous region missing from full declaration")
	}
	hostRegions, serverRegions := map[string]string{}, map[string]string{}
	var members []bootstrap.ControlRuntimeMember
	for _, member := range loaded.members {
		hostRegions[member.MemberID] = member.Region
		serverRegions[member.ServerName] = member.Region
		if active[member.Region] {
			members = append(members, member)
		}
	}
	var actions []bootstrap.ControlRuntimeActionPlan
	for _, plan := range loaded.actions {
		admitted := active[plan.Region]
		for _, handoff := range plan.Handoffs {
			admitted = admitted && active[hostRegions[handoff.MemberID]]
		}
		for _, check := range plan.Checks {
			for _, id := range check.Members {
				admitted = admitted && active[hostRegions[id]]
			}
			for _, stream := range check.Streams {
				for _, server := range stream.Servers {
					admitted = admitted && active[serverRegions[server]]
				}
			}
		}
		if admitted {
			actions = append(actions, plan)
		}
	}
	if len(actions) == 0 || len(members) == 0 {
		return nil, errors.New("control: no complete action admitted for current region stage")
	}
	loaded.members, loaded.actions = members, actions
	return regions, nil
}

func bootstrapControlIntentDigest(loaded loadedBootstrapControl) (string, error) {
	raw, err := json.Marshal(struct {
		Declaration bootstrapControlConfig
		Seeds       map[string]map[int]string
	}{loaded.declaration, loaded.seeds})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}
