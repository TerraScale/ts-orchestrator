package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
)

// ControlNATSStore contains authenticated connection options resolved from
// owner-private credential files. Connections are opened after host handoff,
// so an unbooted candidate does not need an existing control listener.
type ControlNATSStore struct {
	URL     string
	Options []nats.Option
}

type ControlRuntimeMember struct {
	MemberID          string // exact OCI instance identity
	HostID            string // admitted ts-node identity
	ServerName        string // admitted NATS server identity on this host
	Region            string
	Instance          string
	IdentityPublicKey string // pinned canonical base64 PKIX P-256 membership public key
	Store             string
}

type ControlHostHandoff struct {
	MemberID               string
	ExpectedManifestSHA256 string
	Manifest               hostmanifest.HostManifest
}

type ControlStreamAssignment struct {
	Name     string
	Replicas int
	Servers  []string // exact admitted JetStream server names, including leader
}

type ControlMirrorPlan struct {
	Store             string
	Name              string
	SourceStore       string
	SourceStream      string
	ExternalAPIPrefix string
}

type ControlStoreCheck struct {
	Store       string
	Region      string
	AuthorityID string
	LeaseKey    string
	// AuthorityTerm is the real election term, distinct from topology epochs.
	AuthorityTerm uint64
	// Mutation actions bind this exact election identity in the admitted declaration.
	AuthorityCandidateID string   `json:",omitempty"`
	AuthorityLeaseID     string   `json:",omitempty"`
	Members              []string // exact OCI member identities whose signed records must be live
	Streams              []ControlStreamAssignment
	Mirrors              []ControlMirrorPlan
}

type ControlConsumerReplicaPlan struct {
	Stream string
	Config jetstream.ConsumerConfig // Exact admitted target profile, including durable name and Replicas.
}

type ControlReplicaPlan struct {
	Consumers []ControlConsumerReplicaPlan
	Store     string
	Streams   []string
	Replicas  int
}

type ControlRuntimeActionPlan struct {
	Kind           ControlActionKind
	Region         string
	ExpectedEpoch  uint64
	TargetEpoch    uint64
	Handoffs       []ControlHostHandoff
	MirrorUpdates  []ControlMirrorPlan
	ReplicaUpdates []ControlReplicaPlan
	Checks         []ControlStoreCheck
	// RevokedCredential names a bootstrap connection which must fail with an
	// explicit NATS authorization error after credential-removal handoffs.
	RevokedCredential *ControlNATSStore
}

type NATSControlRuntimeConfig struct {
	Hosts   map[string]*hostcontrol.Client
	Stores  map[string]ControlNATSStore
	Members []ControlRuntimeMember
	Actions []ControlRuntimeActionPlan
}

type NATSControlRuntime struct {
	config  NATSControlRuntimeConfig
	members map[string]ControlRuntimeMember
	actions map[string]ControlRuntimeActionPlan
}

var _ ControlRuntime = (*NATSControlRuntime)(nil)

func runtimeActionKey(kind ControlActionKind, region string, expected, target uint64) string {
	return fmt.Sprintf("%s/%s/%d/%d", kind, region, expected, target)
}

func NewNATSControlRuntime(config NATSControlRuntimeConfig) (*NATSControlRuntime, error) {
	if config.Hosts == nil || len(config.Stores) == 0 || len(config.Members) == 0 || len(config.Actions) == 0 {
		return nil, ErrControlRuntimeUnavailable
	}
	runtime := &NATSControlRuntime{config: NATSControlRuntimeConfig{Hosts: map[string]*hostcontrol.Client{}, Stores: map[string]ControlNATSStore{}}, members: map[string]ControlRuntimeMember{}, actions: map[string]ControlRuntimeActionPlan{}}
	for region, client := range config.Hosts {
		if !validControlRegion(region) || client == nil {
			return nil, ErrControlProviderInvalid
		}
		runtime.config.Hosts[region] = client
	}
	for name, store := range config.Stores {
		if name == "" || validateControlNATSStore(store) != nil {
			return nil, ErrControlProviderInvalid
		}
		store.Options = append([]nats.Option(nil), store.Options...)
		runtime.config.Stores[name] = store
	}
	for _, member := range config.Members {
		key, err := base64.StdEncoding.Strict().DecodeString(member.IdentityPublicKey)
		if err != nil || !validControlMembershipPublicKey(key) || base64.StdEncoding.EncodeToString(key) != member.IdentityPublicKey || !validProviderIdentity(member.MemberID, "instance") || !validControlRegion(member.Region) || member.Instance == "" || member.ServerName == "" {
			return nil, ErrControlProviderInvalid
		}
		if _, err := hostagent.NewNodeId(member.HostID); err != nil || !strings.HasPrefix(member.HostID, member.Region+"-") {
			return nil, ErrControlProviderInvalid
		}
		if runtime.config.Hosts[member.Region] == nil {
			return nil, ErrControlProviderInvalid
		}
		if _, ok := runtime.config.Stores[member.Store]; !ok {
			return nil, ErrControlProviderInvalid
		}
		if _, ok := runtime.members[member.MemberID]; ok {
			return nil, ErrControlProviderInvalid
		}
		for _, prior := range runtime.members {
			if prior.HostID == member.HostID || prior.ServerName == member.ServerName || (prior.Store == member.Store && prior.Instance == member.Instance) {
				return nil, ErrControlProviderInvalid
			}
		}
		runtime.members[member.MemberID] = member
	}
	for _, source := range config.Actions {
		// Deep-copy all manifests and proof declarations; only credential options
		// are opaque closures, supplied by the validated credential resolver.
		raw, err := json.Marshal(struct {
			Kind                       ControlActionKind
			Region                     string
			ExpectedEpoch, TargetEpoch uint64
			Handoffs                   []ControlHostHandoff
			MirrorUpdates              []ControlMirrorPlan
			ReplicaUpdates             []ControlReplicaPlan
			Checks                     []ControlStoreCheck
		}{source.Kind, source.Region, source.ExpectedEpoch, source.TargetEpoch, source.Handoffs, source.MirrorUpdates, source.ReplicaUpdates, source.Checks})
		if err != nil {
			return nil, err
		}
		var plan ControlRuntimeActionPlan
		if err = json.Unmarshal(raw, &plan); err != nil {
			return nil, err
		}
		if source.RevokedCredential != nil {
			clone := *source.RevokedCredential
			clone.Options = append([]nats.Option(nil), clone.Options...)
			plan.RevokedCredential = &clone
		}
		if err := runtime.validatePlan(plan); err != nil {
			return nil, err
		}
		key := runtimeActionKey(plan.Kind, plan.Region, plan.ExpectedEpoch, plan.TargetEpoch)
		if _, ok := runtime.actions[key]; ok {
			return nil, ErrControlProviderInvalid
		}
		runtime.actions[key] = plan
	}
	return runtime, nil
}

func validateControlNATSStore(store ControlNATSStore) error {
	parsed, err := url.Parse(store.URL)
	if err != nil || parsed.Scheme != "tls" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" || parsed.Fragment != "" || len(store.Options) == 0 {
		return ErrControlProviderInvalid
	}
	return nil
}

func (r *NATSControlRuntime) validatePlan(plan ControlRuntimeActionPlan) error {
	if !validControlRegion(plan.Region) || plan.TargetEpoch == 0 || plan.ExpectedEpoch > plan.TargetEpoch || len(plan.Checks) == 0 {
		return ErrControlProviderInvalid
	}
	globalProof := false
	provedMembers := map[string]bool{}
	globalServers := map[string]bool{}
	switch plan.Kind {
	case ControlActionStartTemporaryR1, ControlActionFenceR1, ControlActionStartCandidate, ControlActionPromoteR3, ControlActionRevokeBootstrap, ControlActionRemoteManage, ControlActionStartRegionalR3:
		if len(plan.Handoffs) == 0 {
			return ErrControlProviderInvalid
		}
	case ControlActionSyncCandidate:
		mirrored := len(plan.MirrorUpdates) > 0
		for _, check := range plan.Checks {
			mirrored = mirrored || len(check.Mirrors) > 0
		}
		if !mirrored {
			return ErrControlProviderInvalid
		}
	case ControlActionVerifyCandidate, ControlActionVerifyQuorum:
	default:
		return ErrControlProviderInvalid
	}
	if plan.Kind == ControlActionRevokeBootstrap && (plan.RevokedCredential == nil || validateControlNATSStore(*plan.RevokedCredential) != nil) {
		return ErrControlProviderInvalid
	}
	for _, handoff := range plan.Handoffs {
		if _, ok := r.members[handoff.MemberID]; !ok || !canonicalControlDigest(handoff.ExpectedManifestSHA256) {
			return ErrControlProviderInvalid
		}
		if _, err := hostmanifest.CanonicalHostManifestJSON(handoff.Manifest); err != nil {
			return err
		}
		hasControl := false
		for _, component := range handoff.Manifest.Components {
			if component.Name == "orchestrator" {
				hasControl = true
			}
		}
		if !hasControl {
			return ErrControlProviderInvalid
		}
	}
	for _, check := range plan.Checks {
		if _, ok := r.config.Stores[check.Store]; !ok || !validControlRegion(check.Region) || check.AuthorityID == "" || check.LeaseKey == "" || check.AuthorityTerm == 0 || len(check.Streams) == 0 {
			return ErrControlProviderInvalid
		}
		names := map[string]bool{}
		for _, stream := range check.Streams {
			if stream.Name == "" || names[stream.Name] || (stream.Replicas != 1 && stream.Replicas != 3) || len(stream.Servers) != stream.Replicas {
				return ErrControlProviderInvalid
			}
			names[stream.Name] = true
			servers := map[string]bool{}
			for _, server := range stream.Servers {
				if server == "" || servers[server] || !r.admittedServer(server) {
					return ErrControlProviderInvalid
				}
				servers[server] = true
			}
		}
		if names["GLOBAL_SPEC"] {
			if check.AuthorityID != "global" || check.LeaseKey != "authority.global" || len(check.Members) != 0 {
				return ErrControlProviderInvalid
			}
			required := globalControlStreamNames()
			if len(names) != len(required) {
				return errors.New("bootstrap: global proof must cover the complete authoritative topology")
			}
			for _, name := range required {
				if !names[name] {
					return ErrControlProviderInvalid
				}
			}
			replicas := 1
			if plan.Kind == ControlActionPromoteR3 || plan.Kind == ControlActionVerifyQuorum || plan.Kind == ControlActionRevokeBootstrap {
				replicas = 3
			}
			var assigned []string
			for _, stream := range check.Streams {
				actual := append([]string(nil), stream.Servers...)
				sort.Strings(actual)
				if assigned == nil {
					assigned = actual
				}
				if stream.Replicas != replicas || strings.Join(actual, "\x00") != strings.Join(assigned, "\x00") {
					return ErrControlProviderInvalid
				}
			}
			regions := map[string]bool{}
			for _, server := range assigned {
				globalServers[server] = true
				for _, member := range r.members {
					if member.ServerName == server {
						regions[member.Region] = true
					}
				}
			}
			if replicas == 3 && (len(regions) != 3 || !regions["gru"] || !regions["sfo"] || !regions["fra"]) {
				return errors.New("bootstrap: global R3 must occupy GRU, SFO and FRA")
			}
			if replicas == 1 && (len(regions) != 1 || !regions["gru"]) {
				return ErrControlProviderInvalid
			}
			globalProof = true
		}
		if !names["GLOBAL_SPEC"] && (check.AuthorityID != check.Region+"-regional" || check.LeaseKey != "authority.regional") {
			return ErrControlProviderInvalid
		}
		if !names["KV_ORCH_LEADERS"] || (len(check.Members) > 0 && !names["KV_ORCH_RUNTIME"]) || (len(check.Members) == 0 && !names["GLOBAL_SPEC"]) {
			return ErrControlProviderInvalid
		}
		for _, id := range check.Members {
			member, ok := r.members[id]
			if !ok || member.Region != check.Region || member.Store != check.Store {
				return ErrControlProviderInvalid
			}
			provedMembers[member.ServerName] = true
		}
		for _, mirror := range check.Mirrors {
			if err := r.validateMirror(mirror); err != nil {
				return err
			}
		}
	}
	if plan.Kind == ControlActionSyncCandidate {
		expected := map[string]bool{}
		for _, name := range globalControlStreamNames() {
			expected[name] = true
		}
		seen, destinations := map[string]bool{}, map[string]bool{}
		sourceStore, targetStore := "", ""
		for _, check := range plan.Checks {
			for _, mirror := range check.Mirrors {
				if !expected[mirror.SourceStream] || seen[mirror.SourceStream] || destinations[mirror.Name] {
					return errors.New("bootstrap: candidate synchronization stream set is not exact")
				}
				if sourceStore == "" {
					sourceStore, targetStore = mirror.SourceStore, mirror.Store
				}
				if sourceStore != mirror.SourceStore || targetStore != mirror.Store {
					return ErrControlProviderInvalid
				}
				seen[mirror.SourceStream], destinations[mirror.Name] = true, true
			}
		}
		if len(seen) != len(expected) {
			return errors.New("bootstrap: candidate synchronization must cover complete authoritative topology")
		}
	}
	if len(provedMembers) == 0 {
		return ErrControlProviderInvalid
	}
	for server := range globalServers {
		if !provedMembers[server] {
			return errors.New("bootstrap: global replicas require signed member and host proofs")
		}
	}
	switch plan.Kind {
	case ControlActionStartTemporaryR1, ControlActionFenceR1, ControlActionPromoteR3, ControlActionVerifyQuorum, ControlActionRevokeBootstrap:
		if !globalProof {
			return errors.New("bootstrap: action requires a complete authoritative global store proof")
		}
	}
	for _, mirror := range plan.MirrorUpdates {
		if plan.Kind != ControlActionSyncCandidate {
			return ErrControlProviderInvalid
		}
		if err := r.validateMirror(mirror); err != nil {
			return err
		}
		observed := false
		for _, check := range plan.Checks {
			for _, wanted := range check.Mirrors {
				if wanted == mirror {
					observed = true
				}
			}
		}
		if !observed {
			return errors.New("bootstrap: mirror mutation requires exact readback proof")
		}
	}
	for _, update := range plan.ReplicaUpdates {
		seen := map[string]bool{}
		for _, name := range update.Streams {
			if seen[name] {
				return ErrControlProviderInvalid
			}
			seen[name] = true
			admitted := false
			for _, check := range plan.Checks {
				if check.Store != update.Store {
					continue
				}
				for _, stream := range check.Streams {
					if stream.Name == name && stream.Replicas == update.Replicas {
						admitted = true
					}
				}
			}
			if !admitted {
				return ErrControlProviderInvalid
			}
		}
		if err := validateControlConsumerReplicas(update); err != nil {
			return err
		}
		if _, ok := r.config.Stores[update.Store]; !ok || update.Replicas != 3 || len(update.Streams) == 0 || (plan.Kind != ControlActionPromoteR3 && plan.Kind != ControlActionStartRegionalR3) {
			return ErrControlProviderInvalid
		}
	}
	if _, err := r.controlMutationPins(plan); err != nil {
		return err
	}
	return nil
}

func (r *NATSControlRuntime) admittedServer(name string) bool {
	for _, member := range r.members {
		if member.ServerName == name {
			return true
		}
	}
	return false
}

func (r *NATSControlRuntime) validateMirror(m ControlMirrorPlan) error {
	if _, ok := r.config.Stores[m.Store]; !ok {
		return ErrControlProviderInvalid
	}
	if _, ok := r.config.Stores[m.SourceStore]; !ok || m.Name == "" || m.SourceStream == "" || (m.Store != m.SourceStore && m.ExternalAPIPrefix == "") {
		return ErrControlProviderInvalid
	}
	return nil
}

func openControlNATS(ctx context.Context, store ControlNATSStore) (*nats.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateControlNATSStore(store); err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(store.URL)
	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	options := nats.GetDefaultOptions()
	options.Url = store.URL
	for _, apply := range store.Options {
		if err := apply(&options); err != nil {
			return nil, err
		}
	}
	config := options.TLSConfig
	if options.Url != store.URL || len(options.Servers) != 0 || options.SignatureCB == nil || (options.Nkey == "" && options.UserJWT == nil) || config == nil || config.MinVersion < tls.VersionTLS13 || config.InsecureSkipVerify || (config.ServerName != "" && config.ServerName != parsed.Hostname()) || (len(config.Certificates) == 0 && config.GetClientCertificate == nil) {
		return nil, ErrControlRuntimeUnavailable
	}
	options.Timeout, options.AllowReconnect = timeout, false
	connection, err := options.Connect()
	if err != nil {
		return nil, err
	}
	state, err := connection.TLSConnectionState()
	config = connection.Opts.TLSConfig
	if err != nil || !connection.AuthRequired() || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 || connection.Opts.SignatureCB == nil || (connection.Opts.Nkey == "" && connection.Opts.UserJWT == nil) || config == nil || config.InsecureSkipVerify || (config.ServerName != "" && config.ServerName != parsed.Hostname()) || (len(config.Certificates) == 0 && config.GetClientCertificate == nil) {
		connection.Close()
		return nil, ErrControlRuntimeUnavailable
	}
	return connection, nil
}

func controlEvidenceDigest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (r *NATSControlRuntime) Execute(ctx context.Context, request ControlActionRequest) (ControlRuntimeEvidence, error) {
	if r == nil || ctx == nil {
		return ControlRuntimeEvidence{}, ErrControlRuntimeUnavailable
	}
	if err := validateProviderAction(ctx, request, request.Action.Kind); err != nil {
		return ControlRuntimeEvidence{}, err
	}
	plan, ok := r.actions[runtimeActionKey(request.Action.Kind, request.Action.Region, request.Action.ExpectedEpoch, request.Action.TargetEpoch)]
	if !ok {
		return ControlRuntimeEvidence{}, errors.New("bootstrap: no admitted runtime handoff for this control transition")
	}
	for _, handoff := range plan.Handoffs {
		if err := r.applyHandoff(ctx, request, handoff); err != nil {
			return ControlRuntimeEvidence{}, err
		}
	}
	pins, err := r.controlMutationPins(plan)
	if err != nil {
		return ControlRuntimeEvidence{}, err
	}
	for _, mirror := range plan.MirrorUpdates {
		if err := r.createMirror(ctx, mirror, pins); err != nil {
			return ControlRuntimeEvidence{}, err
		}
	}
	for _, update := range plan.ReplicaUpdates {
		if err := r.updateControlReplicas(ctx, update, pins); err != nil {
			return ControlRuntimeEvidence{}, err
		}
	}
	collectionStarted := time.Now().UTC()
	var identities, storage, health []any
	var candidate CandidateRuntimeEvidence
	for _, check := range plan.Checks {
		id, state, facts, err := r.checkStore(ctx, check)
		if err != nil {
			return ControlRuntimeEvidence{}, err
		}
		identities = append(identities, id)
		storage = append(storage, state)
		health = append(health, facts)
		if plan.Kind == ControlActionVerifyCandidate {
			// These gates are derived from the exact candidate check that just
			// passed: signed members, stream assignments, fresh host facts and
			// source/mirror watermark comparisons. Generic action success alone
			// must not imply candidate readiness.
			candidate.IdentityReady = candidate.IdentityReady || len(check.Members) > 0 && len(id) == len(check.Members)
			candidate.StorageReady = candidate.StorageReady || len(check.Streams) > 0 && len(state.Streams) == len(check.Streams)
			candidate.HealthReady = candidate.HealthReady || len(check.Members) > 0 && len(facts) == len(check.Members)
			candidate.CaughtUp = candidate.CaughtUp || len(check.Mirrors) > 0 && len(state.Mirrors) == len(check.Mirrors)
		}
	}
	if plan.RevokedCredential != nil {
		connection, err := openControlNATS(ctx, *plan.RevokedCredential)
		if connection != nil {
			connection.Close()
		}
		// DNS/TLS/timeouts are not proof of credential revocation.
		if !errors.Is(err, nats.ErrAuthorization) {
			return ControlRuntimeEvidence{}, errors.New("bootstrap: bootstrap credential revocation was not proved")
		}
	}
	identityDigest, err := controlEvidenceDigest(identities)
	if err != nil {
		return ControlRuntimeEvidence{}, err
	}
	storageDigest, err := controlEvidenceDigest(storage)
	if err != nil {
		return ControlRuntimeEvidence{}, err
	}
	healthDigest, err := controlEvidenceDigest(health)
	if err != nil {
		return ControlRuntimeEvidence{}, err
	}
	evidence := ControlRuntimeEvidence{IdentityDigest: identityDigest, StorageDigest: storageDigest, HealthDigest: healthDigest, ObservedAt: collectionStarted}
	if plan.Kind == ControlActionVerifyCandidate {
		evidence.Candidate = &candidate
	}
	return evidence, nil
}

func (r *NATSControlRuntime) applyHandoff(ctx context.Context, request ControlActionRequest, handoff ControlHostHandoff) error {
	member := r.members[handoff.MemberID]
	desired, err := hostmanifest.HostManifestSha256(handoff.Manifest)
	if err != nil {
		return err
	}
	current, err := r.config.Hosts[member.Region].Status(ctx, member.HostID)
	if err != nil {
		return err
	}
	if current.Facts.ManifestSha256 != desired {
		if current.Facts.ManifestSha256 != handoff.ExpectedManifestSHA256 {
			return errors.New("bootstrap: host manifest predecessor changed")
		}
		sum := sha256.Sum256([]byte(request.Action.IdempotencyKey + "\x00" + member.HostID + "\x00" + desired))
		commandID := "control-" + hex.EncodeToString(sum[:20])
		if _, err := r.config.Hosts[member.Region].ApplyManifest(ctx, member.HostID, commandID, handoff.ExpectedManifestSHA256, handoff.Manifest); err != nil {
			return err
		}
	}
	// The receipt only acknowledges the desired manifest. Poll actual component
	// versions and unit state before permitting the control action to complete.
	bounded, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		report, err := r.config.Hosts[member.Region].Status(bounded, member.HostID)
		if err != nil {
			return err
		}
		ready := report.Facts.ManifestSha256 == desired && !report.Facts.ClockUnhealthy
		installed, versionsMatch := ready, true
		byName := map[string]hostagent.ComponentFact{}
		for _, fact := range report.Facts.Components {
			byName[fact.Name] = fact
		}
		for _, component := range handoff.Manifest.Components {
			if component.Name == hostmanifest.TsNodeComponentName {
				continue
			}
			fact, ok := byName[component.Name]
			installed = installed && ok && fact.Installed && fact.Desired == component.Version
			versionsMatch = versionsMatch && ok && fact.Version == component.Version
			ready = ready && ok && fact.Installed && fact.UnitActive && fact.Version == component.Version && fact.Desired == component.Version
		}
		if ready {
			return nil
		}
		if installed {
			commandID := func(operation string) string {
				sum := sha256.Sum256([]byte(request.Action.IdempotencyKey + "\x00" + member.HostID + "\x00" + desired + "\x00" + operation))
				return "control-" + hex.EncodeToString(sum[:20])
			}
			client := r.config.Hosts[member.Region]
			if !versionsMatch {
				for _, component := range handoff.Manifest.Components {
					if component.Name == hostmanifest.TsNodeComponentName || byName[component.Name].Version == component.Version {
						continue
					}
					if !report.Quiesced {
						if _, err := client.SetDrain(bounded, member.HostID, commandID("drain/"+component.Name), true); err != nil {
							return err
						}
					} else if _, err := client.Deploy(bounded, member.HostID, commandID("deploy/"+component.Name), component.Name, component.Version); err != nil {
						return err
					}
					break
				}
			} else if report.State == hostagent.NodeStateDraining {
				if _, err := client.SetDrain(bounded, member.HostID, commandID("release"), false); err != nil {
					return err
				}
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-bounded.Done():
			timer.Stop()
			return bounded.Err()
		case <-timer.C:
		}
	}
}

type controlStoreSnapshot struct {
	Lease         authority.RegionalAuthorityLeaseDocument
	LeaseRevision uint64
	Streams       []*jetstream.StreamInfo
	Mirrors       []controlMirrorSnapshot
}
type controlMirrorSnapshot struct {
	SourceStream, MirrorStream     string
	SourceSequence, MirrorSequence uint64
	SourceMessageDigest            string
	EmptyStoreMetadataDigest       string `json:",omitempty"`
}

func (r *NATSControlRuntime) checkStore(ctx context.Context, check ControlStoreCheck) (any, any, any, error) {
	return r.checkStoreMode(ctx, check, false)
}
func (r *NATSControlRuntime) checkStoreMode(ctx context.Context, check ControlStoreCheck, quorumOnly bool) (any, any, any, error) {
	connection, err := openControlNATS(ctx, r.config.Stores[check.Store])
	if err != nil {
		return nil, nil, nil, err
	}
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		return nil, nil, nil, err
	}
	entry, err := readControlLeaseFromLeader(ctx, js.Conn(), check.LeaseKey)
	if err != nil {
		return nil, nil, nil, err
	}
	var lease authority.RegionalAuthorityLeaseDocument
	if json.Unmarshal(entry.Data, &lease) != nil || lease.Validate() != nil || lease.AuthorityId != check.AuthorityID || lease.Epoch <= 0 || uint64(lease.Epoch) != check.AuthorityTerm || check.AuthorityCandidateID != "" && lease.CandidateId != check.AuthorityCandidateID || check.AuthorityLeaseID != "" && lease.LeaseId != check.AuthorityLeaseID || !lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond).After(time.Now().UTC()) {
		return nil, nil, nil, ErrControlRuntimeUnavailable
	}
	if !r.admittedControlAuthority(check, lease.CandidateId) {
		return nil, nil, nil, ErrControlRuntimeUnavailable
	}
	snapshot := controlStoreSnapshot{Lease: lease, LeaseRevision: entry.Sequence}
	var identities []directory.RegionalRuntimeMember
	var facts []hostagent.NodeStatusReport
	for _, id := range check.Members {
		member := r.members[id]
		record, err := readControlMember(ctx, js, member)
		if err != nil {
			return nil, nil, nil, err
		}
		if record.AuthorityEpoch != lease.Epoch || record.AuthorityRevision <= 0 || uint64(record.AuthorityRevision) > entry.Sequence || record.IsAuthorityLeader != (member.Region+"-controller-"+record.Instance == lease.CandidateId) {
			return nil, nil, nil, ErrControlRuntimeUnavailable
		}
		report, err := r.config.Hosts[member.Region].Status(ctx, member.HostID)
		if err != nil || !controlHostReady(report) {
			return nil, nil, nil, ErrControlRuntimeUnavailable
		}
		identities = append(identities, record)
		facts = append(facts, report)
	}
	for _, wanted := range check.Streams {
		stream, err := js.Stream(ctx, wanted.Name)
		if err != nil {
			return nil, nil, nil, err
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return nil, nil, nil, err
		}
		if info.Cluster == nil && wanted.Replicas == 1 {
			// Standalone R1 reports no Raft cluster. Its authenticated INFO names
			// the one storage server; never fill this identity from desired input.
			info.Cluster = &jetstream.ClusterInfo{Leader: connection.ConnectedServerName()}
		}
		if err := verifyControlStreamAssignmentMode(info, wanted, quorumOnly); err != nil {
			return nil, nil, nil, err
		}
		snapshot.Streams = append(snapshot.Streams, info)
	}
	for _, mirror := range check.Mirrors {
		state, err := r.checkMirror(ctx, mirror)
		if err != nil {
			return nil, nil, nil, err
		}
		snapshot.Mirrors = append(snapshot.Mirrors, state)
	}
	// Re-read the lease after the potentially slow provider calls. A different
	// term/holder or expired lease invalidates all evidence gathered above.
	latest, err := readControlLeaseFromLeader(ctx, js.Conn(), check.LeaseKey)
	if err != nil {
		return nil, nil, nil, err
	}
	var finalLease authority.RegionalAuthorityLeaseDocument
	if json.Unmarshal(latest.Data, &finalLease) != nil || finalLease.Validate() != nil || finalLease.LeaseId != lease.LeaseId || finalLease.Epoch != lease.Epoch || finalLease.CandidateId != lease.CandidateId || finalLease.AuthorityId != lease.AuthorityId || !finalLease.IssuedAt.Add(time.Duration(finalLease.DurationMilliseconds)*time.Millisecond).After(time.Now().UTC()) {
		return nil, nil, nil, ErrControlRuntimeUnavailable
	}
	return identities, snapshot, facts, nil
}

func readControlMember(ctx context.Context, js jetstream.JetStream, member ControlRuntimeMember) (directory.RegionalRuntimeMember, error) {
	var record directory.RegionalRuntimeMember
	bucket, err := js.KeyValue(ctx, "ORCH_RUNTIME")
	if err != nil {
		return record, err
	}
	entry, err := bucket.Get(ctx, "controller."+member.Instance)
	if err != nil {
		return record, err
	}
	now := time.Now().UTC()
	if json.Unmarshal(entry.Value(), &record) != nil || !record.IsValidFor(member.Region, now) || !record.VerifySignedIdentity() || record.Instance != member.Instance || record.IdentityPublicKey != member.IdentityPublicKey || now.Sub(record.ObservedAt) > 30*time.Second || record.ObservedAt.After(now.Add(time.Second)) || !record.LeaseExpiresAt.After(now) {
		return record, ErrControlRuntimeUnavailable
	}
	return record, nil
}

func verifyControlStreamAssignment(info *jetstream.StreamInfo, wanted ControlStreamAssignment) error {
	return verifyControlStreamAssignmentMode(info, wanted, false)
}
func verifyControlStreamAssignmentMode(info *jetstream.StreamInfo, wanted ControlStreamAssignment, quorumOnly bool) error {
	if info == nil || info.Config.Name != wanted.Name || info.Config.Storage != jetstream.FileStorage || info.Config.Replicas != wanted.Replicas || info.Cluster == nil || info.Cluster.Leader == "" {
		return ErrControlRuntimeUnavailable
	}
	servers := []string{info.Cluster.Leader}
	healthy := 1
	for _, replica := range info.Cluster.Replicas {
		current := !replica.Offline && replica.Current && replica.Lag == 0
		if !current && !quorumOnly {
			return ErrControlRuntimeUnavailable
		}
		if current {
			healthy++
		}
		servers = append(servers, replica.Name)
	}
	if healthy < wanted.Replicas/2+1 {
		return ErrControlRuntimeUnavailable
	}
	sort.Strings(servers)
	expected := append([]string(nil), wanted.Servers...)
	sort.Strings(expected)
	if len(servers) != len(expected) {
		return ErrControlRuntimeUnavailable
	}
	for i := range servers {
		if servers[i] != expected[i] || (i > 0 && servers[i] == servers[i-1]) {
			return ErrControlRuntimeUnavailable
		}
	}
	return nil
}

func (r *NATSControlRuntime) checkMirror(ctx context.Context, plan ControlMirrorPlan) (controlMirrorSnapshot, error) {
	var result controlMirrorSnapshot
	sourceConn, err := openControlNATS(ctx, r.config.Stores[plan.SourceStore])
	if err != nil {
		return result, err
	}
	defer sourceConn.Close()
	sourceJS, err := jetstream.New(sourceConn)
	if err != nil {
		return result, err
	}
	source, err := sourceJS.Stream(ctx, plan.SourceStream)
	if err != nil {
		return result, err
	}
	before, err := source.Info(ctx)
	if err != nil {
		return result, err
	}
	if before.Config.Storage != jetstream.FileStorage {
		return result, ErrControlRuntimeUnavailable
	}
	mirrorConn, err := openControlNATS(ctx, r.config.Stores[plan.Store])
	if err != nil {
		return result, err
	}
	defer mirrorConn.Close()
	mirrorJS, err := jetstream.New(mirrorConn)
	if err != nil {
		return result, err
	}
	mirror, err := mirrorJS.Stream(ctx, plan.Name)
	if err != nil {
		return result, err
	}
	observed, err := mirror.Info(ctx)
	if err != nil {
		return result, err
	}
	if !matchesControlMirror(observed.Config, plan, before.Config) || observed.State.LastSeq < before.State.LastSeq || observed.Mirror == nil || observed.Mirror.Lag != 0 {
		return result, ErrControlRuntimeUnavailable
	}
	if before.State.Msgs == 0 {
		after, err := source.Info(ctx)
		if err != nil {
			return result, err
		}
		digest, err := verifyEmptyControlMirror(before, after, observed)
		if err != nil {
			return result, err
		}
		return controlMirrorSnapshot{SourceStream: plan.SourceStream, MirrorStream: plan.Name, SourceSequence: before.State.LastSeq, MirrorSequence: observed.State.LastSeq, EmptyStoreMetadataDigest: digest}, nil
	}
	if before.State.LastSeq == 0 {
		return result, ErrControlRuntimeUnavailable
	}
	sourceMessage, err := source.GetMsg(ctx, before.State.LastSeq)
	if err != nil {
		return result, err
	}
	mirroredMessage, err := mirror.GetMsg(ctx, before.State.LastSeq)
	if err != nil {
		return result, err
	}
	// Compare subject, headers and bytes at the actual source watermark.
	// Nonempty stores cannot use equal counters alone as synchronization proof.
	sourceDigest, err := controlEvidenceDigest(struct {
		Subject string
		Header  nats.Header
		Data    []byte
	}{sourceMessage.Subject, sourceMessage.Header, sourceMessage.Data})
	if err != nil {
		return result, err
	}
	mirrorDigest, err := controlEvidenceDigest(struct {
		Subject string
		Header  nats.Header
		Data    []byte
	}{mirroredMessage.Subject, mirroredMessage.Header, mirroredMessage.Data})
	if err != nil || sourceDigest != mirrorDigest {
		return result, ErrControlRuntimeUnavailable
	}
	return controlMirrorSnapshot{SourceStream: plan.SourceStream, MirrorStream: plan.Name, SourceSequence: before.State.LastSeq, MirrorSequence: observed.State.LastSeq, SourceMessageDigest: sourceDigest}, nil
}

func controlHostReady(report hostagent.NodeStatusReport) bool {
	if report.Facts.ClockUnhealthy {
		return false
	}
	for _, component := range report.Facts.Components {
		if component.Name == "orchestrator" {
			return component.UnitActive && component.Installed && component.Version != "" && component.Version == component.Desired
		}
	}
	return false
}

func (r *NATSControlRuntime) Observe(ctx context.Context) (map[string]bool, error) {
	if r == nil || ctx == nil {
		return nil, ErrControlRuntimeUnavailable
	}
	result := make(map[string]bool, len(r.members))
	for id, member := range r.members {
		result[id] = false
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		connection, err := openControlNATS(ctx, r.config.Stores[member.Store])
		if err != nil {
			continue
		}
		js, err := jetstream.New(connection)
		if err == nil {
			_, err = readControlMember(ctx, js, member)
		}
		connection.Close()
		if err != nil {
			continue
		}
		report, err := r.config.Hosts[member.Region].Status(ctx, member.HostID)
		result[id] = err == nil && controlHostReady(report)
	}
	return result, nil
}

func globalControlStreamNames() []string {
	topology, _ := messaging.NewGlobalNatsTopology(3)
	var names []string
	for _, stream := range topology.Streams() {
		names = append(names, stream.Name)
	}
	for _, bucket := range []jetstream.KeyValueConfig{topology.Leaders(), topology.Cells(), topology.MasterDeliveries()} {
		names = append(names, "KV_"+bucket.Bucket)
	}
	sort.Strings(names)
	return names
}

func validControlMembershipPublicKey(raw []byte) bool {
	key, err := x509.ParsePKIXPublicKey(raw)
	public, ok := key.(*ecdsa.PublicKey)
	return err == nil && ok && public.Curve == elliptic.P256()
}

// VerifyQuorumAvailability checks an already admitted R3 without requiring
// every replica online. It does not authorize promotion or credential removal.
func (r *NATSControlRuntime) VerifyQuorumAvailability(ctx context.Context, epoch uint64) error {
	if r == nil || ctx == nil {
		return ErrControlRuntimeUnavailable
	}
	var admitted *ControlRuntimeActionPlan
	for _, plan := range r.actions {
		if plan.Kind == ControlActionVerifyQuorum && plan.TargetEpoch == epoch {
			copy := plan
			admitted = &copy
			break
		}
	}
	if admitted == nil {
		return errors.New("bootstrap: no admitted quorum observation for topology epoch")
	}
	checked := false
	for _, check := range admitted.Checks {
		global := false
		for _, stream := range check.Streams {
			if stream.Name == "GLOBAL_SPEC" {
				global = true
			}
		}
		if !global {
			continue
		}
		// Storage majority and its live authority lease are the availability
		// evidence. Initial admission separately requires all signed members.
		check.Members = nil
		if _, _, _, err := r.checkStoreMode(ctx, check, true); err != nil {
			return err
		}
		checked = true
	}
	if !checked {
		return ErrControlRuntimeUnavailable
	}
	return nil
}

// PlanControlLaunchManifest assigns content-addressed local launch revisions.
// The signed artifact URL, detached signature and digest remain unchanged;
// configuration/arguments/resource changes cannot overwrite an installed slot.
func PlanControlLaunchManifest(input hostmanifest.HostManifest) (hostmanifest.HostManifest, error) {
	canonical, err := hostmanifest.CanonicalHostManifestJSON(input)
	if err != nil {
		return hostmanifest.HostManifest{}, err
	}
	manifest, err := hostmanifest.ParseHostManifest(canonical)
	if err != nil {
		return hostmanifest.HostManifest{}, err
	}
	for i := range manifest.Components {
		component := manifest.Components[i]
		if component.Name == hostmanifest.TsNodeComponentName {
			continue
		}
		material := component
		material.Version = ""
		digest, err := controlEvidenceDigest(material)
		if err != nil {
			return hostmanifest.HostManifest{}, err
		}
		component.Version = "ctl-" + digest[:56]
		validated, err := hostmanifest.NewComponentSpec(component)
		if err != nil {
			return hostmanifest.HostManifest{}, err
		}
		manifest.Components[i] = validated
	}
	return manifest, nil
}

func verifyEmptyControlMirror(before, after, mirror *jetstream.StreamInfo) (string, error) {
	if before == nil || after == nil || mirror == nil || before.Config.Storage != jetstream.FileStorage || after.Config.Storage != jetstream.FileStorage || mirror.Config.Storage != jetstream.FileStorage || before.State.Msgs != 0 || after.State.Msgs != 0 || mirror.State.Msgs != 0 || before.State.Bytes != 0 || after.State.Bytes != 0 || mirror.State.Bytes != 0 || before.State.LastSeq != after.State.LastSeq || mirror.State.LastSeq != before.State.LastSeq || mirror.State.FirstSeq != before.State.FirstSeq || before.State.FirstSeq != after.State.FirstSeq {
		return "", ErrControlRuntimeUnavailable
	}
	firstConfig, err := controlEvidenceDigest(before.Config)
	if err != nil {
		return "", err
	}
	lastConfig, err := controlEvidenceDigest(after.Config)
	if err != nil || firstConfig != lastConfig {
		return "", ErrControlRuntimeUnavailable
	}
	return controlEvidenceDigest(struct {
		SourceConfig jetstream.StreamConfig
		SourceState  jetstream.StreamState
		MirrorConfig jetstream.StreamConfig
		MirrorState  jetstream.StreamState
	}{after.Config, after.State, mirror.Config, mirror.State})
}

type controlLeaseMessage struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"seq"`
	Data     []byte    `json:"data"`
	Time     time.Time `json:"time"`
}

// STREAM.MSG.GET is answered by the stream leader. KV.Get may use a follower's
// direct-get cache and cannot establish the current authority lease.
func readControlLeaseFromLeader(ctx context.Context, conn *nats.Conn, key string) (controlLeaseMessage, error) {
	var zero controlLeaseMessage
	if key != "authority.global" && key != "authority.regional" {
		return zero, ErrControlProviderInvalid
	}
	subject := "$KV.ORCH_LEADERS." + key
	request, err := json.Marshal(struct {
		LastBySubject string `json:"last_by_subj"`
	}{subject})
	if err != nil {
		return zero, err
	}
	response, err := conn.RequestWithContext(ctx, "$JS.API.STREAM.MSG.GET.KV_ORCH_LEADERS", request)
	if err != nil {
		return zero, err
	}
	var result struct {
		Type    string               `json:"type"`
		Message *controlLeaseMessage `json:"message"`
		Error   *jetstream.APIError  `json:"error"`
	}
	if json.Unmarshal(response.Data, &result) != nil || result.Error != nil || result.Type != "io.nats.jetstream.api.v1.stream_msg_get_response" || result.Message == nil || result.Message.Subject != subject || result.Message.Sequence == 0 || len(result.Message.Data) == 0 {
		return zero, ErrControlRuntimeUnavailable
	}
	return *result.Message, nil
}
