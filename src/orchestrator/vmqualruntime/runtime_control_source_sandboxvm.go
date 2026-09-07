//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// qualificationControlHostAdmission is owner intent for one immutable run
// stage. Generation comes from that admission, never a lease term or KV revision.
type qualificationControlHostAdmission struct {
	Architecture runtimeplan.HostArchitecture
	Generation   int64
}

// qualificationAdmittedControlSource reads the stores named by the admitted
// stage. Its config contains intended effects; observations are always read
// from authenticated guest stores when the consumer needs them.
type qualificationAdmittedControlSource struct {
	config     bootstrap.NATSControlRuntimeConfig
	regions    []bootstrap.ControlRegionBinding
	admissions map[string]qualificationControlHostAdmission
}

func (source *qualificationAdmittedControlSource) HostControlResolvers(ctx context.Context, region string) (string, func(context.Context, string) (hostcontrol.Host, error), func(context.Context, hostcontrol.Host) (delivery.RegionalCommandAuthority, error), error) {
	var first bootstrap.ControlRuntimeMember
	for _, member := range source.config.Members {
		if member.Region == region {
			first = member
			break
		}
	}
	if first.MemberID == "" {
		return "", nil, nil, bootstrap.ErrControlRuntimeUnavailable
	}
	lease, err := source.readLease(ctx, first.Store, region, "authority.regional")
	if err != nil {
		return "", nil, nil, err
	}
	candidate := lease.CandidateId
	resolve := func(ctx context.Context, id string) (hostcontrol.Host, error) {
		host, _, err := source.readHost(ctx, region, candidate, id)
		return host, err
	}
	commandAuthority := func(ctx context.Context, requested hostcontrol.Host) (delivery.RegionalCommandAuthority, error) {
		host, lease, err := source.readHost(ctx, region, candidate, requested.NodeID.String())
		if err != nil {
			return delivery.RegionalCommandAuthority{}, err
		}
		if host != requested {
			return delivery.RegionalCommandAuthority{}, bootstrap.ErrControlRuntimeUnavailable
		}
		return delivery.RegionalCommandAuthority{AuthorityID: lease.AuthorityId, Epoch: lease.Epoch, CandidateID: lease.CandidateId, LeaseID: lease.LeaseId, IssuedAt: lease.IssuedAt, ExpiresAt: lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond), DesiredGeneration: source.admissions[requested.NodeID.String()].Generation}, nil
	}
	return candidate, resolve, commandAuthority, nil
}

func (source *qualificationAdmittedControlSource) RuntimeConfig(ctx context.Context, clients map[string]*hostcontrol.Client) (bootstrap.NATSControlRuntimeConfig, []bootstrap.ControlRegionBinding, error) {
	if ctx == nil {
		return bootstrap.NATSControlRuntimeConfig{}, nil, bootstrap.ErrControlRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return bootstrap.NATSControlRuntimeConfig{}, nil, err
	}
	config := source.config
	config.Hosts = maps.Clone(clients)
	config.ResolveChecks = source.resolveChecks
	return config, source.regions, nil
}

func (source *qualificationAdmittedControlSource) readHost(ctx context.Context, region, candidate, id string) (hostcontrol.Host, authority.RegionalAuthorityLeaseDocument, error) {
	var member bootstrap.ControlRuntimeMember
	for _, declared := range source.config.Members {
		if declared.HostID == id && declared.Region == region {
			if member.MemberID != "" {
				return hostcontrol.Host{}, authority.RegionalAuthorityLeaseDocument{}, bootstrap.ErrControlRuntimeUnavailable
			}
			member = declared
		}
	}
	admission, ok := source.admissions[id]
	if member.MemberID == "" || !ok || admission.Generation <= 0 || (admission.Architecture != runtimeplan.HostArchitectureArm64 && admission.Architecture != runtimeplan.HostArchitectureX64) {
		return hostcontrol.Host{}, authority.RegionalAuthorityLeaseDocument{}, bootstrap.ErrControlRuntimeUnavailable
	}
	lease, err := source.readLease(ctx, member.Store, region, "authority.regional")
	if err != nil || lease.CandidateId != candidate {
		return hostcontrol.Host{}, lease, errors.Join(bootstrap.ErrControlRuntimeUnavailable, err)
	}
	connection, err := source.connect(ctx, member.Store)
	if err != nil {
		return hostcontrol.Host{}, lease, err
	}
	defer connection.Close()
	raw, _, err := nodeauthority.ReadLeaderKV(ctx, connection, "ORCH_RUNTIME", "controller."+member.Instance)
	if err != nil {
		return hostcontrol.Host{}, lease, err
	}
	var record directory.RegionalRuntimeMember
	now := time.Now().UTC()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &record) != nil || !record.IsValidFor(region, now) || !record.VerifySignedIdentity() || record.Instance != member.Instance || record.IdentityPublicKey != member.IdentityPublicKey || record.AuthorityEpoch != lease.Epoch || record.ObservedAt.After(now.Add(time.Second)) || now.Sub(record.ObservedAt) > 30*time.Second || !now.Before(record.LeaseExpiresAt) || record.IsAuthorityLeader != (region+"-controller-"+record.Instance == candidate) {
		return hostcontrol.Host{}, lease, bootstrap.ErrControlRuntimeUnavailable
	}
	after, err := source.readLease(ctx, member.Store, region, "authority.regional")
	if err != nil || after.Epoch != lease.Epoch || after.CandidateId != lease.CandidateId || after.LeaseId != lease.LeaseId {
		return hostcontrol.Host{}, lease, errors.Join(bootstrap.ErrControlRuntimeUnavailable, err)
	}
	node, err := hostagent.NewNodeId(id)
	if err != nil {
		return hostcontrol.Host{}, lease, err
	}
	return hostcontrol.Host{NodeID: node, Region: strings.ToUpper(region), Architecture: admission.Architecture}, after, nil
}

func (source *qualificationAdmittedControlSource) connect(ctx context.Context, name string) (*nats.Conn, error) {
	if ctx == nil {
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, ok := source.config.Stores[name]
	parsed, parseErr := url.Parse(store.URL)
	if !ok || parseErr != nil || parsed.Scheme != "tls" || parsed.Hostname() == "" {
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	options := append([]nats.Option(nil), store.Options...)
	options = append(options, nats.Timeout(2*time.Second), nats.NoReconnect())
	connection, err := nats.Connect(store.URL, options...)
	if err != nil {
		return nil, err
	}
	state, err := connection.TLSConnectionState()
	tlsConfig := connection.Opts.TLSConfig
	if err != nil || !connection.AuthRequired() || state.Version < tls.VersionTLS13 || len(state.VerifiedChains) == 0 || connection.Opts.SignatureCB == nil || (connection.Opts.Nkey == "" && connection.Opts.UserJWT == nil) || tlsConfig == nil || tlsConfig.InsecureSkipVerify || tlsConfig.ServerName != "" && tlsConfig.ServerName != parsed.Hostname() || len(tlsConfig.Certificates) == 0 && tlsConfig.GetClientCertificate == nil {
		connection.Close()
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	return connection, nil
}

func (source *qualificationAdmittedControlSource) readLease(ctx context.Context, store, region, key string) (authority.RegionalAuthorityLeaseDocument, error) {
	connection, err := source.connect(ctx, store)
	if err != nil {
		return authority.RegionalAuthorityLeaseDocument{}, err
	}
	defer connection.Close()
	var lease authority.RegionalAuthorityLeaseDocument
	if key == "authority.regional" {
		lease, _, err = nodeauthority.ReadRegionalCommandLease(ctx, connection, "ORCH_LEADERS")
	} else if key == "authority.global" {
		var raw []byte
		raw, _, err = nodeauthority.ReadLeaderKV(ctx, connection, "ORCH_LEADERS", key)
		if err == nil {
			err = json.Unmarshal(raw, &lease)
		}
	} else {
		return lease, bootstrap.ErrControlRuntimeUnavailable
	}
	now := time.Now().UTC()
	wanted := region + "-regional"
	if key == "authority.global" {
		wanted = "global"
	}
	if err != nil || lease.Validate() != nil || lease.AuthorityId != wanted || now.Before(lease.IssuedAt) || !now.Before(lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds)*time.Millisecond)) {
		return lease, errors.Join(bootstrap.ErrControlRuntimeUnavailable, err)
	}
	for _, member := range source.config.Members {
		candidate := region + "-controller-" + member.Instance
		if key == "authority.global" {
			if region != "gru" {
				return lease, bootstrap.ErrControlRuntimeUnavailable
			}
			candidate = "global-controller-gru-" + member.Instance
		}
		if member.Region == region && lease.CandidateId == candidate {
			return lease, nil
		}
	}
	return lease, fmt.Errorf("%w: guest authority candidate is not admitted in %s", bootstrap.ErrControlRuntimeUnavailable, region)
}

func (source *qualificationAdmittedControlSource) resolveChecks(ctx context.Context, _ bootstrap.ControlActionRequest, checks []bootstrap.ControlStoreCheck) ([]bootstrap.ControlStoreCheck, error) {
	for i := range checks {
		lease, err := source.readLease(ctx, checks[i].Store, checks[i].Region, checks[i].LeaseKey)
		if err != nil {
			return nil, err
		}
		checks[i].AuthorityTerm = uint64(lease.Epoch)
		checks[i].AuthorityCandidateID = lease.CandidateId
		checks[i].AuthorityLeaseID = lease.LeaseId
	}
	return checks, nil
}

var _ QualificationControlRuntimeSource = (*qualificationAdmittedControlSource)(nil)
