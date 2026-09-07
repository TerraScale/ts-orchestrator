//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// QualificationControlRuntimeSource is the admitted guest producer used by
// the qualification caller. Implementations must read these values from the
// authenticated guest control plane; declarations and liveness are not
// authority or membership evidence.
type QualificationControlRuntimeSource interface {
	HostControlResolvers(context.Context, string) (string, func(context.Context, string) (hostcontrol.Host, error), func(context.Context, hostcontrol.Host) (delivery.RegionalCommandAuthority, error), error)
	RuntimeConfig(context.Context, map[string]*hostcontrol.Client) (bootstrap.NATSControlRuntimeConfig, []bootstrap.ControlRegionBinding, error)
}

// SetQualificationControlRuntimeSource wires the admitted producer into the
// real guest ready transition. The source is queried only after all declared
// guests have been activated, so its observations cover the complete estate.
func (factory *firecrackerFactory) SetQualificationControlRuntimeSource(source QualificationControlRuntimeSource) error {
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	return services.SetQualificationControlRuntimeSource(source)
}

// ConfigureQualificationControlRuntimeFromSource is the concrete initial-R1
// caller. It binds enrolled candidate signers first, then asks the admitted
// guest producer for lease, membership, stream and action observations before
// installing the runtime consumed by vmqualsuite.
func (factory *firecrackerFactory) ConfigureQualificationControlRuntimeFromSource(ctx context.Context, source QualificationControlRuntimeSource) error {
	if ctx == nil || source == nil {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok || services == nil {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	clients := make(map[string]*hostcontrol.Client)
	for _, planned := range services.plan.Regions {
		region := strings.ToLower(string(planned.Code))
		if len(planned.Guests) == 0 {
			return bootstrap.ErrControlRuntimeUnavailable
		}
		candidate, resolve, authority, err := source.HostControlResolvers(ctx, region)
		if err != nil {
			return err
		}
		client, err := factory.QualificationHostControl(ctx, region, candidate, resolve, authority)
		if err != nil {
			return err
		}
		clients[region] = client
	}
	config, regions, err := source.RuntimeConfig(ctx, clients)
	if err != nil {
		return err
	}
	config.Hosts = clients
	return factory.ConfigureQualificationControlRuntime(config, regions)
}

// QualificationHostControl binds the actual fixture transport to explicit
// admitted-membership and live-authority resolvers. The transport itself does
// not establish either membership or authority.
func (factory *firecrackerFactory) QualificationHostControl(ctx context.Context, region, candidateID string, resolve func(context.Context, string) (hostcontrol.Host, error), commandAuthority func(context.Context, hostcontrol.Host) (delivery.RegionalCommandAuthority, error)) (*hostcontrol.Client, error) {
	if ctx == nil || resolve == nil || commandAuthority == nil || candidateID == "" {
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok {
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	declared := false
	candidateDeclared := false
	for _, planned := range services.plan.Regions {
		if region == strings.ToLower(string(planned.Code)) {
			declared = true
			for i, guest := range planned.Guests {
				if i >= 3 {
					break
				}
				if candidateID == region+"-controller-"+guest.ID {
					candidateDeclared = true
				}
			}
			break
		}
	}
	if !declared {
		return nil, errors.New("vmqual: host-control Region is not a canonical declared Region")
	}
	if !candidateDeclared {
		return nil, errors.New("vmqual: host-control candidate is not enrolled in the requested Region")
	}
	options, err := services.authenticatedNATSOptions()
	if err != nil {
		return nil, err
	}
	services.mu.Lock()
	if services.closed || services.nats == nil || services.natsAuthority == nil {
		services.mu.Unlock()
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	identity := services.natsAuthority.commandSigners[candidateID]
	if identity == nil {
		services.mu.Unlock()
		return nil, errors.New("vmqual: host-control command signer missing")
	}
	signer, err := security.ParseCommandSignatureSignerPEM(identity.PrivatePEM)
	if err != nil {
		services.mu.Unlock()
		return nil, err
	}
	owned := false
	defer func() {
		if !owned {
			_ = signer.Close()
		}
	}()
	address := services.nats.ClientURL()
	services.mu.Unlock()
	options = append(options, nats.Timeout(2*time.Second), nats.Name("vmqual-control-"+region))
	connection, err := nats.Connect(address, options...)
	if err != nil {
		return nil, err
	}
	liveAuthority := func(ctx context.Context, host hostcontrol.Host) (delivery.RegionalCommandAuthority, error) {
		lease, err := commandAuthority(ctx, host)
		if err != nil {
			return lease, err
		}
		now := time.Now().UTC()
		if host.Region != strings.ToUpper(region) || lease.AuthorityID != region+"-regional" || lease.CandidateID != candidateID || lease.LeaseID == "" || lease.Epoch <= 0 || lease.DesiredGeneration <= 0 || lease.IssuedAt.IsZero() || now.Before(lease.IssuedAt) || !now.Before(lease.ExpiresAt) {
			return delivery.RegionalCommandAuthority{}, errors.New("vmqual: command signer does not hold live authority for requested Region")
		}
		return lease, nil
	}
	authorize := func(ctx context.Context, host hostcontrol.Host) error { _, err := liveAuthority(ctx, host); return err }
	client, err := hostcontrol.New(hostcontrol.Config{SigningKey: signer, CommandAuthority: liveAuthority, Region: strings.ToUpper(region), Connection: connection, Timeout: 5 * time.Second, Authorize: authorize, ResolveHost: func(ctx context.Context, id string) (hostcontrol.Host, error) {
		host, err := resolve(ctx, id)
		if err != nil {
			return host, err
		}
		if host.NodeID.String() != id || host.Region != strings.ToUpper(region) {
			return hostcontrol.Host{}, errors.New("vmqual: resolved control host differs from requested Region identity")
		}
		factory.activeMu.Lock()
		vm := factory.active[id]
		closed := factory.closed
		factory.activeMu.Unlock()
		if closed || vm == nil || strings.ToLower(string(vm.guest.Region)) != region {
			return hostcontrol.Host{}, errors.New("vmqual: admitted control host has no matching owned guest")
		}
		return host, nil
	}})
	if err != nil {
		connection.Close()
		return nil, err
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed {
		connection.Close()
		return nil, bootstrap.ErrControlRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		connection.Close()
		return nil, err
	}
	if services.controlClients == nil {
		services.controlClients = make(map[string]*hostcontrol.Client)
	}
	if services.controlClients[region] != nil {
		connection.Close()
		return nil, errors.New("vmqual: regional host-control client already bound")
	}
	services.controlClients[region] = client
	services.controlConnections = append(services.controlConnections, connection)
	services.controlSigners = append(services.controlSigners, signer)
	owned = true
	return client, nil
}

// ConfigureQualificationControlRuntime accepts explicit guest-store and pinned
// membership inputs. Root fixture JetStream is forbidden as control storage.
// Callers resolve real lease/stream assignments; this method invents none.
func (factory *firecrackerFactory) ConfigureQualificationControlRuntime(config bootstrap.NATSControlRuntimeConfig, regions []bootstrap.ControlRegionBinding) error {
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed || services.controlRuntime != nil {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	for region, client := range config.Hosts {
		if client == nil || services.controlClients[region] != client {
			return errors.New("vmqual: control runtime requires the owned authenticated regional host-control client")
		}
	}
	owned := make(map[string]string)
	addresses := make(map[string]bool)
	for _, region := range services.plan.Regions {
		for _, guest := range region.Guests {
			owned[guest.ID] = strings.ToLower(string(region.Code))
			addresses[guest.Address] = true
		}
	}
	memberRegions := make(map[string]string)
	for _, member := range config.Members {
		identity := services.natsAuthority.memberships[member.HostID]
		if identity == nil || identity.PublicKey != member.IdentityPublicKey {
			return fmt.Errorf("%w: control member differs from preissued guest membership identity", bootstrap.ErrControlRuntimeUnavailable)
		}
		if memberRegions[member.MemberID] != "" {
			return errors.New("vmqual: repeated control member identity")
		}
		memberRegions[member.MemberID] = member.Region
		if owned[member.HostID] != member.Region {
			return fmt.Errorf("%w: control member has no owned guest", bootstrap.ErrControlRuntimeUnavailable)
		}
	}
	bound := make(map[string]bool)
	boundRegions := make(map[string]bool)
	for _, binding := range regions {
		if binding.Code == "" || boundRegions[binding.Code] || config.Hosts[binding.Code] == nil {
			return errors.New("vmqual: unbound or repeated control Region")
		}
		boundRegions[binding.Code] = true
		for _, member := range binding.MemberIDs {
			if bound[member] || memberRegions[member] != binding.Code {
				return errors.New("vmqual: control binding differs from configured member Region")
			}
			bound[member] = true
		}
	}
	if len(bound) != len(memberRegions) || len(boundRegions) != len(config.Hosts) {
		return errors.New("vmqual: control bindings omit configured members or Regions")
	}
	for _, store := range config.Stores {
		parsed, err := url.Parse(store.URL)
		if err != nil || parsed.Scheme != "tls" || !addresses[parsed.Hostname()] {
			return fmt.Errorf("%w: control store must belong to a guest, never root fixture transport", bootstrap.ErrControlRuntimeUnavailable)
		}
	}
	runtime, err := bootstrap.NewNATSControlRuntime(config)
	if err != nil {
		return err
	}
	// Defensive copies keep suite topology independent of caller slice reuse.
	bindings := append([]bootstrap.ControlRegionBinding(nil), regions...)
	for i := range bindings {
		bindings[i].MemberIDs = append([]string(nil), bindings[i].MemberIDs...)
	}
	services.controlRegions, services.controlRuntime = bindings, runtime
	return nil
}

// QualificationControlRuntime is resolved after guest bootstrap. A running
// root transport is deliberately insufficient for any control-plane proof.
func (factory *firecrackerFactory) QualificationControlRuntime(ctx context.Context) (bootstrap.ControlRuntime, []bootstrap.ControlRegionBinding, error) {
	if ctx == nil {
		return nil, nil, bootstrap.ErrControlRuntimeUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok {
		return nil, nil, bootstrap.ErrControlRuntimeUnavailable
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed || !services.started || services.natsAuthority == nil || services.controlRuntime == nil {
		return nil, nil, fmt.Errorf("%w: actual guest control stores, pinned membership identities, lease authority and action manifests must be configured", bootstrap.ErrControlRuntimeUnavailable)
	}
	bindings := append([]bootstrap.ControlRegionBinding(nil), services.controlRegions...)
	for i := range bindings {
		bindings[i].MemberIDs = append([]string(nil), bindings[i].MemberIDs...)
	}
	return services.controlRuntime, bindings, nil
}
