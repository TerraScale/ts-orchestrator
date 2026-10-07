package manager

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Change is one planned or applied mutation. It never carries secrets.
type Change struct {
	Action string // create, update, rename, delete
	Kind   string
	Name   string
	Detail string
}

func (c Change) String() string {
	line := c.Action + " " + c.Kind + " " + c.Name
	if c.Detail != "" {
		line += " (" + c.Detail + ")"
	}
	return line
}

// Report lists the changes a run planned (dry run) or applied, and findings
// that need an operator but block nothing.
type Report struct {
	Changes  []Change
	Warnings []string
}

type step struct {
	change Change
	apply  func(context.Context, *refs) error
}

// refs resolves desired names to live IDs; objects created during apply
// fill it in for later steps.
type refs struct {
	groups       map[string]string
	network      string
	resource     resourceRef
	routerPeer   string
	serversGroup string
}

func (r *refs) group(name string) (string, error) {
	if id := r.groups[name]; id != "" {
		return id, nil
	}
	return "", fmt.Errorf("NetBird group %s has no ID", name)
}

func (r *refs) groupIDs(names []string) ([]string, error) {
	ids := make([]string, 0, len(names))
	for _, name := range names {
		id, err := r.group(name)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

type plan struct {
	steps    []step
	warnings []string
	refs     refs
	// networkDeferred is set on a fresh account whose router peer has not
	// joined the gateway group yet: the network, its resource and router and
	// the policies targeting the resource wait for a later sync.
	networkDeferred bool
}

func (p *plan) add(change Change, apply func(context.Context, *refs) error) {
	p.steps = append(p.steps, step{change, apply})
}

func (p *plan) warn(format string, args ...any) {
	p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
}

// run applies the plan's steps in order when apply is set. With only, it
// keeps just the changes to those objects; every name must be a planned
// change, so a mistyped one fails instead of doing nothing.
func (p *plan) run(ctx context.Context, apply bool, only []string) (Report, error) {
	report := Report{Warnings: p.warnings}
	for _, name := range only {
		if !slices.ContainsFunc(p.steps, func(s step) bool { return s.change.Name == name }) {
			return report, fmt.Errorf("--only %s: no planned change has that name", name)
		}
	}
	for _, s := range p.steps {
		if len(only) != 0 && !slices.Contains(only, s.change.Name) {
			continue
		}
		if apply {
			if err := s.apply(ctx, &p.refs); err != nil {
				return report, fmt.Errorf("%s: %w", s.change, err)
			}
		}
		report.Changes = append(report.Changes, s.change)
	}
	return report, nil
}

// Sync plans the desired manager state and applies it when apply is set. Any
// refusal (an unexpected router, a different subnet, ambiguous names) fails
// before the first mutation. Names in only limit it to those objects' changes,
// for a desired state that is ahead of another live operation.
func Sync(ctx context.Context, api *API, d Desired, apply bool, only ...string) (Report, error) {
	if err := d.Validate(); err != nil {
		return Report{}, err
	}
	p := &plan{refs: refs{groups: map[string]string{}}}
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return Report{}, err
	}
	if err := p.planGroups(api, d, groups); err != nil {
		return Report{}, err
	}
	var peers []apiPeer
	if err := api.do(ctx, "GET", "/peers", nil, &peers); err != nil {
		return Report{}, err
	}
	if err := p.planNetwork(ctx, api, d, peers); err != nil {
		return Report{}, err
	}
	if err := p.planPolicies(ctx, api, d); err != nil {
		return Report{}, err
	}
	if err := p.planAccount(ctx, api, d); err != nil {
		return Report{}, err
	}
	if err := p.planDNS(ctx, api, d); err != nil {
		return Report{}, err
	}
	if err := p.verifySetupKey(ctx, api, d); err != nil {
		return Report{}, err
	}
	return p.run(ctx, apply, only)
}

// matchName finds the object called name, else exactly one object carrying a
// former name. Several matches are ambiguous and refused.
func matchName[T any](items []T, nameOf func(T) string, name string, former []string, kind string) (*T, error) {
	var current, legacy []int
	for i, item := range items {
		switch n := nameOf(item); {
		case n == name:
			current = append(current, i)
		case slices.Contains(former, n):
			legacy = append(legacy, i)
		}
	}
	switch {
	case len(current) > 1:
		return nil, fmt.Errorf("several NetBird %ss are named %s", kind, name)
	case len(current) == 1:
		return &items[current[0]], nil
	case len(legacy) > 1:
		return nil, fmt.Errorf("several NetBird %ss carry former names of %s", kind, name)
	case len(legacy) == 1:
		return &items[legacy[0]], nil
	}
	return nil, nil
}

func (p *plan) planGroups(api *API, d Desired, groups []apiGroup) error {
	for _, spec := range d.Groups {
		current, err := matchName(groups, func(g apiGroup) string { return g.Name }, spec.Name, spec.RenamedFrom, "group")
		if err != nil {
			return err
		}
		if current == nil {
			p.add(Change{"create", "group", spec.Name, ""}, func(ctx context.Context, r *refs) error {
				var out created
				if err := api.do(ctx, "POST", "/groups", groupRequest{Name: spec.Name, Peers: []string{}, Resources: []resourceRef{}}, &out); err != nil {
					return err
				}
				if out.ID == "" {
					return errors.New("manager returned no group ID")
				}
				r.groups[spec.Name] = out.ID
				return nil
			})
			continue
		}
		p.refs.groups[spec.Name] = current.ID
		if current.Name == spec.Name {
			continue
		}
		id, old := current.ID, current.Name
		p.add(Change{"rename", "group", spec.Name, "from " + old}, func(ctx context.Context, _ *refs) error {
			// A group PUT replaces membership: send the live peers and
			// resources back unchanged.
			var live apiGroup
			if err := api.do(ctx, "GET", "/groups/"+id, nil, &live); err != nil {
				return err
			}
			if live.Name != old {
				return errors.New("group changed since planning")
			}
			peers := make([]string, 0, len(live.Peers))
			for _, peer := range live.Peers {
				peers = append(peers, peer.ID)
			}
			resources := live.Resources
			if resources == nil {
				resources = []resourceRef{}
			}
			return api.do(ctx, "PUT", "/groups/"+id, groupRequest{Name: spec.Name, Peers: peers, Resources: resources}, nil)
		})
	}
	return nil
}

func hasGroup(groups []groupMinimum, id string) bool {
	return id != "" && slices.ContainsFunc(groups, func(g groupMinimum) bool { return g.ID == id })
}

func (p *plan) planNetwork(ctx context.Context, api *API, d Desired, peers []apiPeer) error {
	spec := d.Network
	var networks []apiNetwork
	if err := api.do(ctx, "GET", "/networks", nil, &networks); err != nil {
		return err
	}
	network, err := matchName(networks, func(n apiNetwork) string { return n.Name }, spec.Name, nil, "network")
	if err != nil {
		return err
	}
	// The router peer must already be in the gateway group.
	gateway := p.refs.groups[spec.RouterGroup]
	var routers []apiPeer
	for _, peer := range peers {
		if peer.Name == spec.RouterPeer && hasGroup(peer.Groups, gateway) {
			routers = append(routers, peer)
		}
	}
	if len(routers) == 0 && network == nil {
		// Fresh account: the gateway group may only be planned. Create the
		// groups and other policies now; an operator adds the router peer to
		// the group and the next sync creates the network.
		p.networkDeferred = true
		p.warn("network %s deferred: add peer %s to group %s, then sync again", spec.Name, spec.RouterPeer, spec.RouterGroup)
		return nil
	}
	if len(routers) != 1 {
		return fmt.Errorf("refusing NetBird network sync: expected exactly one peer named %s in group %s, found %d",
			spec.RouterPeer, spec.RouterGroup, len(routers))
	}
	p.refs.routerPeer = routers[0].ID
	var resources []apiResource
	var routerRows []apiRouter
	if network == nil {
		p.add(Change{"create", "network", spec.Name, ""}, func(ctx context.Context, r *refs) error {
			var out created
			if err := api.do(ctx, "POST", "/networks", networkRequest{spec.Name, spec.Description}, &out); err != nil {
				return err
			}
			if out.ID == "" {
				return errors.New("manager returned no network ID")
			}
			r.network = out.ID
			return nil
		})
	} else {
		p.refs.network = network.ID
		if network.Description != spec.Description {
			id := network.ID
			p.add(Change{"update", "network", spec.Name, "description"}, func(ctx context.Context, _ *refs) error {
				return api.do(ctx, "PUT", "/networks/"+id, networkRequest{spec.Name, spec.Description}, nil)
			})
		}
		if err := api.do(ctx, "GET", "/networks/"+network.ID+"/resources", nil, &resources); err != nil {
			return err
		}
		if err := api.do(ctx, "GET", "/networks/"+network.ID+"/routers", nil, &routerRows); err != nil {
			return err
		}
	}
	if err := p.planResource(api, spec.Resource, resources); err != nil {
		return err
	}
	return p.planRouter(api, spec, routerRows)
}

func (p *plan) planResource(api *API, spec ResourceSpec, resources []apiResource) error {
	resource, err := matchName(resources, func(r apiResource) string { return r.Name }, spec.Name, spec.RenamedFrom, "network resource")
	if err != nil {
		return err
	}
	for _, other := range resources {
		if resource != nil && other.ID == resource.ID {
			continue
		}
		if other.Address == spec.Address {
			return fmt.Errorf("refusing NetBird network sync: resource %s already routes %s", other.Name, spec.Address)
		}
		p.warn("network resource %s (%s) is not managed and was left alone", other.Name, other.Address)
	}
	if resource == nil {
		p.add(Change{"create", "network resource", spec.Name, spec.Address}, func(ctx context.Context, r *refs) error {
			var out apiResource
			if err := api.do(ctx, "POST", "/networks/"+r.network+"/resources", resourceRequest{
				Name: spec.Name, Description: spec.Description, Address: spec.Address, Enabled: true, Groups: []string{},
			}, &out); err != nil {
				return err
			}
			if out.ID == "" || out.Type == "" {
				return errors.New("manager returned no network resource ID")
			}
			r.resource = resourceRef{out.ID, out.Type}
			return nil
		})
		return nil
	}
	if resource.Address != spec.Address {
		return fmt.Errorf("refusing NetBird network sync: resource %s routes %s, not %s", resource.Name, resource.Address, spec.Address)
	}
	if resource.Type != "subnet" {
		return fmt.Errorf("refusing NetBird network sync: resource %s has type %s, not subnet", resource.Name, resource.Type)
	}
	p.refs.resource = resourceRef{resource.ID, resource.Type}
	var diff []string
	if resource.Name != spec.Name {
		diff = append(diff, "from "+resource.Name)
	}
	if resource.Description != spec.Description {
		diff = append(diff, "description")
	}
	if !resource.Enabled {
		diff = append(diff, "enable")
	}
	if len(diff) == 0 {
		return nil
	}
	action := "update"
	if resource.Name != spec.Name {
		action = "rename"
	}
	id := resource.ID
	// Resource groups are not managed (no policy targets them): keep them.
	groups := make([]string, 0, len(resource.Groups))
	for _, g := range resource.Groups {
		groups = append(groups, g.ID)
	}
	p.add(Change{action, "network resource", spec.Name, strings.Join(diff, ", ")}, func(ctx context.Context, r *refs) error {
		return api.do(ctx, "PUT", "/networks/"+r.network+"/resources/"+id, resourceRequest{
			Name: spec.Name, Description: spec.Description, Address: spec.Address, Enabled: true, Groups: groups,
		}, nil)
	})
	return nil
}

func (p *plan) planRouter(api *API, spec NetworkSpec, routers []apiRouter) error {
	label := spec.Name + "/" + spec.RouterPeer
	desired := routerRequest{Metric: spec.Metric, Masquerade: spec.Masquerade, Enabled: true}
	switch {
	case len(routers) == 0:
		p.add(Change{"create", "network router", label, ""}, func(ctx context.Context, r *refs) error {
			request := desired
			request.Peer = r.routerPeer
			return api.do(ctx, "POST", "/networks/"+r.network+"/routers", request, nil)
		})
		return nil
	case len(routers) > 1 || routers[0].Peer != p.refs.routerPeer || len(routers[0].PeerGroups) != 0:
		return fmt.Errorf("refusing NetBird network sync: network %s has an unexpected router", spec.Name)
	}
	router := routers[0]
	if router.Metric == spec.Metric && router.Masquerade == spec.Masquerade && router.Enabled {
		return nil
	}
	id := router.ID
	p.add(Change{"update", "network router", label, "masquerade, metric or enabled"}, func(ctx context.Context, r *refs) error {
		request := desired
		request.Peer = r.routerPeer
		return api.do(ctx, "PUT", "/networks/"+r.network+"/routers/"+id, request, nil)
	})
	return nil
}

func (p *plan) planPolicies(ctx context.Context, api *API, d Desired) error {
	var policies []apiPolicy
	if err := api.do(ctx, "GET", "/policies", nil, &policies); err != nil {
		return err
	}
	managed := map[string]bool{}
	for _, spec := range d.Policies {
		current, err := matchName(policies, func(p apiPolicy) string { return p.Name }, spec.Name, spec.RenamedFrom, "policy")
		if err != nil {
			return err
		}
		if current != nil {
			managed[current.ID] = true
		}
		if spec.DestinationResource != "" && p.networkDeferred {
			p.warn("policy %s deferred until network resource %s exists", spec.Name, spec.DestinationResource)
			continue
		}
		build := func(r *refs, current *apiPolicy) (policyRequest, error) {
			rule := ruleRequest{Name: spec.Name, Description: spec.Description, Enabled: true, Action: "accept",
				Protocol: spec.Protocol, Ports: spec.Ports}
			var err error
			if rule.Sources, err = r.groupIDs(spec.Sources); err != nil {
				return policyRequest{}, err
			}
			if spec.DestinationResource != "" {
				if r.resource.ID == "" {
					return policyRequest{}, errors.New("network resource has no ID")
				}
				resource := r.resource
				rule.DestinationResource = &resource
			} else if rule.Destinations, err = r.groupIDs(spec.Destinations); err != nil {
				return policyRequest{}, err
			}
			request := policyRequest{Name: spec.Name, Description: spec.Description, Enabled: true,
				Rules: []ruleRequest{rule}, SourcePostureChecks: []string{}}
			if current != nil {
				if current.SourcePostureChecks != nil {
					request.SourcePostureChecks = current.SourcePostureChecks
				}
				if len(current.Rules) > 0 {
					request.Rules[0].ID = current.Rules[0].ID
					request.Rules[0].AuthorizedGroups = current.Rules[0].AuthorizedGroups
				}
			}
			return request, nil
		}
		if current == nil {
			p.add(Change{"create", "policy", spec.Name, ""}, func(ctx context.Context, r *refs) error {
				request, err := build(r, nil)
				if err != nil {
					return err
				}
				return api.do(ctx, "POST", "/policies", request, nil)
			})
			continue
		}
		diff := policyDiff(*current, spec, &p.refs)
		if len(diff) == 0 {
			continue
		}
		action := "update"
		if current.Name != spec.Name {
			action = "rename"
			diff = append([]string{"from " + current.Name}, diff...)
		}
		snapshot := *current
		p.add(Change{action, "policy", spec.Name, strings.Join(diff, ", ")}, func(ctx context.Context, r *refs) error {
			request, err := build(r, &snapshot)
			if err != nil {
				return err
			}
			return api.do(ctx, "PUT", "/policies/"+snapshot.ID, request, nil)
		})
	}
	// Policies are never deleted here, but an unmanaged one (such as the
	// default All policy) grants access outside the desired state.
	for _, policy := range policies {
		if !managed[policy.ID] {
			p.warn("policy %s is not in the desired state of cell %s", policy.Name, d.Cell)
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

func minimumIDs(groups []groupMinimum) []string {
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	return ids
}

func policyDiff(current apiPolicy, spec PolicySpec, r *refs) []string {
	var diff []string
	if len(current.Rules) == 1 && current.Rules[0].Name != spec.Name {
		diff = append(diff, "rule name")
	}
	if current.Description != spec.Description {
		diff = append(diff, "description")
	}
	if !current.Enabled {
		diff = append(diff, "enable")
	}
	if len(current.Rules) != 1 {
		return append(diff, fmt.Sprintf("%d rules -> 1", len(current.Rules)))
	}
	rule := current.Rules[0]
	if rule.Description != spec.Description {
		diff = append(diff, "rule description")
	}
	if !rule.Enabled || rule.Action != "accept" {
		diff = append(diff, "rule enabled/action")
	}
	if rule.Bidirectional {
		diff = append(diff, "one-way")
	}
	if rule.Protocol != spec.Protocol {
		diff = append(diff, "protocol")
	}
	if !sameSet(rule.Ports, spec.Ports) || len(rule.PortRanges) != 0 {
		diff = append(diff, "ports")
	}
	sources, err := r.groupIDs(spec.Sources)
	if err != nil || !sameSet(minimumIDs(rule.Sources), sources) || rule.SourceResource != nil {
		diff = append(diff, "sources")
	}
	if spec.DestinationResource != "" {
		if rule.DestinationResource == nil || *rule.DestinationResource != r.resource || len(rule.Destinations) != 0 {
			diff = append(diff, "destination")
		}
	} else {
		destinations, err := r.groupIDs(spec.Destinations)
		if err != nil || !sameSet(minimumIDs(rule.Destinations), destinations) || rule.DestinationResource != nil {
			diff = append(diff, "destinations")
		}
	}
	return diff
}

func rawString(settings map[string]jsontext.Value, name string) string {
	var value string
	if raw, ok := settings[name]; ok {
		_ = json.Unmarshal(raw, &value)
	}
	return value
}

func (p *plan) planAccount(ctx context.Context, api *API, d Desired) error {
	var accounts []apiAccount
	if err := api.do(ctx, "GET", "/accounts", nil, &accounts); err != nil {
		return err
	}
	if len(accounts) != 1 || accounts[0].ID == "" || accounts[0].Settings == nil {
		return errors.New("NetBird manager must expose exactly one account")
	}
	settings := accounts[0].Settings
	var diff []string
	if rawString(settings, "network_range") != d.NetworkRange {
		diff = append(diff, "network_range "+d.NetworkRange+", re-addresses every peer")
	}
	if rawString(settings, "dns_domain") != d.PeerDNSDomain {
		diff = append(diff, "dns_domain "+d.PeerDNSDomain)
	}
	if len(diff) == 0 {
		return nil
	}
	id := accounts[0].ID
	p.add(Change{"update", "account settings", id, strings.Join(diff, "; ")}, func(ctx context.Context, _ *refs) error {
		// The account PUT replaces every setting: re-read and change only
		// the managed members.
		var live []apiAccount
		if err := api.do(ctx, "GET", "/accounts", nil, &live); err != nil {
			return err
		}
		if len(live) != 1 || live[0].ID != id || live[0].Settings == nil {
			return errors.New("account changed since planning")
		}
		settings := live[0].Settings
		for name, value := range map[string]string{"network_range": d.NetworkRange, "dns_domain": d.PeerDNSDomain} {
			wire, err := json.Marshal(value)
			if err != nil {
				return err
			}
			settings[name] = wire
		}
		return api.do(ctx, "PUT", "/accounts/"+id, accountRequest{Settings: settings, Onboarding: live[0].Onboarding}, nil)
	})
	return nil
}

func (p *plan) planDNS(ctx context.Context, api *API, d Desired) error {
	var settings dnsSettings
	if err := api.do(ctx, "GET", "/dns/settings", nil, &settings); err != nil {
		return err
	}
	disabled, err := p.refs.groupIDs(d.DNSDisabledGroups)
	if err != nil || !sameSet(settings.DisabledManagementGroups, disabled) {
		p.add(Change{"update", "dns settings", "disabled_management_groups", strings.Join(d.DNSDisabledGroups, ",")},
			func(ctx context.Context, r *refs) error {
				ids, err := r.groupIDs(d.DNSDisabledGroups)
				if err != nil {
					return err
				}
				return api.do(ctx, "PUT", "/dns/settings", dnsSettings{ids}, nil)
			})
	}
	return p.planZone(ctx, api, d)
}

func (p *plan) planZone(ctx context.Context, api *API, d Desired) error {
	spec := d.Zone
	var zones []apiZone
	if err := api.do(ctx, "GET", "/dns/zones", nil, &zones); err != nil {
		return err
	}
	var matches []apiZone
	for _, zone := range zones {
		if zone.Name == spec.Name || zone.Domain == spec.Domain {
			matches = append(matches, zone)
		}
	}
	if len(matches) > 1 {
		return fmt.Errorf("several NetBird DNS zones match %s or %s", spec.Name, spec.Domain)
	}
	request := func(r *refs) (zoneRequest, error) {
		groups, err := r.groupIDs(spec.DistributionGroups)
		return zoneRequest{Name: spec.Name, Domain: spec.Domain, Enabled: true, EnableSearchDomain: false,
			DistributionGroups: groups}, err
	}
	zoneID := new(string)
	var records []apiRecord
	if len(matches) == 0 {
		p.add(Change{"create", "dns zone", spec.Name, spec.Domain}, func(ctx context.Context, r *refs) error {
			body, err := request(r)
			if err != nil {
				return err
			}
			var out created
			if err := api.do(ctx, "POST", "/dns/zones", body, &out); err != nil {
				return err
			}
			if out.ID == "" {
				return errors.New("manager returned no zone ID")
			}
			*zoneID = out.ID
			return nil
		})
	} else {
		zone := matches[0]
		*zoneID = zone.ID
		groups, err := p.refs.groupIDs(spec.DistributionGroups)
		var diff []string
		if zone.Name != spec.Name {
			diff = append(diff, "name")
		}
		if zone.Domain != spec.Domain {
			diff = append(diff, "domain")
		}
		if err != nil || !sameSet(zone.DistributionGroups, groups) {
			diff = append(diff, "distribution groups")
		}
		if !zone.Enabled || zone.EnableSearchDomain {
			diff = append(diff, "enabled/search domain")
		}
		if len(diff) > 0 {
			p.add(Change{"update", "dns zone", spec.Name, strings.Join(diff, ", ")}, func(ctx context.Context, r *refs) error {
				body, err := request(r)
				if err != nil {
					return err
				}
				return api.do(ctx, "PUT", "/dns/zones/"+*zoneID, body, nil)
			})
		}
		if err := api.do(ctx, "GET", "/dns/zones/"+zone.ID+"/records", nil, &records); err != nil {
			return err
		}
	}
	p.planRecords(api, d, zoneID, records)
	return nil
}

// planRecords owns the whole zone: missing records are created, extra ones
// deleted and TTLs corrected.
func (p *plan) planRecords(api *API, d Desired, zoneID *string, records []apiRecord) {
	wanted := map[Record]bool{}
	for _, record := range d.Records() {
		wanted[record] = true
	}
	matched := map[Record]bool{}
	for _, record := range records {
		key := Record{record.Name, record.Content}
		label := record.Name + " " + record.Type + " " + record.Content
		if record.Type != "A" || !wanted[key] || matched[key] {
			id := record.ID
			p.add(Change{"delete", "dns record", label, ""}, func(ctx context.Context, _ *refs) error {
				return api.do(ctx, "DELETE", "/dns/zones/"+*zoneID+"/records/"+id, nil, nil)
			})
			continue
		}
		matched[key] = true
		if record.TTL != d.Zone.TTL {
			id := record.ID
			p.add(Change{"update", "dns record", label, fmt.Sprintf("ttl %d", d.Zone.TTL)}, func(ctx context.Context, _ *refs) error {
				return api.do(ctx, "PUT", "/dns/zones/"+*zoneID+"/records/"+id,
					recordRequest{Name: key.Name, Type: "A", Content: key.Content, TTL: d.Zone.TTL}, nil)
			})
		}
	}
	for _, record := range d.Records() {
		if matched[record] {
			continue
		}
		p.add(Change{"create", "dns record", record.Name + " A " + record.Content, ""}, func(ctx context.Context, _ *refs) error {
			return api.do(ctx, "POST", "/dns/zones/"+*zoneID+"/records",
				recordRequest{Name: record.Name, Type: "A", Content: record.Content, TTL: d.Zone.TTL}, nil)
		})
	}
}

// verifySetupKey only reports: the server setup key is never created,
// renamed or rotated here.
func (p *plan) verifySetupKey(ctx context.Context, api *API, d Desired) error {
	var keys []apiSetupKey
	if err := api.do(ctx, "GET", "/setup-keys", nil, &keys); err != nil {
		return err
	}
	// A rotation leaves the superseded key revoked under the same name; only
	// unrevoked keys can enroll servers.
	var found []apiSetupKey
	for _, key := range keys {
		if key.Name == d.SetupKeyName && !key.Revoked {
			found = append(found, key)
		}
	}
	if len(found) != 1 {
		p.warn("expected one unrevoked setup key named %s, found %d", d.SetupKeyName, len(found))
		return nil
	}
	key := found[0]
	servers := p.refs.groups[d.ServersGroup]
	if !key.Valid || key.Revoked || key.State != "valid" || key.Type != "reusable" {
		p.warn("setup key %s is not a valid reusable key (state %s, revoked %t)", key.Name, key.State, key.Revoked)
	}
	// Any other auto-group would hand every enrolled server, and anyone who
	// reads the key from Vault, that group's access.
	if servers == "" || !slices.Equal(key.AutoGroups, []string{servers}) {
		p.warn("setup key %s must auto-assign only group %s", key.Name, d.ServersGroup)
	}
	return nil
}
