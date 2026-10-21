package manager

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPAT = "nbp_abcdefghijklmnopqrstuvwxyzABCD012345"

type fakePeer struct {
	apiPeer
}

type fakeZone struct {
	apiZone
	records []apiRecord
}

type fakeNetwork struct {
	apiNetwork
	resources []apiResource
	routers   []apiRouter
}

// fakeManager models the NetBird 0.80 REST behaviour this package relies on:
// a group PUT replaces membership, the account PUT replaces all settings, and
// a peer rename recomputes its DNS label only when the name changes.
type fakeManager struct {
	t          *testing.T
	mu         sync.Mutex
	next       int
	groups     []apiGroup
	peers      []*fakePeer
	policies   []apiPolicy
	networks   []*fakeNetwork
	account    map[string]jsontext.Value
	dnsGroups  []string
	zones      []*fakeZone
	setupKeys  []map[string]any
	mutations  []string
	server     *httptest.Server
	dnsDomain  string
	failStatus int
}

func newFakeManager(t *testing.T) *fakeManager {
	f := &fakeManager{t: t, dnsDomain: "netbird.selfhosted", account: map[string]jsontext.Value{
		"network_range":                 jsontext.Value(`"10.200.0.0/16"`),
		"peer_login_expiration_enabled": jsontext.Value(`false`),
		"lazy_connection_enabled":       jsontext.Value(`true`),
		"extra":                         jsontext.Value(`{"user_approval_required":false}`),
	}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeManager) id(prefix string) string {
	f.next++
	return fmt.Sprintf("%s%03d", prefix, f.next)
}

func (f *fakeManager) api(t *testing.T) *API {
	api, err := NewAPI(f.server.URL, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(api.Close)
	return api
}

func (f *fakeManager) addGroup(name string) string {
	id := f.id("g")
	f.groups = append(f.groups, apiGroup{ID: id, Name: name, Issued: "api", Peers: []groupMinimum{}, Resources: []resourceRef{}})
	return id
}

func (f *fakeManager) group(id string) *apiGroup {
	for i := range f.groups {
		if f.groups[i].ID == id {
			return &f.groups[i]
		}
	}
	return nil
}

func (f *fakeManager) groupByName(name string) *apiGroup {
	for i := range f.groups {
		if f.groups[i].Name == name {
			return &f.groups[i]
		}
	}
	return nil
}

func (f *fakeManager) addPeer(name, connectionIP string, connected bool, lastSeen time.Time, groups ...string) string {
	id := f.id("p")
	label := f.freeLabel(name, fmt.Sprintf("100.64.0.%d", f.next))
	peer := &fakePeer{apiPeer{ID: id, Name: name, Hostname: name, IP: fmt.Sprintf("10.200.0.%d", f.next),
		ConnectionIP: connectionIP, DNSLabel: label, Connected: connected, LastSeen: lastSeen, SSHEnabled: true}}
	f.peers = append(f.peers, peer)
	for _, g := range groups {
		group := f.group(g)
		group.Peers = append(group.Peers, groupMinimum{ID: id, Name: name})
	}
	return id
}

func (f *fakeManager) freeLabel(name, ip string) string {
	for _, peer := range f.peers {
		if strings.SplitN(peer.DNSLabel, ".", 2)[0] == name {
			parts := strings.Split(ip, ".")
			return name + "-" + parts[2] + "-" + parts[3] + "." + f.dnsDomain
		}
	}
	return name + "." + f.dnsDomain
}

func (f *fakeManager) peer(id string) *fakePeer {
	for _, peer := range f.peers {
		if peer.ID == id {
			return peer
		}
	}
	return nil
}

func (f *fakeManager) peerView(peer *fakePeer) apiPeer {
	view := peer.apiPeer
	view.Groups = nil
	for _, group := range f.groups {
		if slices.ContainsFunc(group.Peers, func(p groupMinimum) bool { return p.ID == peer.ID }) {
			view.Groups = append(view.Groups, groupMinimum{group.ID, group.Name})
		}
	}
	return view
}

func (f *fakeManager) network(id string) *fakeNetwork {
	for _, network := range f.networks {
		if network.ID == id {
			return network
		}
	}
	return nil
}

func (f *fakeManager) groupMinimums(ids []string) []groupMinimum {
	var out []groupMinimum
	for _, id := range ids {
		if group := f.group(id); group != nil {
			out = append(out, groupMinimum{id, group.Name})
		} else {
			f.t.Errorf("unknown group %s", id)
		}
	}
	return out
}

func (f *fakeManager) policyFrom(id string, request policyRequest) apiPolicy {
	policy := apiPolicy{ID: id, Name: request.Name, Description: request.Description, Enabled: request.Enabled,
		SourcePostureChecks: request.SourcePostureChecks}
	for _, rule := range request.Rules {
		ruleID := rule.ID
		if ruleID == "" {
			ruleID = f.id("r")
		}
		policy.Rules = append(policy.Rules, apiRule{ID: ruleID, Name: rule.Name, Description: rule.Description,
			Enabled: rule.Enabled, Action: rule.Action, Bidirectional: rule.Bidirectional, Protocol: rule.Protocol,
			Ports: rule.Ports, Sources: f.groupMinimums(rule.Sources), Destinations: f.groupMinimums(rule.Destinations),
			DestinationResource: rule.DestinationResource, AuthorizedGroups: rule.AuthorizedGroups})
	}
	return policy
}

func (f *fakeManager) write(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.MarshalWrite(w, value); err != nil {
		f.t.Error(err)
	}
}

func (f *fakeManager) read(r *http.Request, value any) bool {
	if err := json.UnmarshalRead(r.Body, value, json.RejectUnknownMembers(true)); err != nil {
		f.t.Errorf("%s %s: request does not match the 0.80 schema: %v", r.Method, r.URL.Path, err)
		return false
	}
	return true
}

func (f *fakeManager) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Token "+testPAT {
		http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if f.failStatus != 0 {
		http.Error(w, `{"message":"secret-ish body that must not leak"}`, f.failStatus)
		return
	}
	path := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	if r.Method != http.MethodGet {
		f.mutations = append(f.mutations, r.Method+" "+strings.Join(path, "/"))
	}
	segments := slices.Clone(path)
	first := 1
	if segments[0] == "dns" {
		first = 2
	}
	for i := first; i < len(segments); i += 2 {
		segments[i] = "*"
	}
	route := r.Method + " " + strings.Join(segments, "/")
	notFound := func() { http.Error(w, `{"message":"not found"}`, http.StatusNotFound) }
	switch route {
	case "GET groups":
		f.write(w, f.groups)
	case "GET groups/*":
		if group := f.group(path[1]); group != nil {
			f.write(w, group)
		} else {
			notFound()
		}
	case "POST groups":
		var request groupRequest
		if f.read(r, &request) {
			id := f.addGroup(request.Name)
			f.write(w, f.group(id))
		}
	case "PUT groups/*":
		var request struct {
			Name      string         `json:"name"`
			Peers     *[]string      `json:"peers"`
			Resources *[]resourceRef `json:"resources"`
		}
		group := f.group(path[1])
		if group == nil || !f.read(r, &request) {
			notFound()
			return
		}
		group.Name = request.Name
		group.Peers = []groupMinimum{}
		if request.Peers != nil {
			for _, id := range *request.Peers {
				group.Peers = append(group.Peers, groupMinimum{id, f.peer(id).Name})
			}
		}
		group.Resources = []resourceRef{}
		if request.Resources != nil {
			group.Resources = *request.Resources
		}
		f.write(w, group)
	case "GET peers":
		var out []apiPeer
		for _, peer := range f.peers {
			out = append(out, f.peerView(peer))
		}
		f.write(w, out)
	case "PUT peers/*":
		var request peerRequest
		peer := f.peer(path[1])
		if peer == nil || !f.read(r, &request) {
			notFound()
			return
		}
		if request.Name != peer.Name {
			peer.DNSLabel = ""
			peer.DNSLabel = f.freeLabel(request.Name, peer.IP)
			peer.Name = request.Name
		}
		peer.SSHEnabled = request.SSHEnabled
		f.write(w, f.peerView(peer))
	case "DELETE peers/*":
		index := slices.IndexFunc(f.peers, func(p *fakePeer) bool { return p.ID == path[1] })
		if index < 0 {
			notFound()
			return
		}
		f.peers = slices.Delete(f.peers, index, index+1)
		for i := range f.groups {
			f.groups[i].Peers = slices.DeleteFunc(f.groups[i].Peers, func(p groupMinimum) bool { return p.ID == path[1] })
		}
	case "GET policies":
		f.write(w, f.policies)
	case "POST policies":
		var request policyRequest
		if f.read(r, &request) {
			policy := f.policyFrom(f.id("pol"), request)
			f.policies = append(f.policies, policy)
			f.write(w, policy)
		}
	case "PUT policies/*":
		var request policyRequest
		index := slices.IndexFunc(f.policies, func(p apiPolicy) bool { return p.ID == path[1] })
		if index < 0 || !f.read(r, &request) {
			notFound()
			return
		}
		f.policies[index] = f.policyFrom(path[1], request)
		f.write(w, f.policies[index])
	case "GET networks":
		var out []apiNetwork
		for _, network := range f.networks {
			out = append(out, network.apiNetwork)
		}
		f.write(w, out)
	case "POST networks":
		var request networkRequest
		if f.read(r, &request) {
			network := &fakeNetwork{apiNetwork: apiNetwork{ID: f.id("n"), Name: request.Name, Description: request.Description}}
			f.networks = append(f.networks, network)
			f.write(w, network.apiNetwork)
		}
	case "PUT networks/*":
		var request networkRequest
		network := f.network(path[1])
		if network == nil || !f.read(r, &request) {
			notFound()
			return
		}
		network.Name, network.Description = request.Name, request.Description
		f.write(w, network.apiNetwork)
	case "GET networks/*/resources":
		f.write(w, f.network(path[1]).resources)
	case "POST networks/*/resources", "PUT networks/*/resources/*":
		var request resourceRequest
		network := f.network(path[1])
		if network == nil || !f.read(r, &request) {
			notFound()
			return
		}
		resource := apiResource{Name: request.Name, Description: request.Description, Address: request.Address,
			Enabled: request.Enabled, Type: "subnet", Groups: f.groupMinimums(request.Groups)}
		if r.Method == http.MethodPost {
			resource.ID = f.id("res")
			network.resources = append(network.resources, resource)
		} else {
			index := slices.IndexFunc(network.resources, func(x apiResource) bool { return x.ID == path[3] })
			resource.ID = path[3]
			network.resources[index] = resource
		}
		f.write(w, resource)
	case "GET networks/*/routers":
		f.write(w, f.network(path[1]).routers)
	case "POST networks/*/routers", "PUT networks/*/routers/*":
		var request routerRequest
		network := f.network(path[1])
		if network == nil || !f.read(r, &request) {
			notFound()
			return
		}
		router := apiRouter{Peer: request.Peer, Metric: request.Metric, Masquerade: request.Masquerade, Enabled: request.Enabled}
		if r.Method == http.MethodPost {
			router.ID = f.id("rt")
			network.routers = append(network.routers, router)
		} else {
			index := slices.IndexFunc(network.routers, func(x apiRouter) bool { return x.ID == path[3] })
			router.ID = path[3]
			network.routers[index] = router
		}
		f.write(w, router)
	case "GET accounts":
		f.write(w, []map[string]any{{"id": "acct", "settings": f.account, "onboarding": map[string]bool{"onboarding_flow_pending": false}}})
	case "PUT accounts/*":
		var request struct {
			Settings   map[string]jsontext.Value `json:"settings"`
			Onboarding jsontext.Value            `json:"onboarding"`
		}
		if path[1] != "acct" || !f.read(r, &request) {
			notFound()
			return
		}
		f.account = request.Settings
		var domain string
		_ = json.Unmarshal(f.account["dns_domain"], &domain)
		if domain != "" {
			f.dnsDomain = domain
		}
		f.write(w, map[string]any{"id": "acct", "settings": f.account})
	case "GET dns/settings":
		f.write(w, dnsSettings{append([]string{}, f.dnsGroups...)})
	case "PUT dns/settings":
		var request dnsSettings
		if f.read(r, &request) {
			f.dnsGroups = request.DisabledManagementGroups
			f.write(w, request)
		}
	case "GET dns/zones":
		var out []apiZone
		for _, zone := range f.zones {
			out = append(out, zone.apiZone)
		}
		f.write(w, out)
	case "POST dns/zones", "PUT dns/zones/*":
		var request zoneRequest
		if !f.read(r, &request) {
			return
		}
		zone := apiZone{Name: request.Name, Domain: request.Domain, Enabled: request.Enabled,
			EnableSearchDomain: request.EnableSearchDomain, DistributionGroups: request.DistributionGroups}
		if r.Method == http.MethodPost {
			zone.ID = f.id("z")
			f.zones = append(f.zones, &fakeZone{apiZone: zone})
		} else {
			zone.ID = path[2]
			for _, z := range f.zones {
				if z.ID == zone.ID {
					z.apiZone = zone
				}
			}
		}
		f.write(w, zone)
	case "GET setup-keys":
		f.write(w, f.setupKeys)
	case "POST setup-keys":
		var request setupKeyRequest
		if f.read(r, &request) {
			key := map[string]any{"id": f.id("sk"), "name": request.Name, "key": "NEW-SECRET-SETUP-KEY",
				"type": request.Type, "state": "valid", "valid": true, "revoked": false,
				"auto_groups": request.AutoGroups, "ephemeral": request.Ephemeral, "usage_limit": request.UsageLimit,
				"expires_in": request.ExpiresIn}
			f.setupKeys = append(f.setupKeys, key)
			f.write(w, key)
		}
	case "GET dns/zones/*/records", "POST dns/zones/*/records", "PUT dns/zones/*/records/*", "DELETE dns/zones/*/records/*":
		f.serveRecords(w, r, path)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		notFound()
	}
}

func (f *fakeManager) serveRecords(w http.ResponseWriter, r *http.Request, path []string) {
	var zone *fakeZone
	for _, z := range f.zones {
		if z.ID == path[2] {
			zone = z
		}
	}
	if zone == nil {
		http.Error(w, `{}`, http.StatusNotFound)
		return
	}
	switch {
	case r.Method == http.MethodGet && len(path) == 4:
		f.write(w, zone.records)
	case r.Method == http.MethodPost && len(path) == 4:
		var request recordRequest
		if f.read(r, &request) {
			record := apiRecord{ID: f.id("rec"), Name: request.Name, Type: request.Type, Content: request.Content, TTL: request.TTL}
			zone.records = append(zone.records, record)
			f.write(w, record)
		}
	case r.Method == http.MethodPut && len(path) == 5:
		var request recordRequest
		if f.read(r, &request) {
			index := slices.IndexFunc(zone.records, func(x apiRecord) bool { return x.ID == path[4] })
			zone.records[index] = apiRecord{ID: path[4], Name: request.Name, Type: request.Type, Content: request.Content, TTL: request.TTL}
			f.write(w, zone.records[index])
		}
	case r.Method == http.MethodDelete && len(path) == 5:
		zone.records = slices.DeleteFunc(zone.records, func(x apiRecord) bool { return x.ID == path[4] })
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
	}
}

// legacyShape seeds the production objects admin.py left behind.
type legacyIDs struct {
	operators, gateway, servers  string
	network, resource, router    string
	opsPorts, ssh, forgejo, ping string
	tsOps, server1, operator1    string
}

func (f *fakeManager) seedLegacy(t *testing.T) legacyIDs {
	t.Helper()
	var ids legacyIDs
	ids.operators = f.addGroup("operators")
	ids.gateway = f.addGroup("gateway")
	ids.servers = f.addGroup("ts-orch-servers")
	now := time.Now()
	ids.tsOps = f.addPeer("ts-ops", "10.250.10.155", true, now, ids.gateway)
	ids.server1 = f.addPeer("ts-gru-1", "10.251.0.11", true, now, ids.servers)
	ids.operator1 = f.addPeer("laptop", "203.0.113.7", true, now, ids.operators)
	ids.network, ids.resource, ids.router = "n-legacy", "res-legacy", "rt-legacy"
	f.networks = append(f.networks, &fakeNetwork{
		apiNetwork: apiNetwork{ID: ids.network, Name: "gru-cell", Description: "TerraScale GRU private cell"},
		resources: []apiResource{{ID: ids.resource, Name: "gru-cell", Description: "TerraScale GRU private subnet",
			Address: "10.251.0.0/25", Type: "subnet", Enabled: true, Groups: []groupMinimum{}}},
		routers: []apiRouter{{ID: ids.router, Peer: ids.tsOps, Metric: 100, Masquerade: true, Enabled: true}},
	})
	add := func(name string, rule ruleRequest) string {
		id := f.id("pol")
		f.policies = append(f.policies, f.policyFrom(id, policyRequest{Name: name, Enabled: true,
			SourcePostureChecks: []string{}, Rules: []ruleRequest{rule}}))
		return id
	}
	ids.opsPorts = add("operators-to-gru-cell", ruleRequest{Name: "operators-to-gru-cell", Enabled: true, Action: "accept",
		Protocol: "tcp", Ports: []string{"22", "4222", "9465"}, Sources: []string{ids.operators},
		DestinationResource: &resourceRef{ids.resource, "subnet"}})
	ids.ssh = add("operators-ssh-to-ts-orch-servers", ruleRequest{Name: "operators-ssh-to-ts-orch-servers", Enabled: true,
		Action: "accept", Protocol: "netbird-ssh", Sources: []string{ids.operators}, Destinations: []string{ids.servers}})
	ids.forgejo = add("operators-to-forgejo", ruleRequest{Name: "forgejo-services", Enabled: true, Action: "accept",
		Protocol: "tcp", Ports: []string{"22", "443", "2022"}, Sources: []string{ids.operators}, Destinations: []string{ids.gateway}})
	ids.ping = add("operators-ping-to-forgejo", ruleRequest{Name: "forgejo-ping", Enabled: true, Action: "accept",
		Bidirectional: true, Protocol: "icmp", Sources: []string{ids.operators}, Destinations: []string{ids.gateway}})
	f.setupKeys = []map[string]any{{"id": "sk1", "name": "gru-servers", "key": "SECRET-SETUP-KEY-VALUE",
		"type": "reusable", "state": "valid", "valid": true, "revoked": false, "auto_groups": []string{ids.servers}}}
	return ids
}
