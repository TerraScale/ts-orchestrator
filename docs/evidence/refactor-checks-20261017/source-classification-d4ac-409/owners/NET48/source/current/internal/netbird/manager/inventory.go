package manager

import (
	"context"
	"slices"
	"strings"
	"time"
)

// Inventory is allowlisted, secret-free manager metadata.
type Inventory struct {
	Account   InventoryAccount    `json:"account"`
	DNS       InventoryDNS        `json:"dns"`
	Groups    []InventoryGroup    `json:"groups"`
	Peers     []InventoryPeer     `json:"peers"`
	Policies  []InventoryPolicy   `json:"policies"`
	Networks  []InventoryNetwork  `json:"networks"`
	Zones     []InventoryZone     `json:"zones"`
	SetupKeys []InventorySetupKey `json:"setup_keys"`
}

type InventoryAccount struct {
	NetworkRange string `json:"network_range"`
	DNSDomain    string `json:"dns_domain"`
}

type InventoryDNS struct {
	DisabledManagementGroups []string `json:"disabled_management_groups"`
}

type InventoryGroup struct {
	Name      string `json:"name"`
	Peers     int    `json:"peers"`
	Resources int    `json:"resources"`
}

type InventoryPeer struct {
	Name         string    `json:"name"`
	DNSLabel     string    `json:"dns_label"`
	IP           string    `json:"ip"`
	ConnectionIP string    `json:"connection_ip"`
	Connected    bool      `json:"connected"`
	LastSeen     time.Time `json:"last_seen"`
	Version      string    `json:"version"`
	Groups       []string  `json:"groups"`
}

type InventoryRule struct {
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	Action              string   `json:"action"`
	Bidirectional       bool     `json:"bidirectional"`
	Protocol            string   `json:"protocol"`
	Ports               []string `json:"ports"`
	Sources             []string `json:"sources"`
	Destinations        []string `json:"destinations"`
	DestinationResource string   `json:"destination_resource,omitempty"`
}

type InventoryPolicy struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Rules       []InventoryRule `json:"rules"`
}

type InventoryResource struct {
	Name    string   `json:"name"`
	Address string   `json:"address"`
	Enabled bool     `json:"enabled"`
	Groups  []string `json:"groups"`
}

type InventoryRouter struct {
	Peer       string `json:"peer"`
	PeerGroups int    `json:"peer_groups"`
	Metric     int    `json:"metric"`
	Masquerade bool   `json:"masquerade"`
	Enabled    bool   `json:"enabled"`
}

type InventoryNetwork struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Resources   []InventoryResource `json:"resources"`
	Routers     []InventoryRouter   `json:"routers"`
}

type InventoryRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type InventoryZone struct {
	Name               string            `json:"name"`
	Domain             string            `json:"domain"`
	Enabled            bool              `json:"enabled"`
	EnableSearchDomain bool              `json:"enable_search_domain"`
	DistributionGroups []string          `json:"distribution_groups"`
	Records            []InventoryRecord `json:"records"`
}

type InventorySetupKey struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	State      string    `json:"state"`
	Valid      bool      `json:"valid"`
	Revoked    bool      `json:"revoked"`
	Ephemeral  bool      `json:"ephemeral"`
	UsedTimes  int       `json:"used_times"`
	Expires    time.Time `json:"expires"`
	AutoGroups []string  `json:"auto_groups"`
}

// ReadInventory reads the manager without changing it. Group references are
// reported by name.
func ReadInventory(ctx context.Context, api *API) (Inventory, error) {
	var inventory Inventory
	var groups []apiGroup
	if err := api.do(ctx, "GET", "/groups", nil, &groups); err != nil {
		return inventory, err
	}
	names := map[string]string{}
	for _, group := range groups {
		names[group.ID] = group.Name
		inventory.Groups = append(inventory.Groups, InventoryGroup{group.Name, len(group.Peers), len(group.Resources)})
	}
	named := func(ids []string) []string {
		out := make([]string, 0, len(ids))
		for _, id := range ids {
			if name, ok := names[id]; ok {
				out = append(out, name)
			} else {
				out = append(out, "unknown:"+id)
			}
		}
		slices.Sort(out)
		return out
	}
	var accounts []apiAccount
	if err := api.do(ctx, "GET", "/accounts", nil, &accounts); err != nil {
		return inventory, err
	}
	if len(accounts) > 0 {
		inventory.Account = InventoryAccount{rawString(accounts[0].Settings, "network_range"), rawString(accounts[0].Settings, "dns_domain")}
	}
	var dns dnsSettings
	if err := api.do(ctx, "GET", "/dns/settings", nil, &dns); err != nil {
		return inventory, err
	}
	inventory.DNS.DisabledManagementGroups = named(dns.DisabledManagementGroups)
	var peers []apiPeer
	if err := api.do(ctx, "GET", "/peers", nil, &peers); err != nil {
		return inventory, err
	}
	peerNames := map[string]string{}
	for _, peer := range peers {
		peerNames[peer.ID] = peer.Name
		inventory.Peers = append(inventory.Peers, InventoryPeer{Name: peer.Name, DNSLabel: peer.DNSLabel, IP: peer.IP,
			ConnectionIP: peer.ConnectionIP, Connected: peer.Connected, LastSeen: peer.LastSeen, Version: peer.Version,
			Groups: named(minimumIDs(peer.Groups))})
	}
	var policies []apiPolicy
	if err := api.do(ctx, "GET", "/policies", nil, &policies); err != nil {
		return inventory, err
	}
	resourceNames := map[string]string{}
	var networks []apiNetwork
	if err := api.do(ctx, "GET", "/networks", nil, &networks); err != nil {
		return inventory, err
	}
	for _, network := range networks {
		row := InventoryNetwork{Name: network.Name, Description: network.Description}
		var resources []apiResource
		if err := api.do(ctx, "GET", "/networks/"+network.ID+"/resources", nil, &resources); err != nil {
			return inventory, err
		}
		for _, resource := range resources {
			resourceNames[resource.ID] = network.Name + "/" + resource.Name
			row.Resources = append(row.Resources, InventoryResource{resource.Name, resource.Address, resource.Enabled,
				named(minimumIDs(resource.Groups))})
		}
		var routers []apiRouter
		if err := api.do(ctx, "GET", "/networks/"+network.ID+"/routers", nil, &routers); err != nil {
			return inventory, err
		}
		for _, router := range routers {
			row.Routers = append(row.Routers, InventoryRouter{peerNames[router.Peer], len(router.PeerGroups),
				router.Metric, router.Masquerade, router.Enabled})
		}
		inventory.Networks = append(inventory.Networks, row)
	}
	for _, policy := range policies {
		row := InventoryPolicy{Name: policy.Name, Description: policy.Description, Enabled: policy.Enabled}
		for _, rule := range policy.Rules {
			out := InventoryRule{Name: rule.Name, Enabled: rule.Enabled, Action: rule.Action, Bidirectional: rule.Bidirectional,
				Protocol: rule.Protocol, Ports: rule.Ports, Sources: named(minimumIDs(rule.Sources)),
				Destinations: named(minimumIDs(rule.Destinations))}
			if rule.DestinationResource != nil {
				out.DestinationResource = resourceNames[rule.DestinationResource.ID]
			}
			row.Rules = append(row.Rules, out)
		}
		inventory.Policies = append(inventory.Policies, row)
	}
	var zones []apiZone
	if err := api.do(ctx, "GET", "/dns/zones", nil, &zones); err != nil {
		return inventory, err
	}
	for _, zone := range zones {
		row := InventoryZone{Name: zone.Name, Domain: zone.Domain, Enabled: zone.Enabled,
			EnableSearchDomain: zone.EnableSearchDomain, DistributionGroups: named(zone.DistributionGroups)}
		var records []apiRecord
		if err := api.do(ctx, "GET", "/dns/zones/"+zone.ID+"/records", nil, &records); err != nil {
			return inventory, err
		}
		for _, record := range records {
			row.Records = append(row.Records, InventoryRecord{record.Name, record.Type, record.Content, record.TTL})
		}
		slices.SortFunc(row.Records, func(a, b InventoryRecord) int {
			return strings.Compare(a.Name+" "+a.Content, b.Name+" "+b.Content)
		})
		inventory.Zones = append(inventory.Zones, row)
	}
	var keys []apiSetupKey
	if err := api.do(ctx, "GET", "/setup-keys", nil, &keys); err != nil {
		return inventory, err
	}
	for _, key := range keys {
		inventory.SetupKeys = append(inventory.SetupKeys, InventorySetupKey{Name: key.Name, Type: key.Type, State: key.State,
			Valid: key.Valid, Revoked: key.Revoked, Ephemeral: key.Ephemeral, UsedTimes: key.UsedTimes, Expires: key.Expires,
			AutoGroups: named(key.AutoGroups)})
	}
	slices.SortFunc(inventory.Peers, func(a, b InventoryPeer) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(inventory.Groups, func(a, b InventoryGroup) int { return strings.Compare(a.Name, b.Name) })
	return inventory, nil
}
