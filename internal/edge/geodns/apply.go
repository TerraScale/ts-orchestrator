package geodns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/oracle/oci-go-sdk/v65/common"
)

type Client struct {
	client      common.BaseClient
	dns, health string
}

type object struct {
	ID, Name, ZoneType, Scope, LifecycleState string
	ZoneID, DomainName, SteeringPolicyID      string
	FreeformTags                              map[string]string
	Targets                                   []string
	Nameservers                               []struct{ Hostname string }
}

type Change struct {
	Action, Kind, Name, ID string
}

func New(f *ociclient.Factory) (*Client, error) {
	client, err := common.NewClientWithConfig(f.Provider())
	if err != nil {
		return nil, err
	}
	f.Configure(&client, ociclient.Service("dns"))
	return &Client{client: client,
		dns:    "https://dns." + f.Region() + ".oci.oraclecloud.com/20180115",
		health: "https://healthchecks." + f.Region() + ".oci.oraclecloud.com/20180501"}, nil
}

func (c *Client) request(ctx context.Context, method, endpoint, etag string, body, out any) (http.Header, error) {
	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	request := common.MakeDefaultHTTPRequest(method, target.Path)
	request.URL.RawQuery = target.RawQuery
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		request.Body, request.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
		request.Header.Set("Content-Type", "application/json")
	}
	local := c.client
	local.Host = target.Scheme + "://" + target.Host
	response, err := local.Call(ctx, &request)
	if response != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	if out != nil {
		if err := json.NewDecoder(response.Body).Decode(out); err != nil {
			return nil, err
		}
	}
	return response.Header, nil
}

func (c *Client) objects(ctx context.Context, endpoint string, query url.Values) ([]object, error) {
	var all []object
	for {
		var page []object
		headers, err := c.request(ctx, http.MethodGet, endpoint+"?"+query.Encode(), "", nil, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		next := headers.Get("opc-next-page")
		if next == "" {
			return all, nil
		}
		query.Set("page", next)
	}
}

func (c *Client) ensure(ctx context.Context, cfg Config, collection string, key ociresource.Key, desired any, apply bool) (object, Change, error) {
	change := Change{Kind: key.Kind, Name: key.Name}
	query := url.Values{"compartmentId": {cfg.CompartmentID}}
	if key.Kind == "dns-zone" {
		query.Set("scope", "GLOBAL")
	}
	objects, err := c.objects(ctx, collection, query)
	if err != nil {
		return object{}, change, err
	}
	var found []object
	for _, obj := range objects {
		if obj.LifecycleState == "DELETED" || obj.LifecycleState == "DELETING" {
			continue
		}
		if cfg.owns(key, obj.FreeformTags) {
			found = append(found, obj)
		}
	}
	adopt := false
	if len(found) == 0 && key.Kind == "dns-zone" {
		for _, obj := range objects {
			if strings.EqualFold(obj.Name, cfg.Zone) && obj.LifecycleState != "DELETED" && obj.LifecycleState != "DELETING" {
				if (ociresource.Ownership{Owner: cfg.Owner}).Claimed(ociresource.Tags{Freeform: obj.FreeformTags}) {
					return object{}, change, fmt.Errorf("zone %s is claimed by another owner", cfg.Zone)
				}
				found, adopt = append(found, obj), true
			}
		}
	}
	if len(found) > 1 {
		return object{}, change, fmt.Errorf("duplicate resource key %s", key)
	}
	if len(found) == 0 {
		change.Action = "missing"
		if !apply {
			return object{}, change, nil
		}
		var created object
		_, err := c.request(ctx, http.MethodPost, collection, "", desired, &created)
		change.Action, change.ID = "created", created.ID
		return created, change, err
	}
	obj := found[0]
	change.ID = obj.ID
	var have, want map[string]any
	headers, err := c.request(ctx, http.MethodGet, collection+"/"+obj.ID, "", nil, &have)
	if err != nil {
		return obj, change, err
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return obj, change, err
	}
	if err := json.Unmarshal(data, &want); err != nil {
		return obj, change, err
	}
	var current object
	data, err = json.Marshal(have)
	if err != nil {
		return obj, change, err
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return obj, change, err
	}
	if adopt && (ociresource.Ownership{Owner: cfg.Owner}).Claimed(ociresource.Tags{Freeform: current.FreeformTags}) {
		return obj, change, fmt.Errorf("zone ownership changed before adoption")
	}
	if !adopt && !cfg.owns(key, current.FreeformTags) {
		return obj, change, fmt.Errorf("ownership changed for %s", key)
	}
	if key.Kind == "dns-zone" && (current.Name != cfg.Zone || current.ZoneType != "PRIMARY" || current.Scope != "GLOBAL") {
		return obj, change, fmt.Errorf("owned zone %s is not the public primary zone %s", obj.ID, cfg.Zone)
	}
	delete(want, "compartmentId")
	if key.Kind == "dns-zone" {
		delete(want, "name")
		delete(want, "zoneType")
	}
	change.Action = "ok"
	if covers(have, want) {
		return current, change, nil
	}
	change.Action = "differs"
	if !apply {
		return current, change, nil
	}
	want["freeformTags"] = (ociresource.Tags{Freeform: current.FreeformTags}).Merge(ociresource.Tags{Freeform: cfg.tags(key.Kind, key.Name)}).Freeform
	if headers.Get("etag") == "" {
		return obj, change, fmt.Errorf("no etag for %s", key)
	}
	_, err = c.request(ctx, http.MethodPut, collection+"/"+obj.ID, headers.Get("etag"), want, nil)
	change.Action = "updated"
	if adopt {
		change.Action = "adopted"
	}
	return current, change, err
}

func covers(have, want any) bool {
	switch w := want.(type) {
	case map[string]any:
		h, ok := have.(map[string]any)
		if !ok {
			return false
		}
		for key, value := range w {
			if !covers(h[key], value) {
				return false
			}
		}
		return true
	case []any:
		h, ok := have.([]any)
		if !ok || len(h) != len(w) {
			return false
		}
		for i := range w {
			if !covers(h[i], w[i]) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(have, want)
}

func (c *Client) Reconcile(ctx context.Context, cfg Config, apply bool) ([]Change, error) {
	var changes []Change
	zone, change, err := c.ensure(ctx, cfg, c.dns+"/zones", cfg.key("dns-zone", "zone"), map[string]any{
		"name": cfg.Zone, "zoneType": "PRIMARY", "compartmentId": cfg.CompartmentID, "freeformTags": cfg.tags("dns-zone", "zone")}, apply)
	if err != nil {
		return changes, err
	}
	changes = append(changes, change)
	var targets []string
	for _, region := range cfg.Regions {
		targets = append(targets, region.IP)
	}
	slices.Sort(targets)
	monitor := func(targets []string) map[string]any {
		return map[string]any{"compartmentId": cfg.CompartmentID, "displayName": cfg.Zone,
			"targets": targets, "protocol": "HTTP", "port": 80, "method": "GET", "path": cfg.HealthPath,
			"intervalInSeconds": 10, "timeoutInSeconds": 10, "isEnabled": true, "freeformTags": cfg.tags("http-monitor", "edge")}
	}
	monitors, err := c.objects(ctx, c.health+"/httpMonitors", url.Values{"compartmentId": {cfg.CompartmentID}})
	if err != nil {
		return changes, err
	}
	union := slices.Clone(targets)
	for _, m := range monitors {
		if cfg.owns(cfg.key("http-monitor", "edge"), m.FreeformTags) {
			union = append(union, m.Targets...)
		}
	}
	slices.Sort(union)
	union = slices.Compact(union)
	initial := targets
	if apply {
		initial = union
	}
	m, change, err := c.ensure(ctx, cfg, c.health+"/httpMonitors", cfg.key("http-monitor", "edge"), monitor(initial), apply)
	if err != nil {
		return changes, err
	}
	changes = append(changes, change)
	for _, name := range cfg.Names {
		label := strings.SplitN(name, ".", 2)[0]
		policy, change, err := c.ensure(ctx, cfg, c.dns+"/steeringPolicies", cfg.key("steering-policy", label), cfg.policy(name, m.ID), apply)
		if err != nil {
			return changes, err
		}
		changes = append(changes, change)
		if zone.ID == "" || policy.ID == "" {
			continue
		}
		change, err = c.attach(ctx, cfg, zone.ID, name, policy.ID, apply)
		if err != nil {
			return changes, err
		}
		changes = append(changes, change)
	}
	if zone.ID != "" {
		records, err := c.records(ctx, cfg, zone.ID, apply)
		if err != nil {
			return changes, err
		}
		changes = append(changes, records...)
	}
	if apply && !slices.Equal(union, targets) {
		_, change, err := c.ensure(ctx, cfg, c.health+"/httpMonitors", cfg.key("http-monitor", "edge"), monitor(targets), true)
		if err != nil {
			return changes, err
		}
		changes = append(changes, change)
	}
	for _, ns := range zone.Nameservers {
		changes = append(changes, Change{Action: "ok", Kind: "nameserver", Name: ns.Hostname})
	}
	return changes, nil
}

func (c *Client) attach(ctx context.Context, cfg Config, zone, domain, policy string, apply bool) (Change, error) {
	change := Change{Action: "missing", Kind: "steering-attachment", Name: domain}
	attachments, err := c.objects(ctx, c.dns+"/steeringPolicyAttachments", url.Values{"compartmentId": {cfg.CompartmentID}, "zoneId": {zone}, "domain": {domain}})
	if err != nil {
		return change, err
	}
	var found []object
	for _, a := range attachments {
		if a.ZoneID == zone && strings.EqualFold(a.DomainName, domain) && a.LifecycleState != "DELETED" && a.LifecycleState != "DELETING" {
			found = append(found, a)
		}
	}
	if len(found) > 1 {
		return change, fmt.Errorf("multiple attachments at %s", domain)
	}
	if len(found) == 1 {
		if found[0].SteeringPolicyID != policy {
			return change, fmt.Errorf("foreign attachment at %s", domain)
		}
		change.Action, change.ID = "ok", found[0].ID
		return change, nil
	}
	records, _, err := c.snapshot(ctx, zone)
	if err != nil {
		return change, err
	}
	for _, record := range records {
		if record.Domain != domain {
			continue
		}
		if record.Rtype == "A" || record.Rtype == "AAAA" || record.Rtype == "CNAME" {
			return change, fmt.Errorf("foreign record at steering name %s", domain)
		}
	}
	if !apply {
		return change, nil
	}
	var a object
	_, err = c.request(ctx, http.MethodPost, c.dns+"/steeringPolicyAttachments", "", map[string]string{
		"zoneId": zone, "domainName": domain, "steeringPolicyId": policy, "displayName": cfg.key("steering-attachment", strings.SplitN(domain, ".", 2)[0]).String()}, &a)
	change.Action, change.ID = "created", a.ID
	return change, err
}
