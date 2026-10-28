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

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// compartmentID is gru-1-control, the compartment the mesh secret lives in
// (internal/natscell/mesh/run.go); the global edge DNS objects live there too.
const compartmentID = "ocid1.compartment.oc1..aaaaaaaaypdff62jbchkojfli5i22ybzm3qnptwwsbg3aa2t5ali6te52nzq"

// Endpoints of the OCI DNS and Health Checks REST APIs; both serve global objects.
var (
	dnsAPI    = "https://dns." + catalog.OCIRegion(catalog.Bootstrap) + ".oci.oraclecloud.com/20180115"
	healthAPI = "https://healthchecks." + catalog.OCIRegion(catalog.Bootstrap) + ".oci.oraclecloud.com/20180501"
)

// caller sends one signed OCI REST request and decodes the JSON answer into out.
type caller func(ctx context.Context, method, endpoint string, body, out any) error

// object is the part of every OCI list or get answer the apply reads.
type object struct {
	ID               string `json:"id"`
	SteeringPolicyID string `json:"steeringPolicyId"`
	Nameservers      []struct {
		Hostname string `json:"hostname"`
	} `json:"nameservers"`
}

// Change is one object the apply looked at.
type Change struct {
	Action, Kind, Name, ID string
}

// apply creates what is missing and updates what differs; a second run with
// the same plan changes nothing. It returns the changes and the zone's nameservers.
func apply(ctx context.Context, call caller, plans []HostPlan) ([]Change, []string, error) {
	var changes []Change
	zoneQuery := url.Values{"compartmentId": {compartmentID}, "name": {Zone}, "lifecycleState": {"ACTIVE"}}
	zone, action, err := ensure(ctx, call, dnsAPI+"/zones", zoneQuery,
		map[string]any{"name": Zone, "zoneType": "PRIMARY", "compartmentId": compartmentID, "freeformTags": CostTags})
	if err != nil {
		return nil, nil, fmt.Errorf("zone %s: %w", Zone, err)
	}
	changes = append(changes, Change{action, "zone", Zone, zone.ID})
	for _, p := range plans {
		named := url.Values{"compartmentId": {compartmentID}, "displayName": {p.Monitor.DisplayName}}
		monitor, action, err := ensure(ctx, call, healthAPI+"/httpMonitors", named, p.Monitor)
		if err != nil {
			return nil, nil, fmt.Errorf("monitor %s: %w", p.Monitor.DisplayName, err)
		}
		changes = append(changes, Change{action, "monitor", p.Monitor.DisplayName, monitor.ID})
		policy := p.Policy
		policy.CompartmentID, policy.HealthCheckMonitorID = compartmentID, monitor.ID
		named.Set("lifecycleState", "ACTIVE")
		steering, action, err := ensure(ctx, call, dnsAPI+"/steeringPolicies", named, policy)
		if err != nil {
			return nil, nil, fmt.Errorf("policy %s: %w", policy.DisplayName, err)
		}
		changes = append(changes, Change{action, "policy", policy.DisplayName, steering.ID})
		var attached []object
		domain := url.Values{"compartmentId": {compartmentID}, "domain": {p.Attachment.DomainName}, "lifecycleState": {"ACTIVE"}}
		if err := call(ctx, http.MethodGet, dnsAPI+"/steeringPolicyAttachments?"+domain.Encode(), nil, &attached); err != nil {
			return nil, nil, fmt.Errorf("attachment %s: %w", p.Attachment.DomainName, err)
		}
		attachment := Change{"unchanged", "attachment", p.Attachment.DomainName, ""}
		switch {
		case len(attached) > 0 && attached[0].SteeringPolicyID != steering.ID:
			return nil, nil, fmt.Errorf("attachment %s belongs to policy %s, not %s", p.Attachment.DomainName, attached[0].SteeringPolicyID, steering.ID)
		case len(attached) > 0:
			attachment.ID = attached[0].ID
		default:
			body := p.Attachment
			body.SteeringPolicyID, body.ZoneID = steering.ID, zone.ID
			var created object
			if err := call(ctx, http.MethodPost, dnsAPI+"/steeringPolicyAttachments", body, &created); err != nil {
				return nil, nil, fmt.Errorf("attachment %s: %w", p.Attachment.DomainName, err)
			}
			attachment.Action, attachment.ID = "created", created.ID
		}
		changes = append(changes, attachment)
	}
	var full object
	if err := call(ctx, http.MethodGet, dnsAPI+"/zones/"+zone.ID, nil, &full); err != nil {
		return nil, nil, fmt.Errorf("zone %s nameservers: %w", Zone, err)
	}
	var nameservers []string
	for _, ns := range full.Nameservers {
		nameservers = append(nameservers, ns.Hostname)
	}
	return changes, nameservers, nil
}

// ensure finds the one object the query names under collection, creates it
// from desired when absent and updates it when a desired field differs.
func ensure(ctx context.Context, call caller, collection string, query url.Values, desired any) (object, string, error) {
	var found []object
	if err := call(ctx, http.MethodGet, collection+"?"+query.Encode(), nil, &found); err != nil {
		return object{}, "", err
	}
	if len(found) == 0 {
		var created object
		err := call(ctx, http.MethodPost, collection, desired, &created)
		return created, "created", err
	}
	if len(found) > 1 {
		return object{}, "", fmt.Errorf("%d objects match %s; remove the extra ones", len(found), query.Encode())
	}
	var want, have map[string]any
	if err := roundTrip(desired, &want); err != nil {
		return object{}, "", err
	}
	if err := call(ctx, http.MethodGet, collection+"/"+found[0].ID, nil, &have); err != nil {
		return object{}, "", err
	}
	delete(want, "compartmentId") // update bodies carry no compartment
	if covers(have, want) {
		return found[0], "unchanged", nil
	}
	return found[0], "updated", call(ctx, http.MethodPut, collection+"/"+found[0].ID, want, nil)
}

// covers reports whether have holds every field of want; OCI adds fields of its own.
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

func roundTrip(in, out any) error {
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

// operatorCaller signs requests with the operator's OCI profile, like the
// other operator commands (capacity, disaster-recovery).
func operatorCaller() (caller, error) {
	factory, err := ociclient.OperatorConfig(catalog.OCIRegion(catalog.Bootstrap))
	if err != nil {
		return nil, err
	}
	client, err := common.NewClientWithConfig(factory.Provider())
	if err != nil {
		return nil, err
	}
	factory.Configure(&client, ociclient.Service("dns"))
	return func(ctx context.Context, method, endpoint string, body, out any) error {
		target, err := url.Parse(endpoint)
		if err != nil {
			return err
		}
		request := common.MakeDefaultHTTPRequest(method, target.Path)
		request.URL.RawQuery = target.RawQuery
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				return err
			}
			request.Body, request.ContentLength = io.NopCloser(bytes.NewReader(data)), int64(len(data))
			request.Header.Set("Content-Type", "application/json")
		}
		local := client
		local.Host = target.Scheme + "://" + target.Host
		response, err := local.Call(ctx, &request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if out == nil {
			return nil
		}
		return json.NewDecoder(response.Body).Decode(out)
	}, nil
}
