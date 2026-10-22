package geodns

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"
)

// fakeOCI keeps objects per collection and answers list, get, create and update.
type fakeOCI struct {
	objects map[string]map[string]map[string]any
	writes  []string
}

func (f *fakeOCI) call(_ context.Context, method, endpoint string, body, out any) error {
	target, _ := url.Parse(endpoint)
	collection, id := target.Path, ""
	if f.objects[collection] == nil && strings.Count(collection, "/") > 2 {
		collection, id = path.Dir(target.Path), path.Base(target.Path)
	}
	if f.objects[collection] == nil {
		f.objects[collection] = map[string]map[string]any{}
	}
	store := f.objects[collection]
	switch {
	case method == http.MethodGet && id != "":
		return roundTrip(store[id], out)
	case method == http.MethodGet:
		var found []map[string]any
		for _, o := range store {
			q := target.Query()
			if (q.Has("name") && o["name"] != q.Get("name")) || (q.Has("displayName") && o["displayName"] != q.Get("displayName")) ||
				(q.Has("domain") && o["domainName"] != q.Get("domain")) {
				continue
			}
			found = append(found, o)
		}
		return roundTrip(found, out)
	case method == http.MethodPost:
		var o map[string]any
		_ = roundTrip(body, &o)
		o["id"] = fmt.Sprintf("ocid1.%s.%d", path.Base(collection), len(store)+1)
		o["nameservers"] = []map[string]string{{"hostname": "ns1.p68.dns.oraclecloud.net"}}
		store[o["id"].(string)] = o
		f.writes = append(f.writes, "POST "+path.Base(collection))
		return roundTrip(o, out)
	case method == http.MethodPut:
		var o map[string]any
		_ = roundTrip(body, &o)
		maps.Copy(store[id], o)
		f.writes = append(f.writes, "PUT "+path.Base(collection))
	}
	return nil
}

func TestApplyCreatesThenChangesNothingThenUpdatesDrift(t *testing.T) {
	regions := []Region{{Name: "gru", IP: "163.176.124.12", Latitude: -23.43, Longitude: -46.47}, {Name: "fra", IP: "130.162.238.198", Latitude: 50.11, Longitude: 8.68}}
	fake := &fakeOCI{objects: map[string]map[string]map[string]any{}}
	ctx := context.Background()
	changes, nameservers, err := apply(ctx, fake.call, Build(regions, Hosts))
	if err != nil {
		t.Fatal(err)
	}
	// zone + 3 x (monitor, policy, attachment)
	if len(fake.writes) != 10 || len(changes) != 10 || len(nameservers) != 1 {
		t.Fatalf("first run writes %v changes %d nameservers %v", fake.writes, len(changes), nameservers)
	}
	fake.writes = nil
	changes, _, err = apply(ctx, fake.call, Build(regions, Hosts))
	if err != nil || len(fake.writes) != 0 {
		t.Fatalf("second run writes %v err %v", fake.writes, err)
	}
	for _, c := range changes {
		if c.Action != "unchanged" || c.ID == "" {
			t.Fatalf("second run %+v", c)
		}
	}
	regions[1].IP = "130.162.238.199" // fra edge moved: monitors and policies follow
	if _, _, err = apply(ctx, fake.call, Build(regions, Hosts)); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(fake.writes); got != "[PUT httpMonitors PUT steeringPolicies PUT httpMonitors PUT steeringPolicies PUT httpMonitors PUT steeringPolicies]" {
		t.Fatalf("drift writes %s", got)
	}
}
