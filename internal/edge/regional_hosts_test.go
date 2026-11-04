package edge

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/handoff"
)

func TestRegionalHostSurvivesBackendHandoff(t *testing.T) {
	t.Parallel()
	regions := startRegions(t, func(name string, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unavailable-database" {
			w.Header().Set("X-TerraBase-Database-Home", "sjc")
			w.WriteHeader(http.StatusMisdirectedRequest)
			fmt.Fprint(w, "wrong_region")
			return
		}
		if r.URL.Path == "/database" && name == "gru" {
			w.Header().Set(replayHeader, "region=sjc")
			w.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		fmt.Fprint(w, name)
	})
	for name, reg := range regions {
		port := reg.backend.Listener.Addr().(*net.TCPAddr).Port
		reg.edge.SetRoutes(map[string]int{host: port, name + "." + host: port}, nil)
	}
	get := func(requestHost, pin, path string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, regions["gru"].public.URL+path, nil)
		req.Host = requestHost
		if pin != "" {
			req.Header.Set("X-TerraScale-Region-Pin", pin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", requestHost, resp.StatusCode, body)
		}
		return string(body)
	}
	// Warm the local connection so requests can use it while the port is held.
	if got := get(host, "", "/healthz"); got != "gru" {
		t.Fatal(got)
	}
	port := uint16(regions["gru"].backend.Listener.Addr().(*net.TCPAddr).Port)
	handoff.Hold(port)
	defer handoff.Release(port)
	if got := get(host, "", "/healthz"); got != "sjc" {
		t.Fatalf("un-pinned global failover: %s", got)
	}
	if got := get("GRU."+strings.ToUpper(host)+":443", "", "/healthz"); got != "gru" {
		t.Fatalf("regional host changed region during rollout: %s", got)
	}
	if got := get(host, "gru", "/healthz"); got != "gru" {
		t.Fatalf("global region pin changed region during rollout: %s", got)
	}
	handoff.Release(port)
	if got := get("gru."+host, "", "/database"); got != "sjc" {
		t.Fatalf("database-directed replay: %s", got)
	}
	req, _ := http.NewRequest(http.MethodPost, regions["gru"].public.URL+"/unavailable-database?x=1", nil)
	req.Host = "gru." + host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest || resp.Header.Get("Location") != "https://sjc.api.terrascale.tech/unavailable-database?x=1" {
		t.Fatalf("home unavailable: %d, retry URL %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRegionalOriginsFollowMeshAdmission(t *testing.T) {
	t.Parallel()
	regions := startRegions(t, func(_ string, w http.ResponseWriter, _ *http.Request) {
		t.Error("edge discovery reached an application backend")
		w.WriteHeader(http.StatusInternalServerError)
	}, "new-region")
	reg := regions["gru"]
	reg.edge.SetRoutes(map[string]int{apiHost: reg.backend.Listener.Addr().(*net.TCPAddr).Port}, nil)
	req, _ := http.NewRequest(http.MethodGet, reg.public.URL+regionsPath, nil)
	req.Host = apiHost
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Regions []struct{ ID, APIURL string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || len(body.Regions) != 4 || body.Regions[2].ID != "new-region" || body.Regions[2].APIURL != "https://new-region.api.terrascale.tech" {
		t.Fatalf("discovery: %d %+v", resp.StatusCode, body)
	}
}
