package edge

import (
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

const regionsPath = "/v1/regions/origins"
const apiHost = "api.terrascale.tech"

var regionID = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// A public wrong_region response must give clients a concrete retry URL even
// when replay could not reach the database's home. The backend owns placement.
func locateDatabaseHome(resp *http.Response) {
	home := resp.Header.Get("X-TerraBase-Database-Home")
	if resp.StatusCode == http.StatusMisdirectedRequest && regionID.MatchString(home) && resp.Header.Get("Location") == "" {
		resp.Header.Set("Location", "https://"+home+"."+apiHost+resp.Request.URL.RequestURI())
	}
}

// serveRegions advertises the API routes owned by ts-orch for admitted mesh
// regions. Consumers use these origins rather than keeping a DNS-name catalog.
func (e *Edge) serveRegions(w http.ResponseWriter, r *http.Request) bool {
	host := r.Host
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	if r.URL.Path != regionsPath || !strings.EqualFold(host, apiHost) {
		return false
	}
	secureHeaders(w.Header())
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	m := e.meshNode()
	if m == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	}
	type region struct {
		ID     string `json:"id"`
		APIURL string `json:"apiUrl"`
	}
	names := append(slices.Clone(m.AdmittedRegions()), m.Region())
	slices.Sort(names)
	regions := make([]region, 0, len(names))
	for _, name := range slices.Compact(names) {
		regions = append(regions, region{ID: name, APIURL: "https://" + name + "." + apiHost})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=5")
	if r.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(struct {
			Regions []region `json:"regions"`
		}{regions})
	}
	return true
}
