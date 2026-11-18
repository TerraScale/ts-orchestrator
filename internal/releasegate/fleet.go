package releasegate

import (
	"encoding/json"
	"net/url"
	"slices"

	document "github.com/TerraScale/ts-orchestrator/deploy/fleet"
)

type gateRegion struct {
	Label string `json:"label"`
}
type gateFleet struct {
	Regions []gateRegion `json:"regions"`
	Staging struct {
		Label     string `json:"label"`
		OCIRegion string `json:"oci_region"`
		Namespace string `json:"namespace"`
	} `json:"staging"`
}

var scope = func() gateFleet {
	var parsed gateFleet
	if err := json.Unmarshal(document.Document, &parsed); err != nil {
		panic(err)
	}
	return parsed
}()

func Production(region string) bool {
	return slices.ContainsFunc(scope.Regions, func(r gateRegion) bool { return r.Label == region })
}

func gateURL(tag string) string {
	staging := scope.Staging
	return "https://objectstorage." + staging.OCIRegion + ".oraclecloud.com/n/" + url.PathEscape(staging.Namespace) + "/b/" + url.PathEscape(staging.Label+"-release-gate") + "/o/" + url.PathEscape(tag)
}
