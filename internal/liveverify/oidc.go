package liveverify

import (
	"encoding/json"
	"net/url"
	"strings"
)

func (v *verifier) oidc(auth string) {
	body, code, _, evidence := v.get(auth, "/.well-known/openid-configuration", "")
	var discovery struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	state := "PASS"
	if code != 200 || json.Unmarshal(body, &discovery) != nil || !validOrigin(discovery.Issuer) || strings.TrimRight(discovery.Issuer, "/") != strings.TrimRight(auth, "/") {
		state = "FAIL"
		evidence += "; expected ts-auth issuer discovery"
	}
	if state == "PASS" {
		// Only fetch reviewed key routes from this origin. A discovery URL
		// must never direct a GET to a writing readiness/Management route.
		u, err := url.Parse(discovery.JWKS)
		origin, _ := url.Parse(auth)
		if err != nil || u.Scheme != origin.Scheme || u.Host != origin.Host || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.EscapedPath() != "/.well-known/jwks.json" && u.EscapedPath() != "/.well-known/jwks" && u.EscapedPath() != "/connect/jwks") {
			state = "FAIL"
			evidence += "; invalid/off-origin jwks_uri"
		} else {
			keys, status, _, detail := v.get(auth, u.EscapedPath(), "")
			evidence += "; " + detail
			var jwks struct {
				Keys []json.RawMessage `json:"keys"`
			}
			if status != 200 || json.Unmarshal(keys, &jwks) != nil || len(jwks.Keys) == 0 {
				state = "FAIL"
				evidence += "; expected non-empty JWKS"
			}
		}
	}
	v.add("OIDC discovery/nonempty JWKS retrieved", state, evidence, "TS-491, TS-487")
	// ListOrganizationsAsync calls EnsureCatalogAsync, which may initialize
	// or migrate the catalog. Neither positive nor negative auth probes can
	// safely use that handler (an auth bypass could let either reach it).
	v.add("5. TerraBase validates ts-auth user JWTs", "UNKNOWN", "Management GETs skipped (catalog initialization/migration writes); discovery/JWKS alone cannot prove JWT acceptance; needs a passive authenticated route", "TS-491, TS-519, TS-527")
}
