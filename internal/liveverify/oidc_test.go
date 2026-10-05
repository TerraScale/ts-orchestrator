package liveverify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOIDCNeverRequestsWritingRoutesOrSendsCredentials(t *testing.T) {
	clearVerifyEnv(t)
	t.Setenv("TS_VERIFY_OIDC_JWT", "existing-user-jwt-must-not-be-sent")
	t.Setenv("E2E_MANAGEMENT_CREDENTIAL", "existing-service-secret-must-not-be-sent")
	var trapCalls atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { trapCalls.Add(1) }))
	defer trap.Close()
	for _, attack := range []string{"valid keys", "trailing issuer slash", "writing readiness", "writing Management", "off origin", "credentials", "query", "empty query", "fragment", "encoded readiness", "relative", "wrong issuer", "discovery redirect", "JWKS redirect", "empty keys", "malformed keys"} {
		t.Run(attack, func(t *testing.T) {
			var origin string
			var keyCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Errorf("unsafe request method/credentials")
				}
				if r.URL.Path == "/.well-known/jwks.json" {
					keyCalls.Add(1)
					switch attack {
					case "JWKS redirect":
						http.Redirect(w, r, trap.URL+"/readyz", http.StatusFound)
					case "empty keys":
						io.WriteString(w, `{"keys":[]}`)
					case "malformed keys":
						io.WriteString(w, `{`)
					default:
						io.WriteString(w, `{"keys":[{"kid":"retrieved-only"}]}`)
					}
					return
				}
				if r.URL.Path != "/.well-known/openid-configuration" {
					t.Errorf("fetched writing/unreviewed path %s", r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				issuer, uri := origin, origin+"/.well-known/jwks.json"
				switch attack {
				case "trailing issuer slash":
					issuer += "/"
				case "writing readiness":
					uri = origin + "/readyz"
				case "writing Management":
					uri = origin + "/v1/management/organizations"
				case "off origin":
					uri = trap.URL + "/.well-known/jwks.json"
				case "credentials":
					uri = strings.Replace(uri, "http://", "http://user:secret@", 1)
				case "query":
					uri += "?write=true"
				case "empty query":
					uri += "?"
				case "fragment":
					uri += "#fragment"
				case "encoded readiness":
					uri = origin + "/%72eadyz"
				case "relative":
					uri = "/.well-known/jwks.json"
				case "wrong issuer":
					issuer = trap.URL
				case "discovery redirect":
					http.Redirect(w, r, trap.URL+"/readyz", http.StatusFound)
					return
				}
				json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": uri})
			}))
			defer server.Close()
			origin = server.URL
			v := localVerifier(t)
			v.oidc(origin)
			want := "FAIL"
			if attack == "valid keys" || attack == "trailing issuer slash" {
				want = "PASS"
			}
			assertRow(t, v, "OIDC discovery/nonempty JWKS retrieved", want)
			assertRow(t, v, "5. TerraBase validates ts-auth user JWTs", "UNKNOWN")
			wantCalls := int32(0)
			if want == "PASS" || attack == "JWKS redirect" || attack == "empty keys" || attack == "malformed keys" {
				wantCalls = 1
			}
			if keyCalls.Load() != wantCalls || trapCalls.Load() != 0 {
				t.Fatalf("key requests=%d want=%d; unsafe requests=%d", keyCalls.Load(), wantCalls, trapCalls.Load())
			}
		})
	}
}
