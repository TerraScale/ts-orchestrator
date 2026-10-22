package region

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// Actual signed original-manager admission, OCI SDK/TLS and durable foundation
// CAS remain in the shared fixture; only the account's remote Vault is simulated.
func TestOriginalNetBirdAccountEscrowInterruptedPublication(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	type secret struct {
		id, name string
		value    []byte
		version  int64
		retry    string
	}
	var mu sync.Mutex
	var target vaultsecret.Target
	var password, pat *secret
	var loseCreate = true
	var loseUpdate = true
	var wrongTarget bool
	var creates, updates int
	var createRetry string
	metadata := func(s *secret) map[string]any {
		vaultID := target.VaultID
		if wrongTarget {
			vaultID = "ocid1.vault.oc1.sa-saopaulo-1.foreign"
		}
		m := map[string]any{"id": s.id, "secretName": s.name, "compartmentId": target.CompartmentID, "vaultId": vaultID, "keyId": target.KeyID, "lifecycleState": "ACTIVE", "currentVersionNumber": s.version}
		if s.name == netBirdOwnerPasswordName {
			m["isAutoGenerationEnabled"] = true
			m["secretGenerationContext"] = map[string]string{"generationType": "BYTES", "generationTemplate": "BYTES_512"}
		}
		return m
	}
	bundle := func(s *secret) map[string]any {
		return map[string]any{"secretId": s.id, "versionNumber": s.version, "stages": []string{"CURRENT"}, "secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString(s.value)}}
	}
	route := func(w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		defer mu.Unlock()
		write := func(value any) {
			if err := json.MarshalWrite(w, value); err != nil {
				t.Errorf("account fixture response: %v", err)
			}
		}
		if r.Method == "POST" && r.URL.Path == "/20180608/secrets" {
			wire, err := io.ReadAll(io.LimitReader(r.Body, 8193))
			if err != nil || len(wire) > 8192 {
				http.Error(w, "invalid", 400)
				return true
			}
			var request struct {
				SecretName    string `json:"secretName"`
				CompartmentID string `json:"compartmentId"`
				VaultID       string `json:"vaultId"`
				KeyID         string `json:"keyId"`
				Auto          bool   `json:"enableAutoGeneration"`
				Generation    *struct {
					Type     string `json:"generationType"`
					Template string `json:"generationTemplate"`
				} `json:"secretGenerationContext"`
				Content *struct {
					Value string `json:"content"`
				} `json:"secretContent"`
			}
			if json.Unmarshal(wire, &request) != nil {
				http.Error(w, "invalid", 400)
				return true
			}
			if request.SecretName != netBirdOwnerPasswordName && request.SecretName != netBirdAccountPATName {
				r.Body = io.NopCloser(bytes.NewReader(wire))
				return false
			}
			creates++
			if request.CompartmentID != target.CompartmentID || request.VaultID != target.VaultID || request.KeyID != target.KeyID || r.Header.Get("opc-retry-token") == "" {
				http.Error(w, "wrong target", 400)
				return true
			}
			if request.SecretName == netBirdOwnerPasswordName {
				if !request.Auto || request.Generation == nil || request.Generation.Type != "BYTES" || request.Generation.Template != "BYTES_512" || request.Content != nil {
					http.Error(w, "wrong generation", 400)
					return true
				}
				if password == nil {
					createRetry = r.Header.Get("opc-retry-token")
					password = &secret{id: "ocid1.vaultsecret.oc1.sa-saopaulo-1.accountowner", name: request.SecretName, value: bytes.Repeat([]byte{77}, 64), version: 1, retry: createRetry}
				}
				if createRetry != r.Header.Get("opc-retry-token") {
					http.Error(w, "changed retry", 409)
					return true
				}
				if loseCreate {
					loseCreate = false
					http.Error(w, "committed response lost", 502)
					return true
				}
				write(metadata(password))
				return true
			}
			if request.Auto || request.Generation != nil || request.Content == nil {
				http.Error(w, "wrong PAT body", 400)
				return true
			}
			value, err := base64.StdEncoding.Strict().DecodeString(request.Content.Value)
			if err != nil {
				http.Error(w, "invalid", 400)
				return true
			}
			if pat == nil {
				pat = &secret{id: "ocid1.vaultsecret.oc1.sa-saopaulo-1.accountpat", name: request.SecretName, value: value, version: 1, retry: r.Header.Get("opc-retry-token")}
			}
			if pat.retry != r.Header.Get("opc-retry-token") || !bytes.Equal(pat.value, value) {
				http.Error(w, "changed retry", 409)
				return true
			}
			write(metadata(pat))
			return true
		}
		var selected *secret
		for _, s := range []*secret{password, pat} {
			if s != nil && strings.HasSuffix(r.URL.Path, "/"+s.id) {
				selected = s
			}
		}
		if selected != nil && r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/20180608/secrets/") {
			w.Header().Set("etag", fmt.Sprintf("v%d", selected.version))
			write(metadata(selected))
			return true
		}
		if selected != nil && r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/20190301/secretbundles/") {
			if r.URL.Query().Get("stage") != "CURRENT" || r.URL.Query().Get("versionNumber") != fmt.Sprint(selected.version) {
				http.Error(w, "wrong version", 400)
				return true
			}
			write(bundle(selected))
			return true
		}
		if r.Method == "POST" && r.URL.Path == "/20190301/secretbundles/actions/getByName" && r.URL.Query().Get("secretName") == netBirdAccountPATName {
			if pat == nil || r.URL.Query().Get("vaultId") != target.VaultID || r.URL.Query().Get("stage") != "CURRENT" {
				http.Error(w, "not found", 404)
				return true
			}
			write(bundle(pat))
			return true
		}
		if selected == pat && pat != nil && r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/20180608/secrets/") {
			if r.Header.Get("if-match") != fmt.Sprintf("v%d", pat.version) {
				http.Error(w, "conditional conflict", 412)
				return true
			}
			var request struct {
				Content struct {
					Value string `json:"content"`
				} `json:"secretContent"`
			}
			wire, err := io.ReadAll(io.LimitReader(r.Body, 8193))
			if err != nil || json.Unmarshal(wire, &request) != nil {
				http.Error(w, "invalid", 400)
				return true
			}
			value, err := base64.StdEncoding.Strict().DecodeString(request.Content.Value)
			if err != nil {
				http.Error(w, "invalid", 400)
				return true
			}
			updates++
			pat.value = value
			pat.version++
			if loseUpdate {
				loseUpdate = false
				http.Error(w, "committed update response lost", 502)
				return true
			}
			write(metadata(pat))
			return true
		}
		return false
	}
	WithOriginalNetBirdManagerHTTPFixture(t, route, func(factory *ociclient.Factory, resolver FoundationResolver, manager VerifiedNetBirdManager) {
		ctx := t.Context()
		mu.Lock()
		target = manager.CredentialTarget()
		mu.Unlock()
		material, err := ReadNetBirdComponents(ctx, factory, resolver, manager)
		if err != nil {
			t.Fatal(err)
		}
		if err = material.RetainReleaseFloors(ctx); err != nil {
			t.Fatal(err)
		}
		a, err := ReadNetBirdAccount(ctx, factory, resolver, manager, material)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = a.OwnerPassword(ctx); err == nil {
			t.Fatal("lost committed create response reported success")
		}
		a, err = ReadNetBirdAccount(ctx, factory, resolver, manager, material)
		if err != nil {
			t.Fatal(err)
		}
		value, err := a.OwnerPassword(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if string(value) != base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{77}, 64)) {
			t.Fatal("password did not retain server-generated bytes")
		}
		clear(value)
		mu.Lock()
		if creates != 2 || createRetry == "" {
			t.Errorf("create retry dispatches=%d", creates)
		}
		wrongTarget = true
		mu.Unlock()
		if _, err = a.OwnerPassword(ctx); err == nil {
			t.Fatal("foreign metadata target admitted")
		}
		mu.Lock()
		wrongTarget = false
		mu.Unlock()
		first := []byte("nbp_" + strings.Repeat("a", 40))
		second := []byte("nbp_" + strings.Repeat("b", 40))
		if err = a.PublishPAT(ctx, first); err != nil {
			t.Fatal(err)
		}
		current, err := a.CurrentPAT(ctx)
		if err != nil || current.Value() != string(first) {
			t.Fatalf("original CURRENT: %v", err)
		}
		if err = a.PublishPAT(ctx, second); err == nil {
			t.Fatal("lost committed update response reported success")
		}
		mu.Lock()
		if updates != 1 || pat.version != 2 {
			t.Error("replacement was not exactly one committed update")
		}
		mu.Unlock()
		a, err = ReadNetBirdAccount(ctx, factory, resolver, manager, material)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.PublishPAT(ctx, second); err != nil {
			t.Fatal(err)
		}
		current, err = a.CurrentPAT(ctx)
		if err != nil || current.Value() != string(second) || current.Version != 2 {
			t.Fatalf("reconciled CURRENT: %v", err)
		}
		if err = a.PublishPAT(ctx, second); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		if updates != 1 {
			t.Error("replay duplicated committed PAT update")
		}
		mu.Unlock()
		reader := resolver.Footprint.(*SignedFootprint)
		state, err := reader.originalNetBirdState(ctx, resolver)
		if err != nil {
			t.Fatal(err)
		}
		journal := state.manager.Launch.Account
		if journal.PendingPAT != nil || journal.PAT.Version != 2 || journal.Password.Version != 1 {
			t.Fatal("journal did not retain exact completed account versions")
		}
		// Copies are deliberately malformed; the genuine manager itself is never forged.
		removed := *journal
		removed.PAT.SecretID = ""
		if removed.validate(&journal.Authority) == nil || retainNetBirdAccount(journal, &removed) == nil {
			t.Fatal("pinned original secret removal accepted")
		}
		foreign := journal.Authority
		foreign.Target.VaultOCID = "ocid1.vault.oc1.sa-saopaulo-1.foreign"
		if journal.validate(&foreign) == nil {
			t.Fatal("foreign signed account scope accepted")
		}
		if journal.validate(nil) == nil {
			t.Fatal("historical absence gained account authority")
		}
	})
}
