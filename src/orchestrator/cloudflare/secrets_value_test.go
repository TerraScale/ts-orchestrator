package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func secretTestMetadata(id, name, status string) SecretMetadata {
	return SecretMetadata{ID: id, StoreID: "store-id", Name: name, Status: status, Created: time.Unix(1700000000, 0).UTC(), Modified: time.Unix(1700000001, 0).UTC(), Scopes: []string{"workers"}}
}
func secretTestEnvelope(value any, page, pages int) string {
	result := map[string]any{"success": true, "errors": []any{}, "result": value}
	if page > 0 {
		result["result_info"] = map[string]int{"page": page, "total_pages": pages}
	}
	raw, _ := json.Marshal(result)
	return string(raw)
}
func TestSecretsStoreUsesDocumentedCRUDContract(t *testing.T) {
	const value = "test-key-material"
	requests := 0
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		requests++
		base := "/accounts/acct/secrets_store/stores/store-id/secrets"
		switch requests {
		case 1:
			if call.Method != http.MethodPost || call.Path != base {
				t.Fatalf("unexpected create route: %s %s", call.Method, call.Path)
			}
			var inputs []SecretInput
			if json.Unmarshal([]byte(call.Body), &inputs) != nil || len(inputs) != 1 || inputs[0].Value != value || inputs[0].Name != "current" || !reflect.DeepEqual(inputs[0].Scopes, []string{"workers"}) {
				t.Fatal("create must send the documented root array and value string")
			}
			return 200, secretTestEnvelope([]SecretMetadata{secretTestMetadata("secret-id", "current", "pending")}, 0, 0), nil
		case 2:
			if call.Method != http.MethodPatch || call.Path != base+"/secret-id" {
				t.Fatal("update must address secret ID with PATCH")
			}
			var input SecretUpdate
			if json.Unmarshal([]byte(call.Body), &input) != nil || input.Value == nil || *input.Value != value+"-new" || input.Comment != nil {
				t.Fatal("invalid patch fields")
			}
			return 200, secretTestEnvelope(secretTestMetadata("secret-id", "current", "active"), 0, 0), nil
		case 3:
			if call.Method != http.MethodGet || call.Path != base+"/secret-id" {
				t.Fatal("metadata GET route mismatch")
			}
			metadata := secretTestMetadata("secret-id", "current", "active")
			raw := secretTestEnvelope(metadata, 0, 0)
			// A response must never expose an unexpected value in the returned type.
			raw = strings.Replace(raw, `"result":{`, `"result":{"value":"`+value+`",`, 1)
			return 200, raw, nil
		case 4:
			if call.Method != http.MethodDelete || call.Path != base+"/secret-id" {
				t.Fatal("delete must address secret ID")
			}
			return 200, secretTestEnvelope(nil, 0, 0), nil
		default:
			t.Fatal("unexpected request")
			return 500, "", nil
		}
	})
	c.AccountID = "acct"
	created, err := c.CreateSecret(context.Background(), "store-id", SecretInput{Name: "current", Value: value, Scopes: []string{"workers"}})
	if err != nil || created.ID != "secret-id" || created.Status != "pending" {
		t.Fatalf("create metadata=%+v err=%v", created, err)
	}
	replacement := value + "-new"
	if _, err := c.UpdateSecret(context.Background(), "store-id", created.ID, SecretUpdate{Value: &replacement}); err != nil {
		t.Fatal(err)
	}
	metadata, err := c.GetSecretMetadata(context.Background(), "store-id", created.ID)
	if err != nil || strings.Contains(fmt.Sprint(metadata), value) {
		t.Fatal("metadata retained secret value or failed")
	}
	if err := c.DeleteSecret(context.Background(), "store-id", created.ID); err != nil {
		t.Fatal(err)
	}
	if requests != 4 {
		t.Fatalf("request count %d", requests)
	}
}

func TestSecretsStoreListsEveryPageAndRequiresActiveReferences(t *testing.T) {
	c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
		if strings.Contains(call.Path, "/secrets?") {
			if strings.Contains(call.Path, "page=1&") {
				return 200, secretTestEnvelope([]SecretMetadata{secretTestMetadata("old", "previous", "deleted")}, 1, 2), nil
			}
			return 200, secretTestEnvelope([]SecretMetadata{secretTestMetadata("new", "current", "active")}, 2, 2), nil
		}
		if strings.Contains(call.Path, "page=1&") {
			return 200, secretTestEnvelope([]SecretStore{{ID: "other", Name: "unrelated", Created: time.Unix(1, 0), Modified: time.Unix(2, 0)}}, 1, 2), nil
		}
		return 200, secretTestEnvelope([]SecretStore{{ID: "store-id", Name: "rotation", Created: time.Unix(1, 0), Modified: time.Unix(2, 0)}}, 2, 2), nil
	})
	stores, err := c.ListSecretStores(context.Background())
	if err != nil || len(stores) != 2 {
		t.Fatalf("stores=%v err=%v", stores, err)
	}
	z := Zone{SecretStores: []SecretStoreDecl{{Name: "rotation", SecretNames: []string{"current", "previous"}}}}
	plan := &Plan{}
	if err := z.reconcileSecrets(context.Background(), c, plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Action != Alert || !strings.Contains(plan.Changes[0].Detail, "previous") {
		t.Fatalf("deleted reference accepted: %+v", plan.Changes)
	}
}

func TestSecretsStoreRejectsMalformedPaginationAndMetadata(t *testing.T) {
	for _, failure := range []string{"missing-info", "wrong-page", "duplicate-id", "duplicate-name", "wrong-store", "null", "late-error"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			c, _ := testClient(func(call fakeCall) (int, string, http.Header) {
				calls++
				item := secretTestMetadata(fmt.Sprintf("id-%d", calls), fmt.Sprintf("name-%d", calls), "active")
				if failure == "wrong-store" {
					item.StoreID = "different"
				}
				if calls == 2 && failure == "duplicate-id" {
					item.ID = "id-1"
				}
				if calls == 2 && failure == "duplicate-name" {
					item.Name = "name-1"
				}
				if calls == 2 && failure == "late-error" {
					return 403, `{"success":false,"errors":[{"code":1000,"message":"secret-echo"}]}`, nil
				}
				page := calls
				if failure == "wrong-page" {
					page++
				}
				if failure == "missing-info" {
					page = 0
				}
				var items any = []SecretMetadata{item}
				if failure == "null" {
					items = nil
				}
				return 200, secretTestEnvelope(items, page, 2), nil
			})
			got, err := c.ListSecretMetadata(context.Background(), "store-id")
			if err == nil || got != nil || calls > 2 {
				t.Fatalf("unsafe pagination accepted: calls=%d err=%v", calls, err)
			}
		})
	}
}

type secretsRoundTripFunc func(*http.Request) (*http.Response, error)

func (f secretsRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSecretMutationsNeverRetryOrLeakProviderErrors(t *testing.T) {
	for _, failure := range []string{"transport", "server", "forbidden", "malformed", "unknown-id", "missing-success", "missing-result"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			c := NewClient("token", "zone", "acct")
			c.HTTP = secretsRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Idempotency-Key") != "" {
					t.Fatal("undocumented idempotency assertion")
				}
				if failure == "transport" {
					return nil, errors.New("secret-echo")
				}
				status, body := 200, `{"success":true,"result":null}`
				if failure == "server" {
					status = 503
					body = `{"success":false,"errors":[{"code":1000,"message":"secret-echo"}]}`
				}
				if failure == "forbidden" {
					status = 403
					body = `{"success":false,"errors":[{"code":1000,"message":"secret-echo"}]}`
				}
				if failure == "malformed" {
					body = "secret-echo"
				}
				if failure == "missing-success" {
					body = `{"result":null}`
				}
				if failure == "missing-result" {
					body = `{"success":true}`
				}

				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
			})
			_, err := c.CreateSecret(context.Background(), "store-id", SecretInput{Name: "current", Value: "secret-echo", Scopes: []string{"workers"}})
			if err == nil || strings.Contains(err.Error(), "secret-echo") || calls != 1 {
				t.Fatalf("unsafe outcome: calls=%d err=%v", calls, err)
			}
			if failure != "forbidden" && !errors.Is(err, ErrSecretMutationOutcomeUnknown) {
				t.Fatalf("lost mutation treated as definite failure: %v", err)
			}
			if failure == "forbidden" {
				var api *APIError
				if !errors.As(err, &api) || api.Status != 403 || api.Code != 1000 {
					t.Fatalf("lost provider error contract: %v", err)
				}
			}
		})
	}
}
func TestSecretIDsCannotEscapeAccountOrStoreScope(t *testing.T) {
	c, _ := testClient(func(fakeCall) (int, string, http.Header) { t.Fatal("unsafe ID reached HTTP"); return 500, "", nil })
	for _, id := range []string{"..", "../other", "a/b", "a%2fb", "a?query", "a#fragment", "a\\b", "a\x00b"} {
		if _, err := c.GetSecretMetadata(context.Background(), id, "secret-id"); err == nil {
			t.Fatalf("invalid store admitted: %q", id)
		}
		if err := c.DeleteSecret(context.Background(), "store-id", id); err == nil {
			t.Fatalf("invalid secret ID admitted: %q", id)
		}
	}
}

func TestSecretDeleteRequiresDocumentedSuccessEnvelope(t *testing.T) {
	for _, body := range []string{`{}`, `{"result":null}`, `{"success":true}`, `{"success":"yes","result":null}`} {
		c, _ := testClient(func(fakeCall) (int, string, http.Header) { return 200, body, nil })
		if err := c.DeleteSecret(context.Background(), "store-id", "secret-id"); !errors.Is(err, ErrSecretMutationOutcomeUnknown) {
			t.Fatalf("unverified deletion reported definite outcome: %v", err)
		}
	}
	// The public API's delete result is untyped; null is a valid acknowledgement,
	// never evidence that a particular key generation reached every consumer.
	c, _ := testClient(func(fakeCall) (int, string, http.Header) { return 200, `{"success":true,"result":null}`, nil })
	if err := c.DeleteSecret(context.Background(), "store-id", "secret-id"); err != nil {
		t.Fatal(err)
	}
}
func TestSecretMutationsRejectWrongPublicReceipt(t *testing.T) {
	for _, failure := range []string{"store", "id", "scopes", "comment"} {
		t.Run(failure, func(t *testing.T) {
			c, _ := testClient(func(fakeCall) (int, string, http.Header) {
				v := secretTestMetadata("secret-id", "current", "active")
				v.Comment = "admitted operation"
				switch failure {
				case "store":
					v.StoreID = "other-store"
				case "id":
					v.ID = "other-secret"
				case "scopes":
					v.Scopes = []string{"ai_gateway"}
				case "comment":
					v.Comment = "other operation"
				}
				return 200, secretTestEnvelope(v, 0, 0), nil
			})
			comment := "admitted operation"
			_, err := c.UpdateSecret(context.Background(), "store-id", "secret-id", SecretUpdate{Scopes: []string{"workers"}, Comment: &comment})
			if !errors.Is(err, ErrSecretMutationOutcomeUnknown) {
				t.Fatalf("mismatched %s receipt accepted: %v", failure, err)
			}
		})
	}
}
