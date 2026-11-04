package cli

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
)

const observeOperationDatabase = "0000000000WVSMBJNMAWCDJBSK"
const observeOperationPartition = "0000000000Z3WK359G2W66CVT8"
const observeOperationDomainID = "7E5HKSCCJSQJGMM2DVVHCQDQFV"
const observeOperationMutationID = "0000000000SQ81DF1FR1ZA1QQB"
const observeOperationRecordedAt = "2026-10-17T00:00:00.123456789Z"

// These are the redacted HTTP contracts; runtime producer qualification is separate.
func observeOperationContract(view string) (string, string, []string) {
	commit := `"cell":"gru","commit":{"mutation_operation_id":"` + observeOperationMutationID + `","sequence":1152921504606846977,"epoch":1152921504606846977,"recorded_at":"` + observeOperationRecordedAt + `"}`
	selectors := []string{"--database", observeOperationDatabase, "--partition", observeOperationPartition}
	switch view {
	case "foundation":
		return "/v1/regions/gru/foundation", `{"schemaVersion":1,"cell":"GRU","ociRegion":"sa-saopaulo-1","operationId":"` + observeOperationDomainID + `","generation":1152921504606846977,"epoch":1152921504606846977,"stage":"blocked","reason":"foundation-unavailable","startedAt":"` + observeOperationRecordedAt + `","updatedAt":"` + observeOperationRecordedAt + `","checkpoints":[{"kind":"resource","key":"vault","resourceId":"ocid1.vault.oc1.sa-saopaulo-1.owned"}],"secret":"private-source-secret"}`, []string{"--cell", "gru"}
	case "credentials":
		return "/v1/operations/credentials/" + observeOperationDatabase + "/" + observeOperationPartition,
			`{` + commit + `,"credential":{"database_id":"` + observeOperationDatabase + `","partition_id":"` + observeOperationPartition + `","initial_receipt_sha256":"` + strings.Repeat("a", 64) + `","generation":1152921504606846977,"state_sha256":"` + strings.Repeat("b", 64) + `","status":"pending","members":[{"seat_id":"seat-a","member_id":"member-a","node":"node-a","generation":1152921504606846977,"applied":true,"secret":"private-source-secret"},{"seat_id":"seat-b","member_id":"member-b","applied":false}],"secret":"private-source-secret"},"secret":"private-source-secret"}`, selectors
	case "backups":
		return "/v1/operations/backups/" + observeOperationDatabase + "/" + observeOperationPartition,
			`{` + commit + `,"database_id":"` + observeOperationDatabase + `","partition_id":"` + observeOperationPartition + `","operation_id":"` + observeOperationDomainID + `","state":"uncertain","ordinal":1152921504606846977,"attempt":1152921504606846977,"publication_receipt":"private-source-secret"}`, selectors
	default:
		return "/v1/operations/netbird", `{` + commit + `,"operation_id":"` + observeOperationDomainID + `","node":"node-a","phase":"install","started_at":"` + observeOperationRecordedAt + `","deadline":"2026-10-17T00:03:00.123456789Z","rollback_required":false,"recovery_complete":false,"recovery_returning":true,"fence":"private-source-secret"}`, nil
	}
}

func TestObserveCurrentOperationHTTP(t *testing.T) {
	f := newObserveFixture(t)
	f.server.HandleAuthenticated("GET /v1/regions", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `[{"cell":"gru"}]`)
	}))
	for _, view := range []string{"foundation", "credentials", "backups", "netbird"} {
		path, wire, flags := observeOperationContract(view)
		f.server.HandleAuthenticated("GET "+path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+f.token || r.Header.Get("Accept") != "application/json" {
				t.Errorf("observation request lost exact path, selectors or authentication: %s", r.URL.Path)
			}
			_, _ = io.WriteString(w, wire)
		}))
		for _, format := range []string{"json"} {
			t.Run(view+"/"+format, func(t *testing.T) {
				output, err := f.run(t, view, append(flags, "--format", format)...)
				if err != nil || !strings.Contains(output, "1152921504606846977") || !strings.Contains(output, observeOperationRecordedAt) || strings.Contains(output, "private-source-secret") {
					t.Fatalf("observation lost precision or exposed excluded fields: %s, %v", output, err)
				}
				if view != "credentials" && !strings.Contains(output, observeOperationDomainID) || view != "foundation" && !strings.Contains(output, observeOperationMutationID) {
					t.Fatalf("domain/mutation identity missing: %s", output)
				}
				if view == "credentials" || view == "backups" {
					if !strings.Contains(output, observeOperationDatabase) || !strings.Contains(output, observeOperationPartition) {
						t.Fatalf("partition identity changed: %s", output)
					}
				}
				if format == "json" {
					var envelope struct {
						Version int            `json:"version"`
						View    string         `json:"view"`
						Source  string         `json:"source"`
						Partial bool           `json:"partial"`
						Data    jsontext.Value `json:"data"`
					}
					if err := json.Unmarshal([]byte(output), &envelope); err != nil || envelope.Version != 1 || envelope.View != view || envelope.Source != f.http.URL || envelope.Partial || len(envelope.Data) == 0 {
						t.Fatalf("invalid versioned observation: %s, %v", output, err)
					}
					if view == "foundation" && strings.Contains(output, "completedAt") || view == "netbird" && !strings.Contains(output, `"rollback_required": false`) {
						t.Fatalf("unknown completion or explicit rollback false changed: %s", output)
					}
				}
			})
		}
		response, err := f.http.Client().Get(f.http.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s = %d", view, response.StatusCode)
		}
	}
	if output, err := f.run(t, "foundation"); err != nil || !strings.Contains(output, "GRU") {
		t.Fatalf("foundation local-region discovery failed: %s, %v", output, err)
	}
}
