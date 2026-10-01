package ci

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtureToken = "fixture-token-do-not-log"
const fixtureTag = "image-inputs-fixture"
const assetUUID = "fixture-asset-uuid"
const secretQuery = "fixture-secret-query-do-not-log"
const successBody = "{\"schema\":\"fixture.image-inputs.v1\"}\n"
const errorBody = "Not Found\n"

type attachmentRequest struct {
	Path       string
	Authorized bool
}
type attachmentState struct {
	mu                sync.Mutex
	mode              string
	private, draft    bool
	size              int
	browser, redirect string
	requests          []attachmentRequest
}

func (s *attachmentState) snapshot() []attachmentRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]attachmentRequest(nil), s.requests...)
}
func (s *attachmentState) attachmentAuth() []bool {
	var out []bool
	for _, r := range s.snapshot() {
		if strings.HasPrefix(r.Path, "/attachments/") {
			out = append(out, r.Authorized)
		}
	}
	return out
}
func (s *attachmentState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, attachmentRequest{r.URL.Path, r.Header.Get("Authorization") != ""})
	s.mu.Unlock()
	body := func(status int, data string) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(data))
	}
	jsonBody := func(value any) {
		wire, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(wire)
	}
	attachment := map[string]any{"id": 33, "uuid": assetUUID, "name": "image-inputs.json", "size": s.size, "browser_download_url": s.browser}
	release := map[string]any{"id": 22, "tag_name": fixtureTag, "name": fixtureTag, "draft": s.draft, "prerelease": true, "assets": []any{attachment}}
	switch r.URL.Path {
	case "/objects/" + assetUUID:
		body(200, successBody)
	case "/api/v1/version":
		jsonBody(map[string]any{"version": "v16.0.0-fixture"})
	case "/api/v1/repos/search":
		jsonBody(map[string]any{"data": []any{}})
	case "/api/v1/repos/TerraScale/ts-orchestrator":
		jsonBody(map[string]any{"private": s.private})
	case "/api/v1/repos/TerraScale/ts-orchestrator/releases/tags/" + fixtureTag:
		jsonBody(release)
	case "/api/v1/repos/TerraScale/ts-orchestrator/releases":
		w.Header().Set("X-Total-Count", "1")
		jsonBody([]any{release})
	case "/api/v1/repos/TerraScale/ts-orchestrator/releases/22/assets/33":
		jsonBody(attachment)
	case "/attachments/" + assetUUID:
		if s.mode == "error-body" {
			body(404, errorBody)
			return
		}
		if s.mode == "redirect" {
			w.Header().Set("Location", s.redirect)
			w.WriteHeader(302)
			return
		}
		if (s.mode == "auth-vs-anonymous" || s.mode == "private") && r.Header.Get("Authorization") != "token "+fixtureToken {
			body(404, errorBody)
			return
		}
		body(200, successBody)
	default:
		body(404, errorBody)
	}
}

type probeRoute struct {
	Status            *int     `json:"status"`
	BodyBytes         int      `json:"body_bytes"`
	BodySHA256        string   `json:"body_sha256"`
	SentAuthorization bool     `json:"sent_authorization"`
	MatchesExpected   bool     `json:"matches_expected"`
	Skipped           bool     `json:"skipped"`
	RedirectCount     int      `json:"redirect_count"`
	InitialOrigin     string   `json:"initial_origin"`
	FinalOrigin       string   `json:"final_origin"`
	RedirectOrigins   []string `json:"redirect_origins"`
	Error             string   `json:"error"`
}
type attachmentReport struct {
	Authenticated probeRoute `json:"authenticated"`
	Anonymous     probeRoute `json:"anonymous"`
	URLComparison struct {
		OriginEqual bool `json:"origin_equal"`
	} `json:"url_comparison"`
}

func fjCommand(t *testing.T, binary, origin, home, stdin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), binary, append([]string{"--host", origin}, args...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "XDG_DATA_HOME=" + home, "NO_COLOR=1", "TERM=dumb", "LANG=C.UTF-8"}
	if value := os.Getenv("LD_LIBRARY_PATH"); value != "" {
		cmd.Env = append(cmd.Env, "LD_LIBRARY_PATH="+value)
	}
	cmd.Stdin = strings.NewReader(stdin)
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	cmd.WaitDelay = 20 * time.Second
	err := cmd.Run()
	if err != nil && cmd.ProcessState == nil {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errout.String()
}
func noSensitiveOutput(t *testing.T, out, stderr string) {
	t.Helper()
	lines := strings.Split(out+stderr, "\n")
	var sanitized []string
	for i := 0; i < len(lines); i++ {
		if lines[i] == "Location:" && i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "src/release/probe.rs:") {
			i++
			continue
		}
		sanitized = append(sanitized, lines[i])
	}
	combined := strings.Join(sanitized, "\n")
	for _, value := range []string{fixtureToken, assetUUID, secretQuery, "/attachments/", "/objects/", "Authorization", "Location"} {
		if strings.Contains(combined, value) {
			t.Fatalf("fj output exposed sensitive field %q", value)
		}
	}
}

// The real pinned client is verified after both builds and cache hits by
// prepare-fj-admission.sh. Ordinary go test skips only this external binary
// contract when no binary has been supplied.
func TestFJAttachmentProbe(t *testing.T) {
	binary := os.Getenv("TS_FJ_PROBE_BINARY")
	if binary == "" {
		t.Skip("TS_FJ_PROBE_BINARY not supplied; prepare-fj-admission.sh runs this contract on the pinned client")
	}
	absolute, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	binary = absolute
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("pinned fj binary is not executable")
	}
	for _, name := range []string{"error_body", "download_http_status", "download_success", "auth_vs_anonymous", "redirect", "private", "draft", "strict_pins", "cross_origin_browser", "download_cross_origin", "download_redirect"} {
		t.Run(name, func(t *testing.T) {
			sinkState := &attachmentState{mode: "object"}
			sink := httptest.NewServer(sinkState)
			defer sink.Close()
			state := &attachmentState{mode: "auth-vs-anonymous", size: len(successBody)}
			server := httptest.NewServer(state)
			defer server.Close()
			state.browser = server.URL + "/attachments/" + assetUUID
			state.redirect = sink.URL + "/objects/" + assetUUID + "?" + secretQuery + "=value"
			switch name {
			case "error_body", "download_http_status":
				state.mode = "error-body"
				state.size = 3294
			case "redirect", "download_redirect":
				state.mode = "redirect"
			case "private":
				state.mode = "private"
				state.private = true
			case "draft":
				state.mode = "private"
				state.draft = true
			case "cross_origin_browser", "download_cross_origin":
				state.mode = "private"
				state.browser = state.redirect
			case "strict_pins":
				state.mode = "private"
			}
			home := t.TempDir()
			if err := os.Chmod(home, 0o700); err != nil {
				t.Fatal(err)
			}
			code, _, stderr := fjCommand(t, binary, server.URL, home, fixtureToken+"\n", "auth", "add-token")
			if code != 0 {
				t.Fatal("fixture token setup failed", stderr)
			}
			if strings.HasPrefix(name, "download_") {
				output := filepath.Join(home, "downloaded-asset")
				code, out, stderr := fjCommand(t, binary, server.URL, home, "", "release", "--repo", "TerraScale/ts-orchestrator", "asset", "download", fixtureTag, "image-inputs.json", "--output", output)
				noSensitiveOutput(t, out, stderr)
				data, err := os.ReadFile(output)
				success := name == "download_success" || name == "download_redirect"
				if success {
					if code != 0 || err != nil || string(data) != successBody {
						t.Fatal("download did not return exact bytes")
					}
				} else if code == 0 || !os.IsNotExist(err) {
					t.Fatal("rejected attachment was accepted or written")
				}
				if name == "download_http_status" && !strings.Contains(stderr, "release attachment HTTP status 404") {
					t.Fatal("HTTP status was not safely reported")
				}
				if name == "download_cross_origin" {
					if len(state.attachmentAuth()) != 0 || len(sinkState.snapshot()) != 0 {
						t.Fatal("request sent to untrusted initial origin")
					}
				} else if !reflect.DeepEqual(state.attachmentAuth(), []bool{true}) {
					t.Fatal("download did not use exactly one authenticated attachment request")
				}
				if name == "download_redirect" {
					for _, r := range sinkState.snapshot() {
						if r.Authorized {
							t.Fatal("authorization reached cross-origin redirect")
						}
					}
				}
				return
			}
			probe := func(hash string, size int) (int, attachmentReport) {
				t.Helper()
				code, out, stderr := fjCommand(t, binary, server.URL, home, "", "release", "--repo", "TerraScale/ts-orchestrator", "asset", "probe", fixtureTag, "image-inputs.json", "--expect-sha256", hash, "--expect-bytes", strconv.Itoa(size), "--compare-anonymous")
				noSensitiveOutput(t, out, stderr)
				var report attachmentReport
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal("probe did not return one JSON diagnostic object", err)
				}
				return code, report
			}
			hash := digest([]byte(successBody))
			size := len(successBody)
			if name == "error_body" {
				hash = "773dd889b55136d4b8569560c47b823232eace81a5ccb262cb5aa9970594dd97"
				size = 3294
			}
			if name == "strict_pins" {
				for _, pin := range []struct {
					hash string
					size int
				}{{strings.Repeat("0", 64), size}, {hash, size + 1}} {
					code, report := probe(pin.hash, pin.size)
					if code == 0 || report.Authenticated.MatchesExpected {
						t.Fatal("mismatched content pin accepted")
					}
				}
				return
			}
			code, report := probe(hash, size)
			a := report.Authenticated
			switch name {
			case "error_body":
				if code == 0 || a.Status == nil || *a.Status != 404 || a.BodyBytes != len(errorBody) || a.BodySHA256 != digest([]byte(errorBody)) || !a.SentAuthorization {
					t.Fatalf("invalid HTTP error observation: %+v", a)
				}
			case "cross_origin_browser":
				if code == 0 || a.Status != nil || a.SentAuthorization || a.Error != "origin_mismatch" || report.URLComparison.OriginEqual {
					t.Fatalf("initial origin mismatch not rejected: %+v", report)
				}
				if len(state.attachmentAuth()) != 0 {
					t.Fatal("unexpected authenticated request")
				}
			default:
				if code != 0 || a.Status == nil || *a.Status != 200 || !a.MatchesExpected || !a.SentAuthorization {
					t.Fatalf("valid authenticated route rejected: %+v", a)
				}
			}
			if name == "auth_vs_anonymous" {
				if report.Anonymous.Skipped || report.Anonymous.Status == nil || *report.Anonymous.Status != 404 || !reflect.DeepEqual(state.attachmentAuth(), []bool{true, false}) {
					t.Fatalf("anonymous comparison boundary: %+v", report)
				}
			}
			if name == "private" || name == "draft" {
				if !report.Anonymous.Skipped || !reflect.DeepEqual(state.attachmentAuth(), []bool{true}) {
					t.Fatal("private/draft anonymous route was attempted")
				}
			}
			if name == "redirect" {
				if a.RedirectCount != 1 || a.InitialOrigin != server.URL || a.FinalOrigin != sink.URL || !reflect.DeepEqual(a.RedirectOrigins, []string{sink.URL}) {
					t.Fatalf("redirect origins not sanitized: %+v", a)
				}
			}
			if name == "redirect" || name == "cross_origin_browser" {
				for _, r := range sinkState.snapshot() {
					if r.Authorized {
						t.Fatal("authorization reached untrusted origin")
					}
				}
			}
		})
	}
}
