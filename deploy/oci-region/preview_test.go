package ociregion_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/TerraScale/ts-orchestrator/internal/testutil/script"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// These are data snapshots of API inputs and their observable contracts, not
// executable test bodies. Go owns case selection, filesystem setup, clock,
// dependency responses, and all result/exception/interaction assertions.
type previewContract struct {
	Test                 string                 `json:"test"`
	Function             string                 `json:"function"`
	Args                 any                    `json:"args"`
	Kwargs               any                    `json:"kwargs"`
	Plan                 string                 `json:"plan"`
	Argv                 []string               `json:"argv"`
	Clock                string                 `json:"clock"`
	Files                map[string]previewFile `json:"files"`
	Writes               map[string]previewFile `json:"writes"`
	Deleted              []string               `json:"deleted"`
	Dependencies         []string               `json:"dependencies"`
	Result               any                    `json:"result"`
	Error                string                 `json:"error"`
	ErrorType            string                 `json:"error_type"`
	Calls                []any                  `json:"calls"`
	ResponsesByArguments map[string][]any       `json:"responses_by_arguments"`
}

type previewFile struct {
	Data string `json:"data"`
	Mode uint32 `json:"mode"`
}

type previewObservation struct {
	Result    any    `json:"result"`
	Error     string `json:"error"`
	ErrorType string `json:"error_type"`
	Calls     []any  `json:"calls"`
}

func TestPreviewAdmissionContracts(t *testing.T) {
	runPreviewContracts(t, "PreviewAdmissionTests.", 48)
}

func runPreviewContracts(t *testing.T, prefix string, methodCount int) {
	t.Helper()
	var table struct {
		SchemaVersion int            `json:"schema_version"`
		SourceRoot    string         `json:"source_root"`
		Fixtures      map[string]any `json:"fixtures"`
		Cases         []any          `json:"cases"`
	}
	path := filepath.Join(script.Root(t), "deploy/oci-region/testdata/preview-contracts.json")
	if err := json.Unmarshal(script.Read(t, path), &table); err != nil {
		t.Fatal(err)
	}
	if table.SchemaVersion != 1 || table.SourceRoot == "" {
		t.Fatalf("unknown preview fixture schema %d", table.SchemaVersion)
	}
	methods := map[string]int{}
	for _, value := range table.Cases {
		wire, err := json.Marshal(expandPreviewFixture(t, table.Fixtures, value))
		if err != nil {
			t.Fatal(err)
		}
		var contract previewContract
		if err := json.Unmarshal(wire, &contract); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(contract.Test, prefix) {
			continue
		}
		methods[contract.Test]++
		name := fmt.Sprintf("%s/%03d_%s", strings.TrimPrefix(contract.Test, prefix), methods[contract.Test], contract.Function)
		t.Run(name, func(t *testing.T) {
			// Parallel execution is safe: every case receives independent files,
			// an independent native API engine, and an explicit evaluation clock.
			t.Parallel()
			runPreviewContract(t, wire, table.SourceRoot)
		})
	}
	if len(methods) != methodCount {
		t.Fatalf("preserved %d original methods, want %d", len(methods), methodCount)
	}
}

func expandPreviewFixture(t *testing.T, fixtures map[string]any, value any) any {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		if reference, ok := value["$fixture"].(string); ok {
			fixture, exists := fixtures[reference]
			if !exists || len(value) != 1 {
				t.Fatalf("invalid preview fixture reference %q", reference)
			}
			return expandPreviewFixture(t, fixtures, fixture)
		}
		result := make(map[string]any, len(value))
		for key, field := range value {
			result[key] = expandPreviewFixture(t, fixtures, field)
		}
		return result
	case []any:
		result := make([]any, len(value))
		for i, item := range value {
			result[i] = expandPreviewFixture(t, fixtures, item)
		}
		return result
	default:
		return value
	}
}

var previewTemporaryPath = regexp.MustCompile(`/tmp/tmp[^/"\\\s]+`)

func runPreviewContract(t *testing.T, originalWire []byte, sourceRoot string) {
	t.Helper()
	var original previewContract
	if err := json.Unmarshal(originalWire, &original); err != nil {
		t.Fatal(err)
	}
	// Move fixture paths into this test's directory, including deliberately
	// missing paths and output files that did not exist before the operation.
	directory := t.TempDir()
	origins := slices.Compact(slices.Sorted(slices.Values(previewTemporaryPath.FindAllString(string(originalWire), -1))))
	replacements := make([]string, 0, len(origins)*2+2)
	for i, origin := range origins {
		replacements = append(replacements, origin, filepath.Join(directory, fmt.Sprintf("scope-%03d", i)))
	}
	replacements = append(replacements, sourceRoot, script.Root(t))
	paths := strings.NewReplacer(replacements...)

	// Rebinding local-file paths changes projection hashes. Recalculate hash
	// references from the original bytes in dependency order, leaving deliberately
	// stale/wrong hashes untouched. Inputs and expected writes share the mapping.
	allFiles := maps.Clone(original.Files)
	for path, file := range original.Writes {
		allFiles[path+"$output"] = file
	}
	hashes := map[string]string{}
	for round := range 8 {
		next := make(map[string]string, len(allFiles))
		for _, file := range allFiles {
			data := decodePreviewFile(t, file)
			next[previewSHA(data)] = previewSHA([]byte(rewritePreviewText(paths.Replace(string(data)), hashes)))
		}
		if reflect.DeepEqual(next, hashes) {
			break
		}
		hashes = next
		if round == 7 {
			t.Fatal("preview fixture hash references did not converge")
		}
	}
	var value any
	if err := json.Unmarshal(originalWire, &value); err != nil {
		t.Fatal(err)
	}
	value = rebindPreviewValue(t, value, paths, hashes)
	wire, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var contract previewContract
	if err := json.Unmarshal(wire, &contract); err != nil {
		t.Fatal(err)
	}
	for path, file := range contract.Files {
		script.Write(t, path, decodePreviewFile(t, file), fs.FileMode(file.Mode))
	}
	// Direct load_plan calls may use the checked-in plan; all temporary PLAN
	// overrides and CLI arguments are carried in the case data.
	var observation previewObservation
	contract.ResponsesByArguments = map[string][]any{}
	for _, call := range contract.Calls {
		row := call.(map[string]any)
		key := previewJSON(t, []any{row["name"], row["args"], row["kwargs"]})
		contract.ResponsesByArguments[key] = append(contract.ResponsesByArguments[key], row)
	}
	// The adapter receives only invocation inputs and dependency responses;
	// expected API results, exceptions, and filesystem assertions stay in Go.
	clock, err := time.Parse(time.RFC3339Nano, contract.Clock)
	if err != nil {
		t.Fatal(err)
	}
	overrides := map[string]bool{}
	for _, name := range contract.Dependencies {
		overrides[name] = true
	}
	calls := []any{}
	engine := &ociregion.Engine{Context: t.Context(), PlanPath: contract.Plan, Clock: func() time.Time { return clock }, Argv: contract.Argv, Overrides: overrides}
	engine.Dependency = func(name string, args []any, kwargs map[string]any) (any, error) {
		observation := map[string]any{"name": name, "args": ociregion.EncodeInvocation(args), "kwargs": ociregion.EncodeInvocation(kwargs)}
		calls = append(calls, observation)
		key := previewJSON(t, []any{name, observation["args"], observation["kwargs"]})
		responses := contract.ResponsesByArguments[key]
		if len(responses) == 0 {
			observation["error"] = "unconfigured dependency call"
			observation["error_type"] = "RuntimeError"
			return nil, ociregion.Failure{Message: "unconfigured dependency call", Kind: "RuntimeError"}
		}
		contract.ResponsesByArguments[key] = responses[1:]
		response := responses[0].(map[string]any)
		if kind, ok := response["error_type"].(string); ok {
			observation["error"] = response["error"]
			observation["error_type"] = kind
			return nil, ociregion.Failure{Message: response["error"].(string), Kind: kind}
		}
		observation["result"] = response["result"]
		return ociregion.DecodeInvocation(response["result"]), nil
	}
	var result any
	var operationErr error
	if contract.Function == "oci" {
		// Legacy direct OCI captures now exercise the actual SDK boundary.
		// Each client has its own signer and local endpoint; no operator
		// configuration, shared transport or external process is involved.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
				t.Error("preview SDK request lacks its synthetic signature")
			}
			response, err := engine.Dependency("http", []any{r.Method, r.URL.Path}, map[string]any{"query": r.URL.RawQuery})
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			row := response.(map[string]any)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(int(row["status"].(float64)))
			_, _ = io.WriteString(w, row["body"].(string))
		}))
		t.Cleanup(server.Close)
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..preview", "ocid1.user.oc1..preview", "sa-saopaulo-1", "preview",
			string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
		factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
		if err != nil {
			t.Fatal(err)
		}
		args := ociregion.DecodeInvocation(contract.Args).([]any)
		words := make([]string, len(args))
		for i, arg := range args {
			words[i] = arg.(string)
		}
		data, handled, err := sdkcli.NewClient(factory, server.URL).Call(t.Context(), words)
		server.Close()
		if !handled {
			t.Fatalf("direct OCI capture escaped its SDK handler: %v", err)
		}
		if err != nil {
			operationErr = ociregion.Failure{Message: err.Error(), Kind: "ValueError"}
		} else if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
	} else {
		result, operationErr = engine.Invoke(contract.Function, ociregion.DecodeInvocation(contract.Args).([]any), ociregion.DecodeInvocation(contract.Kwargs).(map[string]any))
	}
	callWire, err := json.Marshal(calls)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(callWire, &observation.Calls); err != nil {
		t.Fatal(err)
	}
	if operationErr != nil {
		observation.Error = operationErr.Error()
		observation.ErrorType = "OSError"
		if typed, ok := errors.AsType[ociregion.Failure](operationErr); ok {
			observation.ErrorType = typed.Kind
		}
	} else {
		// The wire normalization preserves the original observable number types.
		encoded, err := json.Marshal(ociregion.EncodeInvocation(result))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &observation.Result); err != nil {
			t.Fatal(err)
		}
	}
	errorMatches := observation.Error == contract.Error
	if contract.Function == "oci" && contract.Error != "" {
		// SDK decoder diagnostics include response URLs and Go model names;
		// captures pin their stable cause and still require the error type.
		errorMatches = strings.Contains(observation.Error, contract.Error)
	}
	if observation.ErrorType != contract.ErrorType || !errorMatches {
		t.Errorf("exception = %s(%q), want %s(%q)", observation.ErrorType, observation.Error, contract.ErrorType, contract.Error)
	}
	if !reflect.DeepEqual(observation.Result, contract.Result) {
		t.Errorf("API result:\n got: %s\nwant: %s", previewJSON(t, observation.Result), previewJSON(t, contract.Result))
	}
	gotCalls, wantCalls := observation.Calls, contract.Calls
	if contract.Function == "collect_inventory" {
		// Inventory collection intentionally issues independent reads
		// concurrently. Pin the complete multiset rather than scheduler order.
		gotCalls, wantCalls = sortedPreviewCalls(t, gotCalls), sortedPreviewCalls(t, wantCalls)
	} else if contract.Function == "main" && len(contract.Argv) > 1 && contract.Argv[1] == "import-inventory" {
		gotCalls, wantCalls = normalizePreviewObjectReads(t, gotCalls), normalizePreviewObjectReads(t, wantCalls)
	}
	if !reflect.DeepEqual(gotCalls, wantCalls) {
		t.Errorf("dependency call count = %d, want %d", len(gotCalls), len(wantCalls))
		for i := range min(len(gotCalls), len(wantCalls)) {
			if !reflect.DeepEqual(gotCalls[i], wantCalls[i]) {
				t.Errorf("dependency call %d:\n got: %s\nwant: %s", i, previewJSON(t, gotCalls[i]), previewJSON(t, wantCalls[i]))
				break
			}
		}
	}
	wantFiles := maps.Clone(contract.Files)
	maps.Copy(wantFiles, contract.Writes)
	for _, path := range contract.Deleted {
		delete(wantFiles, path)
	}
	for path, file := range wantFiles {
		data := script.Read(t, path)
		assertPreviewFile(t, path, data, decodePreviewFile(t, file))
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != fs.FileMode(file.Mode) {
			t.Errorf("%s permissions = %o, want %o", path, info.Mode().Perm(), file.Mode)
		}
	}
	if err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			if _, exists := wantFiles[path]; !exists {
				t.Errorf("unexpected output file: %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func decodePreviewFile(t *testing.T, file previewFile) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(file.Data)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func previewSHA(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func rewritePreviewText(text string, hashes map[string]string) string {
	keys := slices.Sorted(maps.Keys(hashes))
	pairs := make([]string, 0, len(keys)*2)
	for _, hash := range keys {
		pairs = append(pairs, hash, hashes[hash])
	}
	return strings.NewReplacer(pairs...).Replace(text)
}

func rebindPreviewValue(t *testing.T, value any, paths *strings.Replacer, hashes map[string]string) any {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, field := range value {
			// Serialized fixture files and bytes contain paths/hash references too.
			encodedFile := key == "data" && value["mode"] != nil
			if text, ok := field.(string); (encodedFile || key == "$bytes") && ok {
				data, err := base64.StdEncoding.DecodeString(text)
				if err != nil {
					t.Fatal(err)
				}
				field = base64.StdEncoding.EncodeToString([]byte(rewritePreviewText(paths.Replace(string(data)), hashes)))
				result[paths.Replace(key)] = field
			} else {
				result[paths.Replace(key)] = rebindPreviewValue(t, field, paths, hashes)
			}
		}
		return result
	case []any:
		result := make([]any, len(value))
		for i, field := range value {
			result[i] = rebindPreviewValue(t, field, paths, hashes)
		}
		return result
	case string:
		return rewritePreviewText(paths.Replace(value), hashes)
	default:
		return value
	}
}

func previewJSON(t *testing.T, value any) string {
	t.Helper()
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func sortedPreviewCalls(t *testing.T, calls []any) []any {
	t.Helper()
	result := slices.Clone(calls)
	slices.SortFunc(result, func(left, right any) int {
		return strings.Compare(previewJSON(t, left), previewJSON(t, right))
	})
	return result
}

func normalizePreviewObjectReads(t *testing.T, calls []any) []any {
	t.Helper()
	result := slices.Clone(calls)
	for start := 0; start < len(result); {
		end := start
		for end < len(result) {
			row := result[end].(map[string]any)
			args := row["args"].([]any)
			if row["name"] != "oci" || len(args) < 3 || args[0] != "os" || args[1] != "object" || (args[2] != "list" && args[2] != "list-object-versions") {
				break
			}
			end++
		}
		copy(result[start:end], sortedPreviewCalls(t, result[start:end]))
		start = max(start+1, end)
	}
	return result
}

func assertPreviewFile(t *testing.T, path string, got, want []byte) {
	t.Helper()
	// The CLI controls JSON serialization whitespace. Compare the entire JSON
	// value while requiring exact bytes for image files and other binary inputs.
	var gotJSON, wantJSON any
	if json.Unmarshal(got, &gotJSON) == nil && json.Unmarshal(want, &wantJSON) == nil {
		if !reflect.DeepEqual(gotJSON, wantJSON) {
			t.Errorf("%s JSON contents differ:\n got: %s\nwant: %s", path, got, want)
		}
	} else if string(got) != string(want) {
		t.Errorf("%s bytes differ:\n got: %q\nwant: %q", path, got, want)
	}
}
