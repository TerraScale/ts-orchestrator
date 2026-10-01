package ociregion_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
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
			// a separate implementation process, and an explicit evaluation clock.
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
	request := map[string]any{
		"function": contract.Function, "args": contract.Args, "kwargs": contract.Kwargs,
		"plan": contract.Plan, "argv": contract.Argv, "clock": contract.Clock,
		"dependencies": contract.Dependencies, "responses_by_arguments": contract.ResponsesByArguments,
		"umask": 0o022,
	}
	requestWire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(t.TempDir(), "invocation.json")
	script.Write(t, requestPath, requestWire, 0o600)
	result := script.Python(t, filepath.Join(script.Root(t), "deploy/oci-region/preview.py"), map[string]string{"input_path": requestPath}, previewAPIAdapter)
	if err := json.Unmarshal(result, &observation); err != nil {
		t.Fatal(err)
	}
	if observation.ErrorType != contract.ErrorType || observation.Error != contract.Error {
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

// This bridge only converts wire values, supplies the dependency responses
// chosen by Go, invokes one implementation API, and reports observations.
// Expected values are compared exclusively in Go.
const previewAPIAdapter = `import argparse, base64, datetime, decimal, os, subprocess, types
a = json.loads(pathlib.Path(a["input_path"]).read_text())
os.umask(a["umask"])
def decode(value):
    if isinstance(value, list):
        return [decode(item) for item in value]
    if not isinstance(value, dict):
        return value
    if "$path" in value:
        return pathlib.Path(value["$path"])
    if "$bytes" in value:
        return base64.b64decode(value["$bytes"])
    if "$decimal" in value:
        return decimal.Decimal(value["$decimal"])
    if "$datetime" in value:
        return datetime.datetime.fromisoformat(value["$datetime"])
    if "$namespace" in value:
        return argparse.Namespace(**decode(value["$namespace"]))
    if "$process" in value:
        return subprocess.CompletedProcess(**decode(value["$process"]))
    return {key: decode(item) for key, item in value.items()}
def encode(value):
    if isinstance(value, pathlib.Path):
        return {"$path": str(value)}
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode()}
    if isinstance(value, decimal.Decimal):
        return {"$decimal": str(value)}
    if isinstance(value, datetime.datetime):
        return {"$datetime": value.isoformat()}
    if isinstance(value, (argparse.Namespace, types.SimpleNamespace)):
        return {"$namespace": encode(vars(value))}
    if isinstance(value, subprocess.CompletedProcess):
        return {"$process": encode({"args": value.args, "returncode": value.returncode, "stdout": value.stdout, "stderr": value.stderr})}
    if isinstance(value, dict):
        return {key: encode(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode(item) for item in value]
    return value
clock = datetime.datetime.fromisoformat(a["clock"])
class Clock(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return clock.astimezone(tz) if tz else clock.replace(tzinfo=None)
m.dt.datetime = Clock
m.PLAN = pathlib.Path(a["plan"])
m.sys.argv = a["argv"]
operation = getattr(m, a["function"])
calls = []
keyed_responses = {key: iter(rows) for key, rows in (a.get("responses_by_arguments") or {}).items()}
def dependency(name):
    def invoke(*args, **kwargs):
        observation = {"name": name, "args": encode(args), "kwargs": encode(kwargs)}
        calls.append(observation)
        key = json.dumps([name, encode(args), encode(kwargs)], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        selected = keyed_responses.get(key, iter(()))
        response = next(selected, None)
        if response is None:
            observation.update(error="unconfigured dependency call", error_type="RuntimeError")
            raise RuntimeError("unconfigured dependency call")
        if "error_type" in response:
            observation.update(error=response["error"], error_type=response["error_type"])
            raise getattr(__import__("builtins"), response["error_type"])(response["error"])
        observation["result"] = response.get("result")
        return decode(response.get("result"))
    return invoke
# Block unconfigured process/cloud access as well as recording selected stubs.
m.oci = dependency("oci")
m.checked_tool = dependency("checked_tool")
m.subprocess.run = dependency("subprocess.run")
for name in a["dependencies"]:
    if name == "subprocess.run":
        continue
    setattr(m, name, dependency(name))
try:
    result = {"result": encode(operation(*decode(a["args"]), **decode(a["kwargs"])))}
except Exception as exc:
    result = {"error": str(exc), "error_type": type(exc).__name__}
result["calls"] = calls`
