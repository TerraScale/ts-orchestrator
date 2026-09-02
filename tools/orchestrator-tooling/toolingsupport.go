package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ToolValidationException mirrors the C# ToolValidationException: a distinct
// set of validation errors, each reported on its own line with exit code 1.
type toolValidationException struct {
	errorsList []string
}

func (e *toolValidationException) Error() string {
	return strings.Join(e.errorsList, "\n")
}

func newToolValidationException(errs []string) *toolValidationException {
	distinct := make([]string, 0, len(errs))
	seen := make(map[string]bool, len(errs))
	for _, item := range errs {
		if seen[item] {
			continue
		}
		seen[item] = true
		distinct = append(distinct, item)
	}
	return &toolValidationException{errorsList: distinct}
}

func isToolValidationException(err error) bool {
	var validation *toolValidationException
	return errors.As(err, &validation)
}

// JsonObject is an insertion-ordered JSON object mirroring
// System.Text.Json.Nodes.JsonObject.
type JsonObject struct {
	keys   []string
	values map[string]any
}

func newJsonObject() *JsonObject {
	return &JsonObject{values: make(map[string]any)}
}

// Get returns the value for key, or nil when missing (like the C# indexer).
func (o *JsonObject) Get(key string) any {
	if o == nil {
		return nil
	}
	return o.values[key]
}

func (o *JsonObject) Has(key string) bool {
	if o == nil {
		return false
	}
	_, ok := o.values[key]
	return ok
}

func (o *JsonObject) Set(key string, value any) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *JsonObject) Remove(key string) bool {
	if _, exists := o.values[key]; !exists {
		return false
	}
	delete(o.values, key)
	for index, item := range o.keys {
		if item == key {
			o.keys = append(o.keys[:index], o.keys[index+1:]...)
			break
		}
	}
	return true
}

func (o *JsonObject) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

// Keys returns the key insertion order.
func (o *JsonObject) Keys() []string {
	if o == nil {
		return nil
	}
	return append([]string(nil), o.keys...)
}

func (o *JsonObject) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, key := range o.keys {
		if index > 0 {
			buffer.WriteByte(',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buffer.Write(encodedKey)
		buffer.WriteByte(':')
		encodedValue, err := json.Marshal(o.values[key])
		if err != nil {
			return nil, err
		}
		buffer.Write(encodedValue)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// JsonArray mirrors System.Text.Json.Nodes.JsonArray.
type JsonArray struct {
	items []any
}

func (a *JsonArray) Len() int {
	if a == nil {
		return 0
	}
	return len(a.items)
}

func (a *JsonArray) Get(index int) any {
	if a == nil || index < 0 || index >= len(a.items) {
		return nil
	}
	return a.items[index]
}

func (a *JsonArray) Set(index int, value any) {
	a.items[index] = value
}

func (a *JsonArray) Append(value any) {
	a.items = append(a.items, value)
}

func (a *JsonArray) RemoveAt(index int) {
	a.items = append(a.items[:index], a.items[index+1:]...)
}

func (a *JsonArray) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('[')
	for index, item := range a.items {
		if index > 0 {
			buffer.WriteByte(',')
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		buffer.Write(encoded)
	}
	buffer.WriteByte(']')
	return buffer.Bytes(), nil
}

// parseJSONNode parses JSON text into the DOM above, preserving document key
// order, using json.Number for numbers and enforcing the 64-depth bound of
// JsonDocumentOptions.MaxDepth.
func parseJSONNode(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected trailing JSON token %v", token)
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("The maximum allowed depth of 64 was exceeded.")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := newJsonObject()
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid JSON property name")
			}
			value, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object.Set(key, value)
		}
		if _, err := decoder.Token(); err != nil { // consume '}'
			return nil, err
		}
		return object, nil
	case '[':
		array := &JsonArray{}
		for decoder.More() {
			value, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array.items = append(array.items, value)
		}
		if _, err := decoder.Token(); err != nil { // consume ']'
			return nil, err
		}
		return array, nil
	}
	return nil, fmt.Errorf("unexpected JSON delimiter %v", delim)
}

func deepCloneJSON(node any) (any, error) {
	encoded, err := json.Marshal(node)
	if err != nil {
		return nil, err
	}
	return parseJSONNode(encoded)
}

// deepEqualJSON mirrors JsonNode.DeepEquals structural equality; numbers
// compare by value.
func deepEqualJSON(left, right any) bool {
	switch leftValue := left.(type) {
	case nil:
		return right == nil
	case *JsonObject:
		rightValue, ok := right.(*JsonObject)
		if !ok || leftValue.Len() != rightValue.Len() {
			return false
		}
		for _, key := range leftValue.keys {
			other, exists := rightValue.values[key]
			if !exists || !deepEqualJSON(leftValue.values[key], other) {
				return false
			}
		}
		return true
	case *JsonArray:
		rightValue, ok := right.(*JsonArray)
		if !ok || len(leftValue.items) != len(rightValue.items) {
			return false
		}
		for index, item := range leftValue.items {
			if !deepEqualJSON(item, rightValue.items[index]) {
				return false
			}
		}
		return true
	case json.Number:
		rightValue, ok := right.(json.Number)
		if !ok {
			return false
		}
		if leftValue.String() == rightValue.String() {
			return true
		}
		leftFloat, leftErr := leftValue.Float64()
		rightFloat, rightErr := rightValue.Float64()
		return leftErr == nil && rightErr == nil && leftFloat == rightFloat
	case string:
		rightValue, ok := right.(string)
		return ok && leftValue == rightValue
	case bool:
		rightValue, ok := right.(bool)
		return ok && leftValue == rightValue
	}
	return false
}

// ProcessResult mirrors the C# ProcessResult record.
type ProcessResult struct {
	ExitCode       int
	StandardOutput string
	StandardError  string
}

type toolingSupport struct{}

// ToolingSupport mirrors the C# ToolingSupport static class.
var ToolingSupport = toolingSupport{}

// ReadJSON mirrors ToolingSupport.ReadJson (path relative to the repository
// root, comments disallowed, depth capped at 64).
func (toolingSupport) ReadJSON(relativePath string) (any, error) {
	content, err := os.ReadFile(filepath.Join(ToolingSupport.Root(), relativePath))
	if err != nil {
		return nil, err
	}
	node, err := parseJSONNode(content)
	if err != nil {
		return nil, err
	}
	if node == nil {
		return nil, fmt.Errorf("%s: empty JSON document", relativePath)
	}
	return node, nil
}

func (toolingSupport) ReadObject(relativePath string) (*JsonObject, error) {
	node, err := ToolingSupport.ReadJSON(relativePath)
	if err != nil {
		return nil, err
	}
	object, ok := node.(*JsonObject)
	if !ok {
		return nil, fmt.Errorf("%s: top-level JSON must be an object", relativePath)
	}
	return object, nil
}

// Serialize mirrors ToolingSupport.Serialize: camelCase-irrelevant for DOM
// nodes (keys are emitted verbatim), indented with two spaces plus newline.
func (toolingSupport) Serialize(node any) (string, error) {
	compact, err := json.Marshal(node)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	if err := json.Indent(&buffer, compact, "", "  "); err != nil {
		return "", err
	}
	buffer.WriteByte('\n')
	return buffer.String(), nil
}

func (toolingSupport) Sha256(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return ToolingSupport.Sha256Bytes(content), nil
}

func (toolingSupport) Sha256Text(value string) string {
	return ToolingSupport.Sha256Bytes([]byte(value))
}

func (toolingSupport) Sha256Bytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func (toolingSupport) RequireNoErrors(errs []string) error {
	distinct := make([]string, 0, len(errs))
	seen := make(map[string]bool, len(errs))
	for _, item := range errs {
		if seen[item] {
			continue
		}
		seen[item] = true
		distinct = append(distinct, item)
	}
	if len(distinct) != 0 {
		return newToolValidationException(distinct)
	}
	return nil
}

// RunProcess mirrors ToolingSupport.RunProcess: capture stdout/stderr, kill
// the whole child tree on timeout. An empty workingDirectory runs in Root and
// timeoutMilliseconds <= 0 selects the C# default of 30 seconds.
func (toolingSupport) RunProcess(fileName string, arguments []string, workingDirectory string, timeoutMilliseconds int) (ProcessResult, error) {
	if workingDirectory == "" {
		workingDirectory = ToolingSupport.Root()
	}
	if timeoutMilliseconds <= 0 {
		timeoutMilliseconds = 30_000
	}
	process, done, stdout, stderr, err := startProcess(fileName, arguments, workingDirectory)
	if err != nil {
		return ProcessResult{}, err
	}
	select {
	case waitErr := <-done:
		return ProcessResult{ExitCode: exitCodeOf(waitErr), StandardOutput: stdout.String(), StandardError: stderr.String()}, nil
	case <-time.After(time.Duration(timeoutMilliseconds) * time.Millisecond):
		killProcessTree(process.Pid)
		<-done
		return ProcessResult{}, fmt.Errorf("%s exceeded %d ms", fileName, timeoutMilliseconds)
	}
}

func (toolingSupport) Git(repository string, arguments ...string) (string, error) {
	result, err := ToolingSupport.RunProcess("git", append([]string{"-C", repository}, arguments...), "", 0)
	if err != nil {
		return "", err
	}
	if result.ExitCode != 0 {
		return "", fmt.Errorf("%s", strings.TrimSpace(result.StandardError))
	}
	return result.StandardOutput, nil
}

func (toolingSupport) GitBytes(repository string, arguments ...string) ([]byte, error) {
	_, done, stdout, stderr, err := startProcess("git", append([]string{"-C", repository}, arguments...), ToolingSupport.Root())
	if err != nil {
		return nil, err
	}
	if waitErr := <-done; waitErr != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = waitErr.Error()
		}
		return nil, fmt.Errorf("%s", message)
	}
	return stdout.Bytes(), nil
}

// Root mirrors ToolingSupport.Root: the directory containing the solution
// (module root marker for the Go migration), found by walking up from the
// executable directory and then the working directory.
func (toolingSupport) Root() string {
	if root, ok := findRepositoryRoot(); ok {
		return root
	}
	panic("TerraScale.Orchestrator repository root was not found.")
}

func findRepositoryRoot() (string, bool) {
	if executable, err := os.Executable(); err == nil {
		if root, ok := walkToRoot(filepath.Dir(executable)); ok {
			return root, true
		}
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return "", false
	}
	return walkToRoot(workingDirectory)
}

func walkToRoot(start string) (string, bool) {
	current := start
	for {
		if isRepositoryRoot(current) {
			return current, true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
}

func isRepositoryRoot(directory string) bool {
	for _, marker := range []string{"TerraScale.Orchestrator.slnx", "go.mod"} {
		if info, err := os.Stat(filepath.Join(directory, marker)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// startProcess launches fileName with the .NET-host environment overrides the
// C# runner applied, its own process group (so the tree can be killed), and
// captured stdout/stderr buffers. The returned channel yields the Wait result.
func startProcess(fileName string, arguments []string, workingDirectory string) (*os.Process, chan error, *bytes.Buffer, *bytes.Buffer, error) {
	command := exec.Command(fileName, arguments...)
	command.Dir = workingDirectory
	command.Env = append(filteredEnvironment(os.Environ()),
		"DOTNET_CLI_USE_MSBUILD_SERVER=0",
		"MSBUILDDISABLENODEREUSE=1",
		"UseSharedCompilation=false",
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, nil, nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	return command.Process, done, &stdout, &stderr, nil
}

func filteredEnvironment(environment []string) []string {
	filtered := make([]string, 0, len(environment))
	blocked := map[string]bool{
		"DOTNET_CLI_USE_MSBUILD_SERVER": true,
		"MSBUILDDISABLENODEREUSE":       true,
		"UseSharedCompilation":          true,
	}
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if !blocked[name] {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func exitCodeOf(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(waitErr, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

func killProcessTree(processID int) {
	// The child runs in its own process group (Setpgid), so a group kill
	// reaches the whole tree like Process.Kill(entireProcessTree: true).
	if err := syscall.Kill(-processID, syscall.SIGKILL); err != nil {
		_ = syscall.Kill(processID, syscall.SIGKILL)
	}
}

// envUserName mirrors Environment.UserName on Unix.
func envUserName() string {
	for _, name := range []string{"USER", "LOGNAME"} {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return "unknown"
}
