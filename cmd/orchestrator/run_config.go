package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"terrascale.tech/orchestrator/src/orchestrator/control"
)

const maximumRunConfigurationBytes = 64 << 10

// The file uses the existing setting names, not a second options vocabulary.
// Values are nonsecret settings and credential file references. Inline provider
// tokens, private keys, and arbitrary environment variables are not supported.
var runConfigurationKeys = map[string]bool{
	placementHostFileEnvironment: true,
	databaseHostFileEnvironment:  true,
	keyLeaseSocketEnvironment:    true, keyLeaseCatalogEnvironment: true, keyLeaseEnvironment: true, keyLeaseUIDEnvironment: true,
	"TS_ORCH_CELL": true, "TS_ORCH_INSTANCE": true, "TS_ORCH_NATS_URL": true, "TS_ORCH_REPLICAS": true,
	"TS_ORCH_NATS_NKEY_FILE": true, "TS_ORCH_NATS_TLS_CA_FILE": true, "TS_ORCH_NATS_TLS_CERT_FILE": true, "TS_ORCH_NATS_TLS_KEY_FILE": true,
	"TS_ORCH_GLOBAL_NATS_URL": true, "TS_ORCH_GLOBAL_NATS_NKEY_FILE": true, "TS_ORCH_GLOBAL_NATS_CREDENTIALS_FILE": true,
	"TS_ORCH_GLOBAL_NATS_TLS_CA_FILE": true, "TS_ORCH_GLOBAL_NATS_TLS_CERT_FILE": true, "TS_ORCH_GLOBAL_NATS_TLS_KEY_FILE": true,
	"TS_ORCH_GLOBAL_DIRECTORY_NATS_URL": true, "TS_ORCH_GLOBAL_DIRECTORY_NATS_NKEY_FILE": true, "TS_ORCH_GLOBAL_DIRECTORY_NATS_CREDENTIALS_FILE": true,
	"TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CA_FILE": true, "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_CERT_FILE": true, "TS_ORCH_GLOBAL_DIRECTORY_NATS_TLS_KEY_FILE": true, "TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS": true,
	"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_URL": true, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_NKEY_FILE": true, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_CREDENTIALS_FILE": true,
	"TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CA_FILE": true, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_CERT_FILE": true, "TS_ORCH_GLOBAL_DIRECTORY_SERVICE_NATS_TLS_KEY_FILE": true,
	"TS_ORCH_MEMBERSHIP_SIGNING_KEY_FILE": true, "TS_ORCH_MEMBERSHIP_PINS_FILE": true,
	"TS_ORCH_COMMAND_SIGNING_KEY_FILE": true, "TS_ORCH_COMMAND_TRUST_KEY_FILES": true, "TS_ORCH_COMMAND_AGGREGATE_ID": true,
	natsServerConfigEnvironment: true, natsServerReadinessEnvironment: true,
	providerEnvironment: true, ociEstateFileEnvironment: true, ociKeyIDEnvironment: true, ociPrivateKeyFileEnvironment: true,
}

func loadRunConfiguration(path string) (envLookup, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return nil, errors.New("run configuration requires an absolute file path")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot open run configuration as a regular file")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximumRunConfigurationBytes || before.Mode().Perm()&0o022 != 0 || before.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return nil, errors.New("run configuration must be a bounded regular file without group or other write access")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Geteuid())) || owner.Nlink != 1 {
		return nil, errors.New("run configuration must have one link and be owned by root or the service identity")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumRunConfigurationBytes+1))
	after, statErr := file.Stat()
	if err != nil || statErr != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(data)) != before.Size() {
		return nil, errors.New("run configuration changed while being read")
	}
	return parseRunConfiguration(data)
}

// An explicit file is the entire setting source. Process environment values
// never supplement or override it; absent optional keys use the existing
// options resolver's defaults. Production identity fields are mandatory.
func parseRunConfiguration(data []byte) (envLookup, error) {
	invalid := func() (envLookup, error) {
		return nil, errors.New("run configuration must be one bounded JSON object with unique allowed setting names and nonempty string values")
	}
	if len(data) == 0 || len(data) > maximumRunConfigurationBytes {
		return invalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return invalid()
	}
	values := map[string]string{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return invalid()
		}
		key, ok := token.(string)
		if !ok || !runConfigurationKeys[key] {
			return invalid()
		}
		if _, exists := values[key]; exists {
			return invalid()
		}
		var value string
		if err := decoder.Decode(&value); err != nil || value == "" || len(value) > 4096 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") || strings.Contains(value, "PRIVATE KEY-----") {
			return invalid()
		}
		if !validRunConfigurationReference(key, value) {
			return invalid()
		}
		values[key] = value
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return invalid()
	}
	if _, err = decoder.Token(); err != io.EOF {
		return invalid()
	}
	for _, key := range []string{"TS_ORCH_CELL", "TS_ORCH_INSTANCE", "TS_ORCH_NATS_URL", "TS_ORCH_REPLICAS"} {
		if values[key] == "" {
			return nil, errors.New("run configuration requires explicit cell, instance, NATS URL, and replicas")
		}
	}
	if values["TS_ORCH_CELL"] == "local" {
		return nil, errors.New("run file configuration requires a production cell and OCI provider")
	}
	lookup := func(key string) (string, bool) { value, present := values[key]; return value, present }
	if err := validateConfiguredProvider(values["TS_ORCH_CELL"], lookup); err != nil {
		return nil, err
	}
	return lookup, nil
}

// Credentials live in separately provisioned files, never in this immutable
// configuration. Existing resolvers still validate and load those files.
func validRunConfigurationReference(key, value string) bool {
	if strings.HasSuffix(key, "_URL") {
		parsed, err := url.Parse(value)
		return err == nil && parsed.Scheme != "" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && !parsed.ForceQuery && parsed.Fragment == "" && parsed.Path == "" && parsed.Opaque == ""
	}
	if key == "TS_ORCH_GLOBAL_DIRECTORY_ENDPOINTS" {
		_, err := control.GlobalDirectoryNatsConfigurationParseEndpoints(value)
		return err == nil
	}
	if strings.HasSuffix(key, "_FILE") || key == "TS_ORCH_COMMAND_TRUST_KEY_FILES" {
		paths := []string{value}
		if key == "TS_ORCH_COMMAND_TRUST_KEY_FILES" {
			paths = strings.Split(value, string(filepath.ListSeparator))
		}
		for _, path := range paths {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\t") {
				return false
			}
		}
	}
	return true
}
