// Package memberobserve runs the read-only observe-member diagnostic.
package memberobserve

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"terrascale.tech/orchestrator/src/orchestrator/tbep"
)

// observe-member is a read-only same-host diagnostic. It does not start the
// production control runtime or authorize a member lifecycle transition.
type memberObservationError struct {
	message string
	cause   error
}

func (e memberObservationError) Error() string { return "orchestrator observe-member: " + e.message }
func (e memberObservationError) Unwrap() error { return e.cause }
func observationFailure(message string, cause error) error {
	return memberObservationError{message, cause}
}

func readObservationFile(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return nil, errors.New("file empty or exceeds bound")
	}
	return data, nil
}

// Every value is a required string. Exact keys and duplicate rejection avoid
// ambiguous identity or trust configuration being silently overwritten.
func parseObservationConfig(data []byte) (map[string]string, error) {
	allowed := map[string]bool{"endpoint": true, "serverIdentity": true, "tenant": true, "project": true, "database": true, "timeout": true, "certificateFile": true, "privateKeyFile": true, "trustBundleFile": true}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	values := map[string]string{}
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok || !allowed[key] {
			return nil, errors.New("unknown configuration field")
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate configuration field")
		}
		var value string
		if err := decoder.Decode(&value); err != nil || value == "" {
			return nil, errors.New("configuration values must be nonempty strings")
		}
		values[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing configuration data")
	}
	if len(values) != len(allowed) {
		return nil, errors.New("missing configuration field")
	}
	return values, nil
}

func loadObservationConfig(path string) (tbep.Config, error) {
	data, err := readObservationFile(path, 64*1024)
	if err != nil {
		return tbep.Config{}, observationFailure("cannot read configuration; provide a nonempty regular JSON file of at most 64 KiB", err)
	}
	values, err := parseObservationConfig(data)
	if err != nil {
		return tbep.Config{}, observationFailure("invalid configuration; require exact endpoint, serverIdentity, tenant, project, database, timeout, certificateFile, privateKeyFile, trustBundleFile fields without duplicates", err)
	}
	timeout, err := time.ParseDuration(values["timeout"])
	if err != nil || timeout <= 0 || timeout > time.Minute {
		return tbep.Config{}, observationFailure("timeout must be a Go duration greater than zero and at most 1m", err)
	}
	readAsset := func(name string, limit int64) ([]byte, error) {
		asset := values[name]
		if !filepath.IsAbs(asset) {
			asset = filepath.Join(filepath.Dir(path), asset)
		}
		return readObservationFile(asset, limit)
	}
	certificatePEM, err := readAsset("certificateFile", 64*1024)
	if err != nil {
		return tbep.Config{}, observationFailure("cannot read certificateFile; require a regular PEM file of at most 64 KiB", err)
	}
	keyPEM, err := readAsset("privateKeyFile", 64*1024)
	if err != nil {
		return tbep.Config{}, observationFailure("cannot read privateKeyFile; require a regular PEM file of at most 64 KiB", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return tbep.Config{}, observationFailure("certificateFile and privateKeyFile must contain a matching PEM certificate and private key", err)
	}
	rootsPEM, err := readAsset("trustBundleFile", 1024*1024)
	if err != nil {
		return tbep.Config{}, observationFailure("cannot read trustBundleFile; require a regular PEM CA bundle of at most 1 MiB", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return tbep.Config{}, observationFailure("trustBundleFile contains no PEM certificates", nil)
	}
	return tbep.Config{Endpoint: values["endpoint"], ServerIdentity: values["serverIdentity"], Tenant: values["tenant"], Project: values["project"], Database: values["database"], Timeout: timeout, Certificate: certificate, Roots: roots}, nil
}

type memberHealthFacts struct {
	State         string `json:"state"`
	Sessions      uint32 `json:"sessions"`
	Subscriptions uint32 `json:"subscriptions"`
	FramesServed  uint64 `json:"framesServed"`
}
type memberTopologyFacts struct {
	Binding                 string   `json:"binding"`
	Subsystems              []string `json:"subsystems"`
	EngineTopologyAvailable bool     `json:"engineTopologyAvailable"`
	ClusterMode             string   `json:"clusterMode"`
}
type memberAdminFacts struct {
	RegistryVersion string `json:"registryVersion"`
	FramesServed    uint64 `json:"framesServed"`
	Sessions        uint32 `json:"sessions"`
	Subscriptions   uint32 `json:"subscriptions"`
	Scopes          uint32 `json:"scopes"`
}
type memberObservationFacts struct {
	ServerIdentity string              `json:"serverIdentity"`
	ObservedAt     time.Time           `json:"observedAt"`
	Health         memberHealthFacts   `json:"health"`
	Topology       memberTopologyFacts `json:"topology"`
	Admin          memberAdminFacts    `json:"admin"`
}

// Run executes observe-member with its command name followed by --config FILE.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) != 3 || args[1] != "--config" || args[2] == "" {
		return observationFailure("usage: orchestrator observe-member --config FILE", nil)
	}
	if output == nil {
		return observationFailure("output writer is required", nil)
	}
	config, err := loadObservationConfig(args[2])
	if err != nil {
		return err
	}
	client, err := tbep.New(config)
	if err != nil {
		return observationFailure("invalid TBEP configuration; require a literal loopback endpoint, exact SPIFFE identities, bounded database scope and trusted client credentials", err)
	}
	defer client.Close()
	observed, err := client.Observe(ctx)
	if err != nil {
		switch status.Code(err) {
		case codes.DeadlineExceeded:
			return observationFailure("TBEP observation exceeded its deadline", context.DeadlineExceeded)
		case codes.Canceled:
			return observationFailure("TBEP observation canceled", context.Canceled)
		case codes.Unauthenticated, codes.PermissionDenied:
			return observationFailure("TBEP rejected authentication or database scope; check the admitted identity and scope", err)
		case codes.Unavailable:
			return observationFailure("TBEP unavailable; check the loopback listener, TLS 1.3 certificate chain and exact admitted server identity", err)
		default:
			return observationFailure("TBEP observation failed or returned invalid facts; inspect TerraBase health and contract version", err)
		}
	}
	facts := memberObservationFacts{ServerIdentity: config.ServerIdentity, ObservedAt: time.Now().UTC(), Health: memberHealthFacts{observed.Health.State.String(), observed.Health.Sessions, observed.Health.Subscriptions, observed.Health.FramesServed}, Topology: memberTopologyFacts{observed.Topology.Binding.String(), observed.Topology.Subsystems, observed.Topology.EngineTopologyAvailable, observed.Topology.ClusterMode.String()}, Admin: memberAdminFacts{observed.Admin.RegistryVersion, observed.Admin.FramesServed, observed.Admin.Sessions, observed.Admin.Subscriptions, observed.Admin.Scopes}}
	if err := json.NewEncoder(output).Encode(facts); err != nil {
		return observationFailure("cannot write observation JSON", err)
	}
	return nil
}
