// Package tsauth is the orchestrator's contract with ts-auth (repository
// TerraScale/ts-auth), TerraScale's C# authentication service: its release
// assets, its TS_AUTH_* settings, the secrets kept in the cell's OCI Vault and
// the env file that carries them to a host, its health and readiness
// endpoints, and the TerraBase tenant that holds its data. The host agent
// launches it as a stateless native workload of role "ts-auth" on the
// controllers; see docs/ts-auth-deployment.md.
package tsauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

const (
	// Role is the native workload role of a ts-auth replica.
	Role = "ts-auth"
	// Repository is the source of every ts-auth release.
	Repository = "https://git.terrascale.tech/TerraScale/ts-auth"
	// Port is the plain-HTTP listener on every interface of a replica's
	// host. The public API load balancer (TS-486) sends auth.terrascale.tech
	// to it; the cell plan admits the load balancer's subnet on it.
	Port = 8080
	// HealthPath answers 200 while the process serves requests.
	HealthPath = "/healthz"
	// ReadyPath answers 200 once TerraBase answered a probe; the host and
	// the load balancer send traffic only to a ready replica.
	ReadyPath = "/readyz"
	// Hostname is ts-auth's public name, the load balancer's hostname rule.
	Hostname = "auth.terrascale.tech"
	// Replicas is the replica count: ts-auth keeps all of its state in
	// TerraBase, so two replicas on distinct controllers serve together.
	Replicas = 2
	// Cell is the only production cell with the reviewed ts-auth endpoints.
	Cell = "gru"

	PublicOrigin = "https://" + Hostname
	APIURL       = "https://gru.api.terrascale.tech"
	// Database is ts-auth's own TerraBase database, TS_AUTH_DATABASE.
	Database = "auth"
)

// Settings the workload profile supplies. They are signed controller
// configuration, readable wherever desired state is, so they hold no secret.
const (
	EnvPublicOrigin = "TS_AUTH_PUBLIC_ORIGIN"
	EnvAPIURL       = "TS_AUTH_TERRASCALE_API_URL"
	EnvDatabase     = "TS_AUTH_DATABASE"
)

// Secrets live in the cell's Vault and reach a host only in its env file.
// The project ID is not secret, but terrabase-bootstrap creates it with the
// API key that is narrowed to it, so the two travel together.
const (
	EnvMasterKey       = "TS_AUTH_MASTER_KEY"
	EnvAuditSigningKey = "TS_AUTH_AUDIT_SIGNING_KEY"
	EnvOperatorKey     = "TS_AUTH_OPERATOR_KEY"
	EnvAPIKey          = "TS_AUTH_TERRASCALE_API_KEY"
	EnvProjectID       = "TS_AUTH_TERRASCALE_PROJECT_ID"
)

// Settings the host agent owns.
const (
	EnvListen        = "TS_AUTH_LISTEN"
	EnvBundleExtract = terrabase.EnvBundleExtract
)

// Generated are the secrets ts-orch generates once: 32 random bytes, base64.
var Generated = []string{EnvMasterKey, EnvAuditSigningKey, EnvOperatorKey}

// Secrets are every key of the env file.
var Secrets = []string{EnvMasterKey, EnvAuditSigningKey, EnvOperatorKey, EnvAPIKey, EnvProjectID}

// optionalSecrets are ts-auth secrets that no profile may carry; the env file
// does not provision them yet.
var optionalSecrets = []string{"TS_AUTH_SMTP_PASSWORD", "TS_AUTH_STRIPE_SECRET_KEY", "TS_AUTH_STRIPE_WEBHOOK_SECRET",
	"TS_AUTH_SENTRY_DSN", "TS_AUTH_AUDIT_VERIFY_KEYS", "OTEL_EXPORTER_OTLP_HEADERS"}

var (
	assetRE  = regexp.MustCompile(`^ts-auth-linux-(?:amd64|arm64)$`)
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	envKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	apiKeyRE = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// VerifyRelease checks ts-auth-linux-<arch> against its .sha256 release
// asset and returns the digest to pin.
func VerifyRelease(binaryPath, checksumPath string) (string, error) {
	return terrabase.VerifyAsset(binaryPath, checksumPath, assetRE)
}

// ValidateProfile checks the "ts-auth" workload profile. ts-auth lets an
// argument override any setting, so a profile sets env only.
func ValidateProfile(cell string, args []string, env map[string]string) error {
	if cell != Cell {
		return fmt.Errorf("ts-auth is only reviewed for cell %s", Cell)
	}
	if len(args) != 0 {
		return errors.New("ts-auth profile sets its settings only through env")
	}
	for _, key := range slices.Concat(Secrets, optionalSecrets, []string{EnvListen, EnvBundleExtract}) {
		if _, set := env[key]; set {
			return fmt.Errorf("ts-auth profile must not set %s", key)
		}
	}
	for key, want := range map[string]string{EnvPublicOrigin: PublicOrigin, EnvAPIURL: APIURL, EnvDatabase: Database} {
		if env[key] != want {
			return fmt.Errorf("ts-auth profile must set %s=%s", key, want)
		}
	}
	return nil
}

// Layout is ts-auth's directory below the host's ts-auth root.
type Layout string

// EnvFile holds the secrets: owned by the workload user, mode 0600.
func (l Layout) EnvFile() string { return filepath.Join(string(l), "ts-auth.env") }

// Bundle is where the single-file binary extracts its native libraries.
func (l Layout) Bundle() string { return filepath.Join(string(l), "bundle") }

// Env is the replica's environment: the profile, the secrets and the
// host-owned settings. A replica listens on port of every interface.
func (l Layout) Env(profile, secrets map[string]string, port int) map[string]string {
	env := maps.Clone(profile)
	if env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, secrets)
	env[EnvListen] = "http://0.0.0.0:" + strconv.Itoa(port)
	env[EnvBundleExtract] = l.Bundle()
	return env
}

// RenderEnvFile writes every secret as one KEY=VALUE line.
func RenderEnvFile(secrets map[string]string) ([]byte, error) {
	if err := validateSecrets(secrets); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, key := range Secrets {
		out.WriteString(key + "=" + secrets[key] + "\n")
	}
	return out.Bytes(), nil
}

// ParseEnvFile reads an env file of exactly the Secrets. Errors name keys and
// line numbers, never values.
func ParseEnvFile(data []byte) (map[string]string, error) {
	secrets := make(map[string]string, len(Secrets))
	for index, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || !envKeyRE.MatchString(key) {
			return nil, fmt.Errorf("ts-auth env file line %d is not KEY=VALUE", index+1)
		}
		if !slices.Contains(Secrets, key) {
			return nil, fmt.Errorf("ts-auth env file sets unknown key %s", key)
		}
		if _, repeated := secrets[key]; repeated {
			return nil, fmt.Errorf("ts-auth env file repeats %s", key)
		}
		secrets[key] = value
	}
	if err := validateSecrets(secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}

func validateSecrets(secrets map[string]string) error {
	if len(secrets) != len(Secrets) {
		return fmt.Errorf("ts-auth needs exactly %s", strings.Join(Secrets, ", "))
	}
	for _, key := range Secrets {
		if err := validSecret(key, secrets[key]); err != nil {
			return err
		}
	}
	return nil
}

// validSecret checks one secret value without ever printing it.
func validSecret(key, value string) error {
	if slices.Contains(Generated, key) {
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		// Strict still skips CR and LF; only the canonical form fits one line.
		if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
			return fmt.Errorf("%s must be 32 bytes in base64", key)
		}
		return nil
	}
	if key == EnvProjectID {
		if !uuidRE.MatchString(value) {
			return fmt.Errorf("%s must be a lowercase hyphenated UUID", key)
		}
		return nil
	}
	if key != EnvAPIKey || len(value) > 4096 || !apiKeyRE.MatchString(value) {
		return fmt.Errorf("%s must be 1 to 4096 printable characters without spaces", key)
	}
	return nil
}

// Probe reports nil once the replica on this host is alive and ready: GET
// /healthz answers {"status":"ok"} and GET /readyz {"status":"ready"}.
func Probe(ctx context.Context, port int) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, check := range [][2]string{{HealthPath, "ok"}, {ReadyPath, "ready"}} {
		if err := probe(ctx, "http://127.0.0.1:"+strconv.Itoa(port)+check[0], check[1]); err != nil {
			return fmt.Errorf("ts-auth %s: %w", check[0], err)
		}
	}
	return nil
}

func probe(ctx context.Context, url, want string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var body struct {
		Status string `json:"status"`
	}
	if err := json.UnmarshalRead(io.LimitReader(response.Body, 4096), &body); err != nil ||
		response.StatusCode != http.StatusOK || body.Status != want {
		return fmt.Errorf("HTTP %d, status %q", response.StatusCode, body.Status)
	}
	return nil
}

// LoadBalancer is what the public API load balancer gru-1-api (TS-486) needs
// to serve ts-auth: a Hostname rule to a backend set of every controller,
// since a replica may run on any of them, on Port, with an HTTP health check
// of HealthPath that passes only on a ready replica (200,
// {"status":"ready"}). TLS ends at the load balancer; backends speak plain
// HTTP.
type LoadBalancer struct {
	Hostname   string   `json:"hostname"`
	Backends   []string `json:"backends"` // controller private IPs
	Port       int      `json:"port"`
	HealthPath string   `json:"health_path"`
}

// BackendSet returns ts-auth's load balancer configuration for the cell plan.
func BackendSet(plan map[string]any) (LoadBalancer, error) {
	hosts, _ := plan["hosts"].([]any)
	set := LoadBalancer{Hostname: Hostname, Port: Port, HealthPath: ReadyPath}
	for _, value := range hosts {
		host, _ := value.(map[string]any)
		slot, _ := host["slot"].(string)
		ip, _ := host["private_ip"].(string)
		if !strings.HasPrefix(slot, "controller-") {
			continue
		}
		if ip == "" {
			return LoadBalancer{}, fmt.Errorf("plan controller %q has no private IP", slot)
		}
		set.Backends = append(set.Backends, ip)
	}
	if len(set.Backends) < Replicas {
		return LoadBalancer{}, fmt.Errorf("plan has %d controllers, ts-auth needs %d", len(set.Backends), Replicas)
	}
	return set, nil
}
