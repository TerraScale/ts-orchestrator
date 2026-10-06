// Package tsauth is the orchestrator's contract with ts-auth (repository
// TerraScale/ts-auth), TerraScale's C# authentication service: its release
// assets, its TS_AUTH_* settings, the secrets kept in the cell's OCI Vault,
// which hosts read through the profile's secret refs, its health and readiness
// endpoints, and the TerraBase tenant that holds its data. The host agent
// launches it as a stateless native workload of role "ts-auth" on the
// controllers; see docs/ts-auth-deployment.md. ts-orch ouroboros prepares
// that tenant together with the dashboard's in TerraScale's own organization.
package tsauth

import (
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
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const (
	// Role is the native workload role of a ts-auth replica.
	Role = "ts-auth"
	// Repository is the source of every ts-auth release.
	Repository = "https://git.terrascale.tech/TerraScale/ts-auth"
	// Port is the plain-HTTP listener on every interface of a replica's
	// host. The public API load balancer (TS-486) sends gru.auth.terrascale.tech
	// to it; the cell plan admits the load balancer's subnet on it.
	Port = 8080
	// HealthPath answers 200 while the process serves requests.
	HealthPath = "/healthz"
	// ReadyPath answers 200 once TerraBase answered a probe; the host and
	// the load balancer send traffic only to a ready replica.
	ReadyPath = "/readyz"
	// Hostname is ts-auth's regional name, <region>.auth.terrascale.tech, the
	// load balancer's hostname rule. Atlas serves auth.terrascale.tech.
	Hostname = Cell + ".auth.terrascale.tech"
	// Replicas is the replica count: ts-auth keeps all of its state in
	// TerraBase, so two replicas on distinct controllers serve together.
	Replicas = 2
	// Cell is the only production cell with the reviewed ts-auth endpoints.
	Cell = "gru"

	PublicOrigin = "https://" + Hostname
	APIURL       = "https://" + Cell + ".api.terrascale.tech"
	// Database is ts-auth's own TerraBase database. ts-auth selects it as
	// TS_AUTH_DATABASE=<project-uuid>/auth; the host joins the project ID it
	// read from the Vault to it.
	Database = "auth"
	// Issuer is ts-auth's one hosted OpenID Connect issuer; its discovery
	// document is Issuer + "/.well-known/openid-configuration".
	Issuer = PublicOrigin + "/terrascale"

	// DashboardClientID is ts-auth's confidential OIDC client for ts-dashboard,
	// which the dashboard (Fly app ts-dashboard) serves at DashboardOrigin.
	DashboardClientID    = "ts-dashboard"
	DashboardOrigin      = "https://dash.terrascale.tech"
	DashboardRedirectURI = DashboardOrigin + "/login/callback"
	// DashboardLogoutURI is the dashboard's sign-in page, the exact
	// post_logout_redirect_uri it sends at sign-out.
	DashboardLogoutURI = DashboardOrigin + "/login"
)

// Settings the workload profile supplies. They are signed controller
// configuration, readable wherever desired state is, so they hold no secret.
const (
	EnvPublicOrigin = "TS_AUTH_PUBLIC_ORIGIN"
	EnvAPIURL       = "TS_AUTH_TERRASCALE_API_URL"
	EnvDatabase     = "TS_AUTH_DATABASE"
	// EnvAudiences are the aud values of every access token: TerraBase's
	// auth-audience, so a dashboard user's token reaches its Management API.
	EnvAudiences = "TS_AUTH_ACCESS_TOKEN_AUDIENCES"
	// The dashboard client's exact callback and post-logout URIs.
	EnvDashboardRedirectURIs = "TS_AUTH_DASHBOARD_REDIRECT_URIS"
	EnvDashboardLogoutURIs   = "TS_AUTH_DASHBOARD_POST_LOGOUT_REDIRECT_URIS"
)

// Secrets live in the cell's Vault; the profile names them and the host reads
// them at each start. The project ID is not secret, but ouroboros bootstrap
// creates it with the API key that is narrowed to it, so the two travel
// together.
const (
	EnvMasterKey       = "TS_AUTH_MASTER_KEY"
	EnvAuditSigningKey = "TS_AUTH_AUDIT_SIGNING_KEY"
	EnvOperatorKey     = "TS_AUTH_OPERATOR_KEY"
	// EnvDashboardClientSecret is the ts-dashboard client's secret, which
	// ouroboros fly-secrets also hands the dashboard as TS_AUTH_CLIENT_SECRET.
	EnvDashboardClientSecret = "TS_AUTH_DASHBOARD_CLIENT_SECRET"
	EnvAPIKey                = "TS_AUTH_TERRASCALE_API_KEY"
	EnvProjectID             = "TS_AUTH_TERRASCALE_PROJECT_ID"
)

// Settings the host agent owns.
const (
	EnvListen        = "TS_AUTH_LISTEN"
	EnvBundleExtract = terrabase.EnvBundleExtract
)

// Generated are the secrets ts-orch generates once: 32 random bytes, base64.
var Generated = []string{EnvMasterKey, EnvAuditSigningKey, EnvOperatorKey, EnvDashboardClientSecret}

// Secrets are the keys of the profile's secret refs.
var Secrets = []string{EnvMasterKey, EnvAuditSigningKey, EnvOperatorKey, EnvDashboardClientSecret, EnvAPIKey, EnvProjectID}

// OptionalSecrets are ts-auth secrets a profile may name as Vault secret
// refs: the SMTP relay password, and the service clients (id:secret pairs)
// that may use the client credentials grant.
var OptionalSecrets = []string{"TS_AUTH_SMTP_PASSWORD", "TS_AUTH_SERVICE_CLIENTS"}

// optionalSecrets are ts-auth secrets that no profile may carry, as env or
// refs, yet.
var optionalSecrets = []string{"TS_AUTH_STRIPE_SECRET_KEY", "TS_AUTH_STRIPE_WEBHOOK_SECRET",
	"TS_AUTH_SENTRY_DSN", "TS_AUTH_AUDIT_VERIFY_KEYS", "OTEL_EXPORTER_OTLP_HEADERS"}

var (
	assetRE  = regexp.MustCompile(`^ts-auth-linux-(?:amd64|arm64)$`)
	uuidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	apiKeyRE = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// VerifyRelease checks ts-auth-linux-<arch> against its .sha256 release
// asset and returns the digest to pin.
func VerifyRelease(binaryPath, checksumPath string) (string, error) {
	return terrabase.VerifyAsset(binaryPath, checksumPath, assetRE)
}

// ValidateProfile checks the "ts-auth" workload profile. ts-auth lets an
// argument override any setting, so a profile sets env only, and it names
// the Secrets, and optionally the OptionalSecrets, as Vault secret refs.
func ValidateProfile(cell string, args []string, env map[string]string, secrets map[string]vaultsecret.Ref) error {
	if cell != Cell {
		return fmt.Errorf("ts-auth is only reviewed for cell %s", Cell)
	}
	if len(args) != 0 {
		return errors.New("ts-auth profile sets its settings only through env")
	}
	if slices.ContainsFunc(Secrets, func(key string) bool { _, ok := secrets[key]; return !ok }) {
		return fmt.Errorf("ts-auth profile secrets must name %s", strings.Join(Secrets, ", "))
	}
	for key := range secrets {
		if !slices.Contains(Secrets, key) && !slices.Contains(OptionalSecrets, key) {
			return fmt.Errorf("ts-auth profile secrets may add only %s, not %s", strings.Join(OptionalSecrets, ", "), key)
		}
	}
	for _, key := range slices.Concat(Secrets, OptionalSecrets, optionalSecrets, []string{EnvListen, EnvBundleExtract}) {
		if _, set := env[key]; set {
			return fmt.Errorf("ts-auth profile must not set %s", key)
		}
	}
	for key, want := range map[string]string{EnvPublicOrigin: PublicOrigin, EnvAPIURL: APIURL, EnvDatabase: Database, EnvAudiences: APIURL,
		EnvDashboardRedirectURIs: DashboardRedirectURI, EnvDashboardLogoutURIs: DashboardLogoutURI} {
		if env[key] != want {
			return fmt.Errorf("ts-auth profile must set %s=%s", key, want)
		}
	}
	return nil
}

// Layout is ts-auth's directory below the host's ts-auth root.
type Layout string

// Bundle is where the single-file binary extracts its native libraries.
func (l Layout) Bundle() string { return filepath.Join(string(l), "bundle") }

// Env is the replica's environment: the profile, the secrets and the
// host-owned settings. TS_AUTH_DATABASE becomes <project-uuid>/<database>
// from the secrets' project ID and the profile's database, the selector
// ts-auth reads; the project ID itself is not passed on. A replica listens on
// port of every interface.
func (l Layout) Env(profile, secrets map[string]string, port int) map[string]string {
	env := maps.Clone(profile)
	if env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, secrets)
	env[EnvDatabase] = secrets[EnvProjectID] + "/" + profile[EnvDatabase]
	delete(env, EnvProjectID)
	env[EnvListen] = "http://0.0.0.0:" + strconv.Itoa(port)
	env[EnvBundleExtract] = l.Bundle()
	return env
}

// ValidateSecrets checks that secrets holds exactly the Secrets in their
// forms. Errors name keys, never values.
func ValidateSecrets(secrets map[string]string) error {
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
	if slices.ContainsFunc(Projects, func(project Project) bool { return project.ProjectIDKey == key }) {
		if !uuidRE.MatchString(value) {
			return fmt.Errorf("%s must be a lowercase hyphenated UUID", key)
		}
		return nil
	}
	if !slices.ContainsFunc(Projects, func(project Project) bool { return project.APIKeyKey == key }) ||
		len(value) > 4096 || !apiKeyRE.MatchString(value) {
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
