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
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const (
	// Role is the native workload role of a ts-auth replica.
	Role = "ts-auth"
	// Repository is the source of every ts-auth release.
	Repository = "https://git.terrascale.tech/TerraScale/ts-auth"
	// Port is the plain-HTTP listener on every interface of a replica's
	// host. The cell's public API load balancer (TS-486) sends the cell's
	// Hostname to it; the cell plan admits the load balancer's subnet on it.
	Port = 8080
	// HealthPath answers 200 while the process serves requests.
	HealthPath = "/healthz"
	// ReadyPath answers 200 once TerraBase answered a probe; the host and
	// the load balancer send traffic only to a ready replica.
	ReadyPath = "/readyz"
	// Replicas is the replica count: ts-auth keeps all of its state in
	// TerraBase, so one replica on each of the cell's three nodes, every one
	// in its own failure domain, serve together (TS-578).
	Replicas = 3
	// Database is ts-auth's own TerraBase database. ts-auth selects it as
	// TS_AUTH_DATABASE=<project-ulid>/auth; the host joins the project ID it
	// read from the Vault to it.
	Database = "auth"

	// DashboardClientID is ts-auth's confidential OIDC client for ts-dashboard,
	// which the dashboard (Fly app ts-dashboard) serves at DashboardOrigin.
	DashboardClientID    = "ts-dashboard"
	DashboardOrigin      = "https://dash.terrascale.tech"
	DashboardRedirectURI = DashboardOrigin + "/login/callback"
	// DashboardLogoutURI is the dashboard's sign-in page, the exact
	// post_logout_redirect_uri it sends at sign-out.
	DashboardLogoutURI = DashboardOrigin + "/login"
)

// Hostname is ts-auth's regional name in cell, the lower-case catalog cell
// token: <cell>.auth.terrascale.tech, the load balancer's hostname rule.
// Atlas serves auth.terrascale.tech.
func Hostname(cell string) string { return cell + ".auth.terrascale.tech" }

// PublicOrigin is ts-auth's public origin in cell.
func PublicOrigin(cell string) string { return "https://" + Hostname(cell) }

// APIURL is the public TerraBase API of cell, which ts-auth's access tokens
// name as their audience.
func APIURL(cell string) string { return "https://" + cell + ".api.terrascale.tech" }

// Issuer is the hosted OpenID Connect issuer of ts-auth in cell; its
// discovery document is Issuer + "/.well-known/openid-configuration".
func Issuer(cell string) string { return PublicOrigin(cell) + "/terrascale" }

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
	// EnvAPIEndpoints lists the cell's TerraBase members ts-auth stores
	// through instead of EnvAPIURL, most preferred first, over the private
	// network; EnvAPICA holds the only roots it trusts for them, the cell's
	// TerraBase member CA (PEM).
	EnvAPIEndpoints = "TS_AUTH_TERRASCALE_API_ENDPOINTS"
	EnvAPICA        = "TS_AUTH_TERRASCALE_API_CA"
	// EnvAPIFailover=true lets ts-auth move to the next of several endpoints
	// while the preferred member is down: ts-auth's documented exception to a
	// single storage authority, since the next member may not have replicated
	// the latest writes yet. One endpoint pins storage and fails closed.
	EnvAPIFailover = "TS_AUTH_TERRASCALE_API_FAILOVER"
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
	// The signing owner publishes ring versions; replicas reopen this file.
	EnvSigningKeyRingFile = "TS_AUTH_SIGNING_KEY_RING_FILE"
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
// refs: the SMTP relay credentials, and the service clients (id:secret pairs)
// that may use the client credentials grant.
var OptionalSecrets = []string{"TS_AUTH_SMTP_USERNAME", "TS_AUTH_SMTP_PASSWORD", "TS_AUTH_SERVICE_CLIENTS", EnvSigningKeyRingFile, "TS_AUTH_OCI_PRIVATE_KEY"}

// optionalSecrets are ts-auth secrets that no profile may carry, as env or
// refs, yet.
var optionalSecrets = []string{"TS_AUTH_STRIPE_SECRET_KEY", "TS_AUTH_STRIPE_WEBHOOK_SECRET",
	"TS_AUTH_SENTRY_DSN", "TS_AUTH_AUDIT_VERIFY_KEYS", "OTEL_EXPORTER_OTLP_HEADERS"}

var (
	assetRE  = regexp.MustCompile(`^ts-auth-linux-(?:amd64|arm64)$`)
	ulidRE   = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	uuidV7RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	apiKeyRE = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// VerifyRelease checks ts-auth-linux-<arch> against its .sha256 release
// asset and returns the digest to pin.
func VerifyRelease(binaryPath, checksumPath string) (string, error) {
	return terrabase.VerifyAsset(binaryPath, checksumPath, assetRE)
}

// ValidateProfile checks the "ts-auth" workload profile. ts-auth lets an
// argument override any setting, so a profile sets env only, and it names
// the Secrets, and optionally the OptionalSecrets, as Vault secret refs. cell
// is a catalog cell token, and the profile names that cell's endpoints.
func ValidateProfile(cell string, args []string, env map[string]string, secrets map[string]vaultsecret.Ref) error {
	if _, ok := catalog.LookupName(cell); !ok {
		return fmt.Errorf("ts-auth needs a catalog cell, not %q", cell)
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
	for key, want := range map[string]string{EnvPublicOrigin: PublicOrigin(cell), EnvAPIURL: APIURL(cell), EnvDatabase: Database, EnvAudiences: APIURL(cell),
		EnvDashboardRedirectURIs: DashboardRedirectURI, EnvDashboardLogoutURIs: DashboardLogoutURI} {
		if env[key] != want {
			return fmt.Errorf("ts-auth profile must set %s=%s", key, want)
		}
	}
	return nil
}

// ValidateMembers checks a ts-auth profile's private TerraBase endpoints
// against the cell's TerraBase profile terraBase: each one is
// https://<member IP>:<client port> of a member TERRABASE_PEERS lists, at
// most once, and EnvAPICA holds 1 to 4 PEM CA certificates and nothing else.
// Several endpoints need EnvAPIFailover=true. A profile without endpoints and
// CA stores through EnvAPIURL. Without a terrabase
// profile, as in an identity-only controller config whose first cell spec
// brings it, only the pairing and the CA are checked.
func ValidateMembers(env, terraBase map[string]string) error {
	endpoints, roots := env[EnvAPIEndpoints], env[EnvAPICA]
	if endpoints == "" && roots == "" {
		return nil
	}
	if endpoints == "" || roots == "" {
		return fmt.Errorf("ts-auth profile sets %s and %s together", EnvAPIEndpoints, EnvAPICA)
	}
	if !caCertificates(roots) {
		return fmt.Errorf("%s must hold 1 to 4 PEM CA certificates and nothing else", EnvAPICA)
	}
	if failover, set := env[EnvAPIFailover]; set && failover != "true" && failover != "false" ||
		strings.Contains(endpoints, ";") && failover != "true" {
		return fmt.Errorf("%s lists several members only with %s=true", EnvAPIEndpoints, EnvAPIFailover)
	}
	if len(terraBase) == 0 {
		return nil
	}
	members, err := terrabase.ParseProfile(terraBase)
	if err != nil || members.ClientPort == 0 {
		return fmt.Errorf("%s needs a terrabase profile with %s", EnvAPIEndpoints, terrabase.EnvClientPort)
	}
	seen := map[string]bool{}
	for _, endpoint := range strings.Split(endpoints, ";") {
		member := slices.ContainsFunc(members.Peers, func(peer terrabase.Peer) bool {
			return endpoint == "https://"+netip.AddrPortFrom(peer.Address.Addr(), uint16(members.ClientPort)).String()
		})
		if !member || seen[endpoint] {
			return fmt.Errorf("%s must list distinct https://IP:%d client endpoints of the %s, not %q",
				EnvAPIEndpoints, members.ClientPort, terrabase.EnvPeers, endpoint)
		}
		seen[endpoint] = true
	}
	return nil
}

func caCertificates(roots string) bool {
	rest, count := []byte(roots), 0
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			return count > 0 && strings.TrimSpace(string(rest)) == ""
		}
		count++
		certificate, err := x509.ParseCertificate(block.Bytes)
		if block.Type != "CERTIFICATE" || err != nil || !certificate.IsCA || count > 4 {
			return false
		}
		rest = next
	}
}

// Layout is ts-auth's directory below the host's ts-auth root.
type Layout string

// Bundle is where the single-file binary extracts its native libraries.
func (l Layout) Bundle() string { return filepath.Join(string(l), "bundle") }

// Env is the replica's environment: the profile, the secrets and the
// host-owned settings. TS_AUTH_DATABASE becomes <project-ulid>/<database>
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

// ValidateSecrets checks that secrets holds the Secrets in their forms and
// otherwise only non-empty OptionalSecrets, which ts-auth validates itself.
// Errors name keys, never values.
func ValidateSecrets(secrets map[string]string) error {
	for key, value := range secrets {
		if !slices.Contains(Secrets, key) && (!slices.Contains(OptionalSecrets, key) || value == "") {
			return fmt.Errorf("ts-auth needs %s and may add only non-empty %s, not %s",
				strings.Join(Secrets, ", "), strings.Join(OptionalSecrets, ", "), key)
		}
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
		// Existing regional projects keep their UUIDv7 IDs when a host restarts.
		if !ulidRE.MatchString(value) && !uuidV7RE.MatchString(value) {
			return fmt.Errorf("%s must be a canonical uppercase ULID or lowercase UUIDv7", key)
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

// LoadBalancer is what the cell's public API load balancer, gru-1-api in
// gru-1 (TS-486), needs to serve ts-auth: a Hostname rule to a backend set of every controller,
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
	entry, ok := catalog.Lookup(fmt.Sprint(plan["cell"]))
	if !ok {
		return LoadBalancer{}, fmt.Errorf("plan cell %v is not a catalog cell", plan["cell"])
	}
	hosts, _ := plan["hosts"].([]any)
	set := LoadBalancer{Hostname: Hostname(entry.Name()), Port: Port, HealthPath: ReadyPath}
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
