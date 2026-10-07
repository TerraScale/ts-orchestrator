// Package cellspec is a cell's signed desired state: the amendable sections
// of its configuration that running controllers adopt without a rebuild or a
// config edit. The signed controller config holds generation 0. Running
// controllers accept a later spec when it is signed for the exact
// deployment, cell and environment and its generation follows the current
// one, so unsigned specs, replays and rollbacks are refused.
//
// The release leaf, under a root delegation, signs ordinary amendments. An
// amendment that widens authority (AuthorityChanges) needs a root to sign
// the spec itself. Every amendment names the spec level it needs
// (requires_binary): a controller whose binary understands less refuses it
// gracefully and keeps the spec it has.
package cellspec

import (
	"bytes"
	"cmp"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/atlas"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostpool"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/machinesapi"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/bucket"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/nsg"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/routetable"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/seclist"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/placement"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
)

const (
	Domain = "terrascale.controller.cell-spec"
	Schema = "terrascale.controller.cell-spec.v1"
	// BinaryLevel is the highest requires_binary this binary understands.
	// A change that adds a section raises it, and amendments that use the
	// section require the new level.
	// Level 2 adds profile secrets, level 3 the budget, level 4 host images,
	// level 5 the kv_snapshot schedule, level 6 the rollout policy, level 7
	// the desired OCI resources, level 8 the trusted signers, level 9 the
	// launch image, level 10 the artifact store quota, level 11 the Atlas
	// publisher, level 12 the release fence, level 13 a fenced set's
	// min_serving, level 14 a fenced set's role, level 15 the release
	// fence's canary, level 16 the Machines API, level 17 a host grant's
	// controller, level 18 the dashboard, level 19 a signer's
	// can_install_material.
	BinaryLevel = 19
	// MaxHostImages bounds the image allow-list: the images a rollout moves
	// between, plus room to stage the next one.
	MaxHostImages = 4
	// MaxDelegationLifetime bounds the root's grant to the release leaf; the
	// root re-issues it offline.
	MaxDelegationLifetime = 31 * 24 * time.Hour
	// MaxSpecLifetime bounds how long a signed spec may wait to be applied.
	// Once accepted it stays in force until a later generation replaces it.
	MaxSpecLifetime = 24 * time.Hour
	MaxSpecBytes    = 32 << 10
	MaxSignedBytes  = 48 << 10
	clockSkew       = time.Minute
	scopeRole       = "cell-spec"
	scopeSlot       = "spec"
)

var (
	ErrInvalid   = errors.New("cell spec is invalid")
	tokenRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	hostRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}[a-z0-9]$`)
	controllerRE = regexp.MustCompile(`^controller-[a-z]$`)
	deploymentR  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// NewerBinaryError refuses an amendment that needs a newer binary. It is
// expected while a binary rolls out: the controller keeps its current spec.
type NewerBinaryError struct {
	Generation     uint64
	RequiresBinary uint64
}

func (e *NewerBinaryError) Error() string {
	return fmt.Sprintf("cell spec generation %d requires binary level %d; this binary understands level %d",
		e.Generation, e.RequiresBinary, BinaryLevel)
}

// Profile is a role's signed delivery profile: the resources placement
// reserves and the arguments and environment every replica starts with.
// Secrets are environment settings the host reads from OCI Vault at each
// start; the profile holds only their names.
type Profile struct {
	Resources placement.Resources        `json:"resources"`
	Args      []string                   `json:"args,omitempty"`
	Env       map[string]string          `json:"env,omitempty"`
	Secrets   map[string]vaultsecret.Ref `json:"secrets,omitempty"`
}

// Service is one generic workload. Spec is set when the controller's
// workload reconciler owns the role; without it releases place the role.
// Releasers are actors, already trusted signers of the signed controller
// config, that may release the role and register its hosts in the spec's
// environment.
type Service struct {
	Role      string                `json:"role"`
	Profile   Profile               `json:"profile"`
	Spec      *workload.ServiceSpec `json:"spec,omitempty"`
	Releasers []string              `json:"releasers,omitempty"`
}

// HostGrant lets one static host enroll: the host named Node, at PrivateIP,
// registers Roles in Environment, with one replica's resources per role.
// Controller VMs run their own ts-auth host agents this way, and role
// terrabase colocates the member TERRABASE_PEERS lists at PrivateIP.
// Controller names the controller slot (controller-a) whose VM the host is,
// once the node no longer carries the slot's NATS server name (TS-609
// renamed gru-1-ctl-1 to ts-gru-1); empty means that name.
type HostGrant struct {
	Node        string   `json:"node"`
	PrivateIP   string   `json:"private_ip"`
	Roles       []string `json:"roles"`
	Environment string   `json:"environment"`
	Controller  string   `json:"controller,omitempty"`
}

// HostImage is one qualified OS image that managed hosts may run besides the
// signed fleet image: its release image receipt and the root's delegation
// that signs it, as exact canonical envelopes. A host launched from an
// allowed image stays a fleet member; removing the image makes its hosts
// foreign again.
type HostImage struct {
	ImageID    string         `json:"image_id"`
	Receipt    jsontext.Value `json:"receipt"`
	Delegation jsontext.Value `json:"delegation"`
}

// Identity is the deployment, cell and environment a controller accepts
// specs for. Production controllers take it from their image.
type Identity struct {
	DeploymentID string `json:"deployment_id"`
	Cell         string `json:"cell"`
	Environment  string `json:"environment"`
}

// Spec is the complete desired state of one cell at one generation. Its
// sections replace the cell's previous ones as a whole. Services are sorted
// by role.
type Spec struct {
	Schema string `json:"schema"`
	Identity
	Generation uint64 `json:"generation"`
	// RequiresBinary is the lowest spec level a controller binary must
	// understand to adopt this amendment.
	RequiresBinary uint64      `json:"requires_binary"`
	Services       []Service   `json:"services"`
	HostGrants     []HostGrant `json:"host_grants,omitempty"`
	// Budget is the monthly cap on the cell's OCI spend that node pools
	// launch hosts within.
	Budget     *hostpool.Budget `json:"budget,omitempty"`
	HostImages []HostImage      `json:"host_images,omitempty"`
	// KVSnapshot schedules the configuration bucket snapshots.
	KVSnapshot *KVSnapshot `json:"kv_snapshot,omitempty"`
	// RolloutPolicy replaces the signed config's policy for the cell's next
	// orchestrator rollouts; a rollout keeps the policy it started with.
	RolloutPolicy *rollout.Policy `json:"rollout_policy,omitempty"`
	// OCIDesired replaces the signed config's desired OCI resources.
	OCIDesired *OCIDesired `json:"oci_desired,omitempty"`
	// Signers replace the signed config's trusted signers, sorted by actor;
	// none keeps the signed ones. Only a root may change them.
	Signers []TrustedSigner `json:"signers,omitempty"`
	// LaunchImage names the host image new managed hosts boot instead of
	// the fleet's pinned image; empty keeps the pin.
	LaunchImage string `json:"launch_image,omitempty"`
	// ArtifactStore replaces the signed config's delivery artifact store
	// quota.
	ArtifactStore *ArtifactStore `json:"artifact_store,omitempty"`
	// Atlas makes the authority leader publish the cell's topology to
	// ts-atlas (internal/atlas); nil publishes nothing.
	Atlas *atlas.Config `json:"atlas,omitempty"`
	// ReleaseFence makes the leader's service releases (TS-610) restart one
	// node at a time, each fenced on the load balancer first; nil restarts
	// every replica at once. Adding or changing it needs a root.
	ReleaseFence *ReleaseFence `json:"release_fence,omitempty"`
	// MachinesAPI makes every controller serve the Machines REST API for
	// the regional load balancer's <region>.orch host; nil serves none.
	// Adding or changing it needs a root.
	MachinesAPI *MachinesAPI `json:"machines_api,omitempty"`
	// Dashboard makes every controller serve the read-only operator
	// dashboard on its NetBird address at DashboardPort, behind a bearer
	// token read from Vault; nil serves it there on none. Adding or
	// changing it needs a root.
	Dashboard *Dashboard `json:"dashboard,omitempty"`
}

// DashboardPort is where a controller serves the operator dashboard on its
// NetBird address: the observability port, on another interface.
const DashboardPort = 9463

// DashboardRole and DashboardKey name the dashboard token's Vault secret:
// <cell>-<n>-orch-dashboard-token.
const (
	DashboardRole = "orch-dashboard"
	DashboardKey  = "TOKEN"
)

// Dashboard is the operator dashboard's NetBird listener (docs/observability.md).
// Token is the bearer token operators present, or exchange for a browser
// session; every controller of the cell reads the same secret.
type Dashboard struct {
	Token vaultsecret.Ref `json:"token"`
}

// MachinesAPIPort is where a controller serves the Machines REST API on its
// broker address.
const MachinesAPIPort = 8444

// MachinesAPI is the Machines REST API's token and tenancy policy
// (docs/machines-api.md). Every controller serves it on its broker address
// at MachinesAPIPort with its signed controller TLS certificate, which the
// load balancer verifies against the cell CA.
type MachinesAPI struct {
	Issuer   string              `json:"issuer"`
	Audience string              `json:"audience"`
	JWKSURLs []string            `json:"jwks_urls"`
	Clients  []string            `json:"clients"`
	Members  map[string][]string `json:"members,omitempty"`
}

// Config is the API's listener on host with the controller's TLS files.
func (m MachinesAPI) Config(host, certFile, keyFile string) machinesapi.Config {
	return machinesapi.Config{ListenAddress: net.JoinHostPort(host, strconv.Itoa(MachinesAPIPort)),
		TLSCertFile: certFile, TLSKeyFile: keyFile, Issuer: m.Issuer, Audience: m.Audience,
		JWKSURLs: m.JWKSURLs, Clients: m.Clients, Members: m.Members}
}

// ReleaseFence names the load balancer backend sets that serve a node's
// workloads. Before a service release restarts a node, the leader takes
// each of the node's backends that is in rotation out (drain, then offline
// after DrainGraceSeconds), while another backend of the set serves healthy;
// it returns them once the node serves the release and keeps them in
// rotation for SettleSeconds before the next node.
type ReleaseFence struct {
	LoadBalancerID    string      `json:"load_balancer_id"`
	BackendSets       []FencedSet `json:"backend_sets"`
	DrainGraceSeconds int         `json:"drain_grace_seconds,omitzero"`
	SettleSeconds     int         `json:"settle_seconds,omitzero"`
	// Canary gates each release on its first node (TS-623): once the node
	// serves the release, still out of rotation, the leader runs live
	// checks against it before any other node restarts. Nil gates nothing.
	Canary *Canary `json:"canary,omitempty"`
}

// Canary is what a release fence's canary gate checks with: credentials of
// a test project, read from Vault, and the database of that project the
// gate writes a document in. AuthURL and APIURL are the cell's public
// ts-auth and TerraBase origins, used for the role the canary does not run;
// DashboardLoginURL, when set, is the dashboard's sign-in page.
type Canary struct {
	Credentials       vaultsecret.Ref `json:"credentials"`
	Project           string          `json:"project"`
	Database          string          `json:"database"`
	AuthURL           string          `json:"auth_url"`
	APIURL            string          `json:"api_url"`
	DashboardLoginURL string          `json:"dashboard_login_url,omitempty"`
}

// CanaryRole and CanaryKey name the canary's Vault secret:
// <cell>-<n>-canary-credentials.
const (
	CanaryRole = "canary"
	CanaryKey  = "CANARY_CREDENTIALS"
)

var (
	// canaryProjectRE admits a ts-auth project id, such as a UUID.
	canaryProjectRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	canaryDatabaseRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

func (c Canary) validate(cell string) error {
	if err := vaultsecret.ValidateRefs(cell, CanaryRole, map[string]vaultsecret.Ref{CanaryKey: c.Credentials}, nil); err != nil {
		return fmt.Errorf("%w: release_fence canary: %w", ErrInvalid, err)
	}
	if !canaryProjectRE.MatchString(c.Project) || !canaryDatabaseRE.MatchString(c.Database) || !originURL(c.AuthURL) ||
		!originURL(c.APIURL) || c.DashboardLoginURL != "" && !httpsURL(c.DashboardLoginURL) {
		return fmt.Errorf("%w: release_fence canary needs a project, a database name and https auth_url and api_url origins", ErrInvalid)
	}
	return nil
}

// httpsURL reports an absolute https URL without credentials.
func httpsURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && len(raw) <= 2048
}

// originURL reports an https origin: no path, query or fragment.
func originURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return httpsURL(raw) && err == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == ""
}

// FencedSet is one backend set; a node's backend in it is the node's
// private address at Port.
type FencedSet struct {
	Name string `json:"name"`
	Port int    `json:"port"`
	// MinServing is the quorum guard: a node's backend is taken out only
	// while at least this many backends of other nodes serve healthy in
	// the set. Zero means DefaultMinServing.
	MinServing int `json:"min_serving,omitzero"`
	// Role makes the leader's edge reconciler own the set: its backends
	// are the role's replicas, each in rotation only while it serves.
	// Empty leaves the set's membership to an operator.
	Role string `json:"role,omitempty"`
}

// DefaultMinServing keeps two members of every fenced set serving, for
// example two TerraBase members and two ts-auth replicas.
const DefaultMinServing = 2

// Min is the set's quorum guard.
func (s FencedSet) Min() int {
	if s.MinServing > 0 {
		return s.MinServing
	}
	return DefaultMinServing
}

// MaxFencedSets bounds a release fence's backend sets.
const MaxFencedSets = 8

func (f ReleaseFence) validate(cell string) error {
	if !strings.HasPrefix(f.LoadBalancerID, "ocid1.loadbalancer.") || len(f.LoadBalancerID) > 255 ||
		strings.ContainsAny(f.LoadBalancerID, " \t\r\n/") {
		return fmt.Errorf("%w: release_fence load_balancer_id must be a load balancer OCID", ErrInvalid)
	}
	if len(f.BackendSets) == 0 || len(f.BackendSets) > MaxFencedSets {
		return fmt.Errorf("%w: release_fence needs 1 to %d backend sets", ErrInvalid, MaxFencedSets)
	}
	for i, set := range f.BackendSets {
		if !tokenRE.MatchString(set.Name) || i > 0 && f.BackendSets[i-1].Name >= set.Name || set.Port < 1 || set.Port > 65535 {
			return fmt.Errorf("%w: release_fence backend sets must be sorted names without repeats, each with a port", ErrInvalid)
		}
		if set.MinServing < 0 || set.MinServing > 64 {
			return fmt.Errorf("%w: release_fence min_serving must be between 0 and 64", ErrInvalid)
		}
		if set.Role != "" && !tokenRE.MatchString(set.Role) {
			return fmt.Errorf("%w: release_fence role must be a role name", ErrInvalid)
		}
	}
	if f.DrainGraceSeconds < 0 || f.DrainGraceSeconds > 300 || f.SettleSeconds < 0 || f.SettleSeconds > 300 {
		return fmt.Errorf("%w: release_fence drain_grace_seconds and settle_seconds must be between 0 and 300", ErrInvalid)
	}
	if f.Canary != nil {
		return f.Canary.validate(cell)
	}
	return nil
}

// ArtifactStore is the delivery artifact store's byte quota. Each controller
// refuses one its embedded NATS store cannot hold beside its control state,
// and the leader raises it only while its disk has room.
type ArtifactStore struct {
	MaxBytes int64 `json:"max_bytes"`
}

// TrustedSigner grants an actor's Ed25519 key operator requests and
// releases for its roles and environments, and the capabilities it sets.
type TrustedSigner struct {
	Actor                            string   `json:"actor"`
	PublicKey                        string   `json:"public_key"`
	Roles                            []string `json:"roles"`
	Environments                     []string `json:"environments"`
	CanRegisterHosts                 bool     `json:"can_register_hosts,omitzero"`
	CanPlaceTerraBase                bool     `json:"can_place_terrabase,omitzero"`
	CanUpdateTerraBaseRuntime        bool     `json:"can_update_terrabase_runtime,omitzero"`
	CanCertifyTerraBaseCompatibility bool     `json:"can_certify_terrabase_compatibility,omitzero"`
	CanTeardownTerraBase             bool     `json:"can_teardown_terrabase,omitzero"`
	CanPrepareManagedMaterial        bool     `json:"can_prepare_managed_material,omitzero"`
	CanOperateBackup                 bool     `json:"can_operate_backup,omitzero"`
	CanManageClientKeys              bool     `json:"can_manage_client_keys,omitzero"`
	ClientKeyScopes                  []string `json:"client_key_scopes,omitempty"`
	CanRotateBrokerAccount           bool     `json:"can_rotate_broker_account,omitzero"`
	// CanRollOutOrchestrator lets the signer publish, pause, resume and roll
	// back the cell's orchestrator release (ts-orch rollout).
	CanRollOutOrchestrator bool `json:"can_roll_out_orchestrator,omitzero"`
	// CanInstallMaterial lets the signer publish a root-signed material
	// generation and arm controller slots to install it (TS-668).
	CanInstallMaterial bool     `json:"can_install_material,omitzero"`
	Repositories       []string `json:"repositories,omitempty"`
}

// OCIDesiredEntry is one desired OCI resource. Policy is "report" (the
// default: drift is only recorded) or "enforce".
type OCIDesiredEntry[S any] struct {
	Policy string `json:"policy,omitempty"`
	Spec   S      `json:"spec"`
}

// OCIDesired lists the cell's desired OCI specs by logical name per kind;
// the leader publishes them into TS_OCI_DESIRED before every reconcile pass.
type OCIDesired struct {
	NSGRules      map[string]OCIDesiredEntry[nsg.Spec]        `json:"nsg_rules,omitempty"`
	SecurityLists map[string]OCIDesiredEntry[seclist.Spec]    `json:"security_lists,omitempty"`
	RouteTables   map[string]OCIDesiredEntry[routetable.Spec] `json:"route_tables,omitempty"`
	Buckets       map[string]OCIDesiredEntry[bucket.Spec]     `json:"buckets,omitempty"`
	// Prune tombstones records of these kinds that this configuration no
	// longer lists, released PruneDelaySeconds later (default one hour).
	// Off by default: unlisted records, including ones written by tools,
	// are left alone.
	Prune             bool `json:"prune,omitzero"`
	PruneDelaySeconds int  `json:"prune_delay_seconds,omitzero"`
}

// KVSnapshot is how often the authority leader uploads changed
// configuration buckets, and a pause. Zero IntervalSeconds keeps the signed
// controller config's interval. The location stays in the signed config: a
// rebuilt cell restores from it before any KV bucket exists.
type KVSnapshot struct {
	IntervalSeconds int  `json:"interval_seconds,omitzero"`
	Paused          bool `json:"paused,omitzero"`
}

// Signed is what an operator applies and what controllers store, as exact
// canonical bytes: the spec envelope and, when the release leaf signed it,
// the root's delegation to the leaf. A spec without a delegation is signed
// by a root itself.
type Signed struct {
	Delegation jsontext.Value `json:"delegation,omitzero"`
	Spec       jsontext.Value `json:"spec"`
}

// Verified is a spec that passed verification and who signed it.
type Verified struct {
	Spec
	// RootSigned is set when a root signed the spec itself, which
	// authority-widening amendments need.
	RootSigned bool
}

func (id Identity) Validate() error {
	if !deploymentR.MatchString(id.DeploymentID) || !tokenRE.MatchString(id.Cell) || !tokenRE.MatchString(id.Environment) {
		return fmt.Errorf("%w: deployment, cell or environment", ErrInvalid)
	}
	return nil
}

// Scope is the exact signature scope of a spec for this identity.
func (id Identity) Scope() trust.Scope {
	return trust.Scope{Domain: Domain, DeploymentID: id.DeploymentID, Cell: id.Cell,
		Environment: id.Environment, Role: scopeRole, Slot: scopeSlot}
}

// Validate checks the spec's structure. Controllers also check every profile
// and service spec against the cell's own rules before they accept it.
func (s Spec) Validate() error {
	if s.Schema != Schema {
		return fmt.Errorf("%w: schema", ErrInvalid)
	}
	if err := s.Identity.Validate(); err != nil {
		return err
	}
	if s.RequiresBinary < s.Level() || s.RequiresBinary > BinaryLevel {
		return fmt.Errorf("%w: requires_binary must be between %d and %d", ErrInvalid, s.Level(), BinaryLevel)
	}
	for index, service := range s.Services {
		if !tokenRE.MatchString(service.Role) {
			return fmt.Errorf("%w: role %q", ErrInvalid, service.Role)
		}
		if index > 0 && s.Services[index-1].Role >= service.Role {
			return fmt.Errorf("%w: services must be sorted by role without repeats", ErrInvalid)
		}
		for i, actor := range service.Releasers {
			if !tokenRE.MatchString(actor) || i > 0 && service.Releasers[i-1] >= actor {
				return fmt.Errorf("%w: service %q releasers must be sorted actor names without repeats", ErrInvalid, service.Role)
			}
		}
		if service.Spec != nil {
			if service.Spec.Role != service.Role {
				return fmt.Errorf("%w: service %q has a spec for role %q", ErrInvalid, service.Role, service.Spec.Role)
			}
			if err := service.Spec.Validate(); err != nil {
				return fmt.Errorf("service %q: %w", service.Role, err)
			}
		}
	}
	if s.Budget != nil {
		if err := s.Budget.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	if snapshot := s.KVSnapshot; snapshot != nil && snapshot.IntervalSeconds != 0 &&
		(snapshot.IntervalSeconds < 5 || snapshot.IntervalSeconds > 3600) {
		return fmt.Errorf("%w: kv_snapshot interval_seconds must be 0 or 5 to 3600", ErrInvalid)
	}
	if s.RolloutPolicy != nil {
		if err := s.RolloutPolicy.Validate(); err != nil {
			return fmt.Errorf("%w: rollout_policy: %w", ErrInvalid, err)
		}
	}
	if s.OCIDesired != nil {
		if err := s.OCIDesired.Validate(); err != nil {
			return fmt.Errorf("%w: oci_desired: %w", ErrInvalid, err)
		}
	}
	for index, signer := range s.Signers {
		if !tokenRE.MatchString(signer.Actor) || index > 0 && s.Signers[index-1].Actor >= signer.Actor {
			return fmt.Errorf("%w: signers must be sorted by actor without repeats", ErrInvalid)
		}
	}
	addresses, controllers := map[string]bool{}, map[string]bool{}
	for index, grant := range s.HostGrants {
		if grant.Controller != "" {
			if !controllerRE.MatchString(grant.Controller) || controllers[grant.Controller] {
				return fmt.Errorf("%w: host grant %q controller must be one controller-<letter> slot per grant", ErrInvalid, grant.Node)
			}
			controllers[grant.Controller] = true
		}
		address, err := netip.ParseAddr(grant.PrivateIP)
		if !hostRE.MatchString(grant.Node) || index > 0 && s.HostGrants[index-1].Node >= grant.Node ||
			err != nil || !address.Is4() || !address.IsPrivate() || address.String() != grant.PrivateIP ||
			addresses[grant.PrivateIP] || len(grant.Roles) == 0 || !tokenRE.MatchString(grant.Environment) {
			return fmt.Errorf("%w: host grants must be sorted by node with one private IPv4 address, roles and an environment each", ErrInvalid)
		}
		addresses[grant.PrivateIP] = true
		for i, role := range grant.Roles {
			if !tokenRE.MatchString(role) || i > 0 && grant.Roles[i-1] >= role {
				return fmt.Errorf("%w: host grant %q roles must be sorted without repeats", ErrInvalid, grant.Node)
			}
		}
	}
	if len(s.HostImages) > MaxHostImages {
		return fmt.Errorf("%w: at most %d host images", ErrInvalid, MaxHostImages)
	}
	for index, image := range s.HostImages {
		if !release.ValidOCIImageIDForRegion(image.ImageID, s.logicalRegion()) ||
			index > 0 && s.HostImages[index-1].ImageID >= image.ImageID ||
			len(image.Receipt) == 0 || len(image.Delegation) == 0 {
			return fmt.Errorf("%w: host images must be sorted by a cell image ID without repeats, each with a receipt and delegation", ErrInvalid)
		}
	}
	if _, allowed := s.HostImage(s.LaunchImage); s.LaunchImage != "" && !allowed {
		return fmt.Errorf("%w: the launch image must be one of the host images", ErrInvalid)
	}
	if s.ArtifactStore != nil && s.ArtifactStore.MaxBytes <= 0 {
		return fmt.Errorf("%w: artifact_store max_bytes must be positive", ErrInvalid)
	}
	if s.Atlas != nil {
		if err := s.Atlas.Validate(s.Identity.Cell); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	if s.ReleaseFence != nil {
		if err := s.ReleaseFence.validate(s.Identity.Cell); err != nil {
			return err
		}
	}
	if s.MachinesAPI != nil {
		if err := s.MachinesAPI.Config("127.0.0.1", "", "").Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalid, err)
		}
	}
	if s.Dashboard != nil {
		if err := vaultsecret.ValidateRefs(s.Identity.Cell, DashboardRole,
			map[string]vaultsecret.Ref{DashboardKey: s.Dashboard.Token}, nil); err != nil {
			return fmt.Errorf("%w: dashboard: %w", ErrInvalid, err)
		}
	}
	return nil
}

// logicalRegion is the release region of the cell's images: cell gru boots
// GRU images.
func (id Identity) logicalRegion() string { return strings.ToUpper(id.Cell) }

// HostImage returns the allowed host image imageID.
func (s Spec) HostImage(imageID string) (HostImage, bool) {
	index := slices.IndexFunc(s.HostImages, func(image HostImage) bool { return image.ImageID == imageID })
	if index < 0 {
		return HostImage{}, false
	}
	return s.HostImages[index], true
}

// VerifyHostImages checks that a root qualified host images for the spec's
// environment and cell: each receipt names exactly its image and is signed
// under a root's image delegation. Without now, it checks every image as of
// its signatures' issue. With now, it checks only the images that previous
// lacks or holds with other bytes, and a newly chosen launch image, with
// current signatures, so an amendment can add, change or launch only an
// image that is qualified today, while an accepted image stays allowed after
// its receipt expires.
func VerifyHostImages(previous, next Spec, roots trust.Keyring, now *time.Time) error {
	for _, image := range next.HostImages {
		expected := release.ImageExpectation{Environment: next.Environment,
			LogicalRegion: next.logicalRegion(), OCIImageOCID: image.ImageID}
		var err error
		if now == nil {
			_, err = release.VerifyImageHistorical(image.Receipt, image.Delegation, roots, expected)
		} else if before, kept := previous.HostImage(image.ImageID); !kept || !reflect.DeepEqual(before, image) ||
			image.ImageID == next.LaunchImage && next.LaunchImage != previous.LaunchImage {
			_, err = release.VerifyImageCurrent(image.Receipt, image.Delegation, roots, expected, *now)
		}
		if err != nil {
			return fmt.Errorf("host image %s is not qualified: %w", image.ImageID, err)
		}
	}
	return nil
}

// Grant returns the host grant of node.
func (s Spec) Grant(node string) (HostGrant, bool) {
	index := slices.IndexFunc(s.HostGrants, func(grant HostGrant) bool { return grant.Node == node })
	if index < 0 {
		return HostGrant{}, false
	}
	return s.HostGrants[index], true
}

// Level is the lowest requires_binary the spec's sections need: 2 once a
// profile names Vault secrets, 3 with a budget, 4 once it allows host
// images, 5 with a kv_snapshot schedule, 6 with a rollout policy, 7 with
// desired OCI resources, 8 with signers, 9 once it names a launch image and
// 10 with an artifact store quota, 11 with an Atlas publisher, 12 with
// a release fence (13, 14 and 15 with its min_serving, role and canary) and
// 16 with the Machines API, 17 once a host grant names its controller and
// 18 with the dashboard, which an older binary could not read.
func (s Spec) Level() uint64 {
	level := uint64(1)
	for _, service := range s.Services {
		if len(service.Profile.Secrets) != 0 {
			level = 2
		}
	}
	if s.Budget != nil {
		level = max(level, 3)
	}
	if len(s.HostImages) != 0 {
		level = 4
	}
	if s.KVSnapshot != nil {
		level = max(level, 5)
	}
	if s.RolloutPolicy != nil {
		level = max(level, 6)
	}
	if s.OCIDesired != nil {
		level = max(level, 7)
	}
	if len(s.Signers) != 0 {
		level = max(level, 8)
	}
	if s.LaunchImage != "" {
		level = 9
	}
	if s.ArtifactStore != nil {
		level = 10
	}
	if s.Atlas != nil {
		level = 11
	}
	if s.ReleaseFence != nil {
		level = 12
		if slices.ContainsFunc(s.ReleaseFence.BackendSets, func(set FencedSet) bool { return set.MinServing != 0 }) {
			level = 13
		}
		if slices.ContainsFunc(s.ReleaseFence.BackendSets, func(set FencedSet) bool { return set.Role != "" }) {
			level = 14
		}
		if s.ReleaseFence.Canary != nil {
			level = 15
		}
	}
	if s.MachinesAPI != nil {
		level = 16
	}
	if slices.ContainsFunc(s.HostGrants, func(grant HostGrant) bool { return grant.Controller != "" }) {
		level = 17
	}
	if s.Dashboard != nil {
		level = 18
	}
	if slices.ContainsFunc(s.Signers, func(signer TrustedSigner) bool { return signer.CanInstallMaterial }) {
		level = 19
	}
	return level
}

// Find returns the service of role.
func (s Spec) Find(role string) (Service, bool) {
	for _, service := range s.Services {
		if service.Role == role {
			return service, true
		}
	}
	return Service{}, false
}

// Encode returns the canonical payload bytes of the spec.
func Encode(spec Spec) ([]byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	encoded, err := trust.EncodePayload(spec)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxSpecBytes {
		return nil, fmt.Errorf("%w: spec exceeds %d bytes", ErrInvalid, MaxSpecBytes)
	}
	return encoded, nil
}

// Decode strictly decodes canonical spec payload bytes. An amendment for a
// newer binary is refused with a NewerBinaryError before its sections are
// read; an unknown section is refused as invalid.
func Decode(encoded []byte) (Spec, error) {
	if len(encoded) > MaxSpecBytes {
		return Spec{}, fmt.Errorf("%w: spec exceeds %d bytes", ErrInvalid, MaxSpecBytes)
	}
	var header struct {
		Schema         string `json:"schema"`
		Generation     uint64 `json:"generation"`
		RequiresBinary uint64 `json:"requires_binary"`
	}
	if err := json.Unmarshal(encoded, &header); err == nil && header.Schema == Schema && header.RequiresBinary > BinaryLevel {
		return Spec{}, &NewerBinaryError{Generation: header.Generation, RequiresBinary: header.RequiresBinary}
	}
	var spec Spec
	if err := protocol.DecodeStrict(encoded, &spec, MaxSpecBytes); err != nil {
		return Spec{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	canonical, err := Encode(spec)
	if err != nil {
		return Spec{}, err
	}
	if !bytes.Equal(canonical, encoded) {
		return Spec{}, fmt.Errorf("%w: spec is not canonical JSON", ErrInvalid)
	}
	return spec, nil
}

// Candidate reads the spec of an unsigned candidate or of a signed file
// without verifying any signature, for review before apply.
func Candidate(data []byte) (Spec, error) {
	var signed Signed
	if protocol.DecodeStrict(data, &signed, MaxSignedBytes) != nil || len(signed.Spec) == 0 {
		return Decode(data)
	}
	envelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		return Spec{}, fmt.Errorf("signed spec envelope: %w", err)
	}
	return Decode(envelope.Payload)
}

// Digest is the SHA-256 of the spec's canonical payload.
func Digest(spec Spec) (string, error) {
	encoded, err := Encode(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// SignDelegation is the offline root operation: it lets leaf sign ordinary
// amendments for one identity.
func SignDelegation(leaf ed25519.PublicKey, id Identity, issuedAt, expiresAt time.Time,
	root ed25519.PrivateKey,
) (trust.Envelope, error) {
	if err := id.Validate(); err != nil {
		return trust.Envelope{}, err
	}
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxDelegationLifetime {
		return trust.Envelope{}, fmt.Errorf("cell spec delegation must expire within %s", MaxDelegationLifetime)
	}
	keyID, err := trust.KeyID(leaf)
	if err != nil {
		return trust.Envelope{}, err
	}
	encoded, err := trust.EncodeDelegatedPublicKey(leaf)
	if err != nil {
		return trust.Envelope{}, err
	}
	scope := id.Scope()
	return trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: keyID,
		SubjectPublicKey: encoded, Capabilities: []trust.Capability{{Domain: scope.Domain,
			DeploymentID: scope.DeploymentID, Cell: scope.Cell, Environment: scope.Environment,
			Role: scope.Role, Slots: []string{scope.Slot}, Actions: []string{"sign"}}}}, issuedAt, expiresAt, root)
}

// Sign signs a spec of generation one or later and checks the result as a
// controller would, so a spec signed under a wrong or expired delegation, or
// by a key that is not a root, fails here instead of on the cell. With a
// delegation the signer is the release leaf; without one it is a root.
func Sign(spec Spec, delegationWire []byte, roots trust.Keyring, now time.Time, validFor time.Duration,
	signer ed25519.PrivateKey,
) ([]byte, error) {
	if spec.Generation == 0 {
		return nil, fmt.Errorf("%w: generation 0 is the signed controller config's spec", ErrInvalid)
	}
	if validFor <= 0 || validFor > MaxSpecLifetime {
		return nil, fmt.Errorf("cell spec validity must be positive and at most %s", MaxSpecLifetime)
	}
	payload, err := Encode(spec)
	if err != nil {
		return nil, err
	}
	issuedAt := now.Round(0).UTC().Truncate(time.Second)
	envelope, err := trust.Sign(payload, spec.Identity.Scope(), issuedAt, issuedAt.Add(validFor), signer)
	if err != nil {
		return nil, err
	}
	specWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(Signed{Delegation: bytes.Clone(delegationWire), Spec: specWire})
	if err != nil {
		return nil, err
	}
	if _, err := VerifyCurrent(wire, roots, spec.Identity, now); err != nil {
		return nil, err
	}
	return wire, nil
}

// VerifyCurrent is the controller's admission check: currently valid
// signatures for exactly id and a valid spec of generation one or later.
func VerifyCurrent(wire []byte, roots trust.Keyring, id Identity, now time.Time) (Verified, error) {
	return verify(wire, roots, id, &now)
}

// VerifyHistorical re-checks an accepted spec without expiry: a controller
// reloads it after the signatures' validity ended. Removing the root from
// the image still revokes it.
func VerifyHistorical(wire []byte, roots trust.Keyring, id Identity) (Verified, error) {
	return verify(wire, roots, id, nil)
}

func verify(wire []byte, roots trust.Keyring, id Identity, now *time.Time) (Verified, error) {
	if err := id.Validate(); err != nil {
		return Verified{}, err
	}
	var signed Signed
	if err := protocol.DecodeStrict(wire, &signed, MaxSignedBytes); err != nil {
		return Verified{}, fmt.Errorf("decode signed cell spec: %w", err)
	}
	// One signed spec has one wire form, so its digest names it.
	if canonical, err := protocol.EncodeJSON(signed); err != nil || !bytes.Equal(canonical, wire) {
		return Verified{}, fmt.Errorf("%w: signed cell spec is not canonical JSON", ErrInvalid)
	}
	specEnvelope, err := trust.DecodeEnvelope(signed.Spec)
	if err != nil {
		return Verified{}, fmt.Errorf("cell spec envelope: %w", err)
	}
	specPolicy := trust.Policy{MaxLifetime: MaxSpecLifetime, ClockSkew: clockSkew}
	var payload []byte
	rootSigned := len(signed.Delegation) == 0
	switch {
	case rootSigned && now != nil:
		payload, err = trust.VerifyCurrent(specEnvelope, id.Scope(), roots, *now, specPolicy)
	case rootSigned:
		payload, err = trust.VerifyHistorical(specEnvelope, id.Scope(), roots, specPolicy)
	default:
		payload, err = verifyDelegated(signed.Delegation, specEnvelope, roots, id, now, specPolicy)
	}
	if err != nil {
		return Verified{}, fmt.Errorf("verify cell spec signature: %w", err)
	}
	spec, err := Decode(payload)
	if err != nil {
		return Verified{}, err
	}
	if spec.Identity != id || spec.Generation == 0 {
		return Verified{}, fmt.Errorf("%w: signed spec names another identity or generation 0", ErrInvalid)
	}
	return Verified{Spec: spec, RootSigned: rootSigned}, nil
}

func verifyDelegated(delegationWire []byte, specEnvelope trust.Envelope, roots trust.Keyring, id Identity,
	now *time.Time, specPolicy trust.Policy,
) ([]byte, error) {
	delegationEnvelope, err := trust.DecodeEnvelope(delegationWire)
	if err != nil {
		return nil, fmt.Errorf("delegation: %w", err)
	}
	delegationPolicy := trust.Policy{MaxLifetime: MaxDelegationLifetime, ClockSkew: clockSkew}
	if now != nil {
		delegation, err := trust.VerifyDelegationCurrent(delegationEnvelope, roots, *now, delegationPolicy)
		if err != nil {
			return nil, fmt.Errorf("delegation: %w", err)
		}
		return trust.VerifyDelegatedCurrent(specEnvelope, id.Scope(), delegation, *now, specPolicy)
	}
	delegation, err := trust.VerifyDelegationHistorical(delegationEnvelope, roots, delegationPolicy)
	if err != nil {
		return nil, fmt.Errorf("delegation: %w", err)
	}
	return trust.VerifyDelegatedHistorical(specEnvelope, id.Scope(), delegation, specPolicy)
}

// AuthorityChanges lists what next widens relative to current; a non-empty
// list needs a root's signature. signed holds the signed controller config's
// profiles, which a role without a service entry keeps. Widening is:
//
//   - a releaser a service did not have, since releasers may release the
//     role and register its hosts;
//   - a new or changed Vault secret ref, since the host reads that secret
//     for the role with an identity that may read more;
//   - a new or changed host grant, since the host receives credentials;
//   - a new or changed host image, since a release image receipt says the
//     image was built and qualified, not that this cell should run it, and
//     a new launch image, which every new host boots (returning to the
//     fleet's signed pin is ordinary);
//   - any change to TerraBase's profile (resources, arguments or a setting),
//     which binds membership, listeners, member certificates and the
//     credentials and token issuers TerraBase trusts;
//   - any budget change but a lower cap in the same currency, since the
//     budget bounds what the cell may spend on hosts;
//   - pausing kv_snapshot, since a rebuilt cell restores only what was
//     uploaded;
//   - in oci_desired, a new or changed enforce entry, turning on prune,
//     shortening the prune delay, and dropping an entry while prune is on,
//     since each changes the cell's OCI resources;
//   - any change to the trusted signers, which decide who may send
//     operator requests and releases at all.
//
// Everything else is an ordinary change.
func AuthorityChanges(current, next Spec, signed map[string]Profile) []string {
	var changes []string
	for _, service := range next.Services {
		before, _ := current.Find(service.Role)
		for _, actor := range service.Releasers {
			if !slices.Contains(before.Releasers, actor) {
				changes = append(changes, fmt.Sprintf("service %s releaser %s", service.Role, actor))
			}
		}
		for key, ref := range service.Profile.Secrets {
			if before.Profile.Secrets[key] != ref {
				changes = append(changes, fmt.Sprintf("service %s Vault secrets", service.Role))
				break
			}
		}
	}
	for _, grant := range next.HostGrants {
		if before, ok := current.Grant(grant.Node); !ok || !reflect.DeepEqual(before, grant) {
			changes = append(changes, "host grant "+grant.Node)
		}
	}
	for _, image := range next.HostImages {
		if before, ok := current.HostImage(image.ImageID); !ok || !reflect.DeepEqual(before, image) {
			changes = append(changes, "host image "+image.ImageID)
		}
	}
	if next.LaunchImage != "" && next.LaunchImage != current.LaunchImage {
		changes = append(changes, "launch image "+next.LaunchImage)
	}
	// The publish key writes what every SDK trusts for region discovery.
	if next.Atlas != nil && !reflect.DeepEqual(current.Atlas, next.Atlas) {
		changes = append(changes, "atlas")
	}
	// A fence takes load balancer backends out of rotation with the
	// controllers' instance principal.
	if next.ReleaseFence != nil && !reflect.DeepEqual(current.ReleaseFence, next.ReleaseFence) {
		changes = append(changes, "release fence")
	}
	// The API's issuer, clients and members decide who reads the cell.
	if next.MachinesAPI != nil && !reflect.DeepEqual(current.MachinesAPI, next.MachinesAPI) {
		changes = append(changes, "machines api")
	}
	// The token decides who reads the cell's dashboard.
	if next.Dashboard != nil && !reflect.DeepEqual(current.Dashboard, next.Dashboard) {
		changes = append(changes, "dashboard")
	}
	if change := budgetChange(current.Budget, next.Budget); change != "" && change != "lowered" {
		changes = append(changes, "budget")
	}
	if next.KVSnapshot != nil && next.KVSnapshot.Paused && (current.KVSnapshot == nil || !current.KVSnapshot.Paused) {
		changes = append(changes, "kv_snapshot pause")
	}
	changes = append(changes, ociDesiredChanges(current.OCIDesired, next.OCIDesired)...)
	for _, actor := range signerChanges(current.Signers, next.Signers) {
		changes = append(changes, "signer "+actor)
	}
	effective := func(spec Spec) Profile {
		if service, ok := spec.Find(terrabase.Role); ok {
			return service.Profile
		}
		return signed[terrabase.Role]
	}
	before, after := effective(current), effective(next)
	if before.Resources != after.Resources {
		changes = append(changes, "terrabase resources")
	}
	if !slices.Equal(before.Args, after.Args) {
		changes = append(changes, "terrabase args")
	}
	keys := slices.Sorted(maps.Keys(before.Env))
	for key := range after.Env {
		if _, found := before.Env[key]; !found {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		old, hadOld := before.Env[key]
		value, hasValue := after.Env[key]
		if hadOld != hasValue || old != value {
			changes = append(changes, "terrabase setting "+key)
		}
	}
	return changes
}

// Plan is the change from one spec to the next, for review before signing.
type Plan struct {
	Identity
	From           uint64   `json:"from_generation"`
	To             uint64   `json:"to_generation"`
	RequiresBinary uint64   `json:"requires_binary"`
	Added          []string `json:"added,omitempty"`
	Updated        []string `json:"updated,omitempty"`
	Removed        []string `json:"removed,omitempty"`
	// HostGrants names each node whose host grant is added, changed or
	// removed.
	HostGrants []string `json:"host_grants,omitempty"`
	// Budget is "added", "updated" or "removed" when the budget changes.
	Budget string `json:"budget,omitempty"`
	// HostImages names each image the allow-list adds, changes or removes.
	HostImages []string `json:"host_images,omitempty"`
	// KVSnapshot is "added", "updated" or "removed" when the kv_snapshot
	// schedule changes.
	KVSnapshot string `json:"kv_snapshot,omitempty"`
	// RolloutPolicy is "added", "updated" or "removed" when the rollout
	// policy changes.
	RolloutPolicy string `json:"rollout_policy,omitempty"`
	// OCIDesired is "added", "updated" or "removed" when the desired OCI
	// resources change.
	OCIDesired string `json:"oci_desired,omitempty"`
	// Signers names each actor whose trusted signer grant is added, changed
	// or removed.
	Signers []string `json:"signers,omitempty"`
	// LaunchImage is the new launch image when it changes, or "pinned" when
	// new hosts return to the fleet's pinned image.
	LaunchImage string `json:"launch_image,omitempty"`
	// ArtifactStore is "added", "updated" or "removed" when the artifact
	// store quota changes.
	ArtifactStore string `json:"artifact_store,omitempty"`
	// Atlas is "added", "updated" or "removed" when the Atlas publisher
	// changes.
	Atlas string `json:"atlas,omitempty"`
	// ReleaseFence is "added", "updated" or "removed" when the release
	// fence changes.
	ReleaseFence string `json:"release_fence,omitempty"`
	// Dashboard is "added", "updated" or "removed" when the dashboard
	// listener changes.
	Dashboard string `json:"dashboard,omitempty"`
	// MachinesAPI is "added", "updated" or "removed" when the Machines API
	// changes.
	MachinesAPI string `json:"machines_api,omitempty"`
	// RootRequired lists the authority-widening changes; the amendment
	// applies only when a root signed it.
	RootRequired []string `json:"root_required,omitempty"`
}

// Diff lists the services next adds, changes and removes relative to
// current and what it widens.
func Diff(current, next Spec, signed map[string]Profile) (Plan, error) {
	plan := Plan{Identity: next.Identity, From: current.Generation, To: next.Generation,
		RequiresBinary: next.RequiresBinary, RootRequired: AuthorityChanges(current, next, signed)}
	for _, service := range next.Services {
		previous, exists := current.Find(service.Role)
		if !exists {
			plan.Added = append(plan.Added, service.Role)
			continue
		}
		before, err := protocol.EncodeJSON(previous)
		if err != nil {
			return Plan{}, err
		}
		after, err := protocol.EncodeJSON(service)
		if err != nil {
			return Plan{}, err
		}
		if !bytes.Equal(before, after) {
			plan.Updated = append(plan.Updated, service.Role)
		}
	}
	for _, service := range current.Services {
		if _, exists := next.Find(service.Role); !exists {
			plan.Removed = append(plan.Removed, service.Role)
		}
	}
	nodes := map[string]bool{}
	for _, grants := range [][]HostGrant{current.HostGrants, next.HostGrants} {
		for _, grant := range grants {
			nodes[grant.Node] = true
		}
	}
	for _, node := range slices.Sorted(maps.Keys(nodes)) {
		before, _ := current.Grant(node)
		after, _ := next.Grant(node)
		if !reflect.DeepEqual(before, after) {
			plan.HostGrants = append(plan.HostGrants, node)
		}
	}
	if plan.Budget = budgetChange(current.Budget, next.Budget); plan.Budget == "lowered" {
		plan.Budget = "updated"
	}
	images := map[string]bool{}
	for _, list := range [][]HostImage{current.HostImages, next.HostImages} {
		for _, image := range list {
			images[image.ImageID] = true
		}
	}
	for _, id := range slices.Sorted(maps.Keys(images)) {
		before, _ := current.HostImage(id)
		after, _ := next.HostImage(id)
		if !reflect.DeepEqual(before, after) {
			plan.HostImages = append(plan.HostImages, id)
		}
	}
	switch before, after := current.KVSnapshot, next.KVSnapshot; {
	case before == nil && after != nil:
		plan.KVSnapshot = "added"
	case before != nil && after == nil:
		plan.KVSnapshot = "removed"
	case before != nil && *before != *after:
		plan.KVSnapshot = "updated"
	}
	switch before, after := current.RolloutPolicy, next.RolloutPolicy; {
	case before == nil && after != nil:
		plan.RolloutPolicy = "added"
	case before != nil && after == nil:
		plan.RolloutPolicy = "removed"
	case before != nil && *before != *after:
		plan.RolloutPolicy = "updated"
	}
	switch before, after := current.OCIDesired, next.OCIDesired; {
	case before == nil && after != nil:
		plan.OCIDesired = "added"
	case before != nil && after == nil:
		plan.OCIDesired = "removed"
	case before != nil && !reflect.DeepEqual(*before, *after):
		plan.OCIDesired = "updated"
	}
	plan.Signers = signerChanges(current.Signers, next.Signers)
	if next.LaunchImage != current.LaunchImage {
		plan.LaunchImage = cmp.Or(next.LaunchImage, "pinned")
	}
	switch before, after := current.ArtifactStore, next.ArtifactStore; {
	case before == nil && after != nil:
		plan.ArtifactStore = "added"
	case before != nil && after == nil:
		plan.ArtifactStore = "removed"
	case before != nil && *before != *after:
		plan.ArtifactStore = "updated"
	}
	switch before, after := current.Atlas, next.Atlas; {
	case before == nil && after != nil:
		plan.Atlas = "added"
	case before != nil && after == nil:
		plan.Atlas = "removed"
	case before != nil && !reflect.DeepEqual(*before, *after):
		plan.Atlas = "updated"
	}
	switch before, after := current.ReleaseFence, next.ReleaseFence; {
	case before == nil && after != nil:
		plan.ReleaseFence = "added"
	case before != nil && after == nil:
		plan.ReleaseFence = "removed"
	case before != nil && !reflect.DeepEqual(*before, *after):
		plan.ReleaseFence = "updated"
	}
	switch before, after := current.MachinesAPI, next.MachinesAPI; {
	case before == nil && after != nil:
		plan.MachinesAPI = "added"
	case before != nil && after == nil:
		plan.MachinesAPI = "removed"
	case before != nil && !reflect.DeepEqual(*before, *after):
		plan.MachinesAPI = "updated"
	}
	switch before, after := current.Dashboard, next.Dashboard; {
	case before == nil && after != nil:
		plan.Dashboard = "added"
	case before != nil && after == nil:
		plan.Dashboard = "removed"
	case before != nil && *before != *after:
		plan.Dashboard = "updated"
	}
	return plan, nil
}

// budgetChange is "added", "removed", "lowered" when only the cap went
// down, "updated" for any other change, or empty. Both the plan and the
// root rule read it, so a field Budget gains is root-gated by default.
func budgetChange(before, after *hostpool.Budget) string {
	switch {
	case before == nil && after == nil:
		return ""
	case before == nil:
		return "added"
	case after == nil:
		return "removed"
	case *before == *after:
		return ""
	}
	lowered := *before
	lowered.MonthlyCapCents = after.MonthlyCapCents
	if lowered == *after && after.MonthlyCapCents < before.MonthlyCapCents {
		return "lowered"
	}
	return "updated"
}

// Empty reports whether the plan changes nothing.
func (p Plan) Empty() bool {
	return len(p.Added)+len(p.Updated)+len(p.Removed)+len(p.HostGrants)+len(p.HostImages) == 0 && p.Budget == "" &&
		p.KVSnapshot == "" && p.RolloutPolicy == "" && p.OCIDesired == "" && len(p.Signers) == 0 &&
		p.LaunchImage == "" && p.ArtifactStore == "" && p.Atlas == "" && p.ReleaseFence == "" && p.MachinesAPI == "" &&
		p.Dashboard == ""
}

// Validate checks each entry's policy and spec and the prune delay. The
// controller also checks the entries against the signed region config.
func (d OCIDesired) Validate() error {
	if d.PruneDelaySeconds < 0 || d.PruneDelaySeconds > 7*24*60*60 {
		return errors.New("prune delay must be between zero and seven days")
	}
	return errors.Join(validDesired(d.NSGRules), validDesired(d.SecurityLists),
		validDesired(d.RouteTables), validDesired(d.Buckets))
}

func validDesired[S interface{ Validate() error }](entries map[string]OCIDesiredEntry[S]) error {
	for name, entry := range entries {
		if entry.Policy != "" && entry.Policy != "report" && entry.Policy != "enforce" {
			return fmt.Errorf("%q has unsupported policy %q", name, entry.Policy)
		}
		if err := entry.Spec.Validate(); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
	}
	return nil
}

// ociDesiredChanges lists what after widens relative to before: a new or
// changed enforce entry, turning on prune, a shorter prune delay while
// prune is on, and an entry dropped while prune is on, since prune then
// releases its resource. Nil means no desired resources.
func ociDesiredChanges(before, after *OCIDesired) []string {
	if before == nil {
		before = &OCIDesired{}
	}
	if after == nil {
		after = &OCIDesired{}
	}
	var changes []string
	if after.Prune && !before.Prune {
		changes = append(changes, "oci_desired prune")
	}
	if after.Prune && before.Prune && pruneDelay(after) < pruneDelay(before) {
		changes = append(changes, "oci_desired prune delay")
	}
	changes = append(changes, desiredChanges("nsg_rules", before.NSGRules, after.NSGRules, after.Prune)...)
	changes = append(changes, desiredChanges("security_lists", before.SecurityLists, after.SecurityLists, after.Prune)...)
	changes = append(changes, desiredChanges("route_tables", before.RouteTables, after.RouteTables, after.Prune)...)
	return append(changes, desiredChanges("buckets", before.Buckets, after.Buckets, after.Prune)...)
}

func pruneDelay(d *OCIDesired) int {
	if d.PruneDelaySeconds == 0 {
		return 60 * 60
	}
	return d.PruneDelaySeconds
}

func desiredChanges[S any](kind string, before, after map[string]OCIDesiredEntry[S], prune bool) []string {
	var changes []string
	for _, name := range slices.Sorted(maps.Keys(after)) {
		entry := after[name]
		if previous, ok := before[name]; entry.Policy == "enforce" && (!ok || !reflect.DeepEqual(previous, entry)) {
			changes = append(changes, "oci_desired "+kind+" "+name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(before)) {
		if _, kept := after[name]; !kept && prune {
			changes = append(changes, "oci_desired "+kind+" "+name+" pruned")
		}
	}
	return changes
}

// signerChanges lists, sorted, each actor whose grant after adds, changes or
// removes relative to before.
func signerChanges(before, after []TrustedSigner) []string {
	grants := func(signers []TrustedSigner) map[string]TrustedSigner {
		byActor := make(map[string]TrustedSigner, len(signers))
		for _, signer := range signers {
			byActor[signer.Actor] = signer
		}
		return byActor
	}
	old, next := grants(before), grants(after)
	var changed []string
	for actor := range old {
		if _, kept := next[actor]; !kept {
			changed = append(changed, actor)
		}
	}
	for actor, grant := range next {
		if previous, ok := old[actor]; !ok || !reflect.DeepEqual(canonicalSigner(previous), canonicalSigner(grant)) {
			changed = append(changed, actor)
		}
	}
	slices.Sort(changed)
	return changed
}

// canonicalSigner sorts the grant's lists, which are sets: their order
// grants nothing.
func canonicalSigner(signer TrustedSigner) TrustedSigner {
	for _, list := range []*[]string{&signer.Roles, &signer.Environments, &signer.ClientKeyScopes, &signer.Repositories} {
		*list = slices.Sorted(slices.Values(*list))
	}
	return signer
}
