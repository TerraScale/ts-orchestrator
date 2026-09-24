package host

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	stateBucket        = "TS_HOST_STATE"
	sessionTTL         = 30 * time.Second
	requestTTL         = 10 * time.Second
	maxClockSkew       = 2 * time.Second
	maxArtifactBytes   = 512 << 20
	artifactChunkBytes = 256 << 10
)

var tokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var managedFaultDomainPattern = regexp.MustCompile(`^FAULT-DOMAIN-[1-3]$`)

var ErrDesiredConflict = errors.New("desired generation or target conflicts with committed state")

// Registration is the controller's durable allowlist for one host identity.
// PublicKey is a base64 encoded Ed25519 key; a higher Generation rotates it.
type Registration struct {
	Cell          string             `json:"cell"`
	Node          string             `json:"node"`
	FailureDomain string             `json:"failure_domain"`
	Environment   string             `json:"environment"`
	Roles         []string           `json:"roles"`
	PublicKey     string             `json:"public_key"`
	Generation    uint64             `json:"generation"`
	Capacity      Capacity           `json:"capacity"`
	ManagedOCI    *ManagedOCIBinding `json:"managed_oci,omitempty"`
}

// ManagedOCIBinding is an operator-assigned OCI identity for a host key. It is
// not hardware attestation; callers must verify ownership and live OCI state.
type ManagedOCIBinding struct {
	Region          string `json:"region"`
	InstanceID      string `json:"instance_id"`
	Owner           string `json:"owner"`
	FleetGeneration uint64 `json:"fleet_generation"`
	CreateKey       string `json:"create_key"`
}

type Capacity struct {
	CPU         int   `json:"cpu"`
	MemoryBytes int64 `json:"memory_bytes"`
	DiskBytes   int64 `json:"disk_bytes"`
}

// Desired is a single host allocation. A generation can be written only once;
// a later generation may replace or withdraw it.
type Desired struct {
	Cell           string            `json:"cell"`
	Node           string            `json:"node"`
	Environment    string            `json:"environment"`
	Role           string            `json:"role"`
	Digest         string            `json:"digest"`
	Generation     uint64            `json:"generation"`
	AuthorityEpoch uint64            `json:"authority_epoch"`
	Args           []string          `json:"args,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	Withdrawn      bool              `json:"withdrawn"`
}

type Receipt struct {
	Generation uint64 `json:"generation"`
	Revision   uint64 `json:"revision"`
}

type Report struct {
	Cell        string    `json:"cell"`
	Node        string    `json:"node"`
	Environment string    `json:"environment"`
	Role        string    `json:"role"`
	Digest      string    `json:"digest"`
	Generation  uint64    `json:"generation"`
	SessionID   string    `json:"session_id"`
	Epoch       uint64    `json:"epoch"`
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
	ObservedAt  time.Time `json:"observed_at"`
}

type HostStatus struct {
	Registration     Registration `json:"registration"`
	SessionExpiresAt time.Time    `json:"session_expires_at,omitzero"`
	Reports          []Report     `json:"reports,omitempty"`
	Verified         bool         `json:"verified"`
}

type AgentConfig struct {
	Cell                string
	Node                string
	Environment         string
	Roles               []string
	Conn                *nats.Conn
	Identity            ed25519.PrivateKey
	ControllerPublicKey ed25519.PublicKey
	Runner              Runner
	InstallRoot         string
	StateRoot           string
	PollInterval        time.Duration
}

type ControllerConfig struct {
	Cell           string
	Conn           *nats.Conn
	JS             jetstream.JetStream
	State          jetstream.KeyValue
	Artifacts      ArtifactStore
	ResponseKey    ed25519.PrivateKey
	StateReplicas  int
	AuthorityEpoch func() uint64
	AuthorityGuard func(context.Context, uint64) error
	HostMutations  authority.HostMutationStore
	ControlLog     jetstream.Stream
}

type ReaderConfig struct {
	Cell          string
	JS            jetstream.JetStream
	State         jetstream.KeyValue
	StateReplicas int
	HostMutations authority.HostMutationStore
	ControlLog    jetstream.Stream
}

// ArtifactStore is the read-only object-store capability held by controllers.
type ArtifactStore interface {
	Get(context.Context, string, ...jetstream.GetObjectOpt) (jetstream.ObjectResult, error)
	GetInfo(context.Context, string, ...jetstream.GetObjectInfoOpt) (*jetstream.ObjectInfo, error)
}

func validateToken(value, name string) error {
	if !tokenPattern.MatchString(value) {
		return fmt.Errorf("invalid %s %q", name, value)
	}
	return nil
}

func validateDigest(value string) error {
	if !digestPattern.MatchString(value) {
		return errors.New("digest must be lowercase SHA-256 hex")
	}
	return nil
}

func validateRegistration(r Registration, cell string) error {
	if r.Cell != cell {
		return errors.New("registration belongs to another cell")
	}
	for name, value := range map[string]string{"cell": r.Cell, "node": r.Node, "environment": r.Environment} {
		if err := validateToken(value, name); err != nil {
			return err
		}
	}
	if r.ManagedOCI != nil {
		if err := validateManagedOCIBinding(*r.ManagedOCI, r.FailureDomain); err != nil {
			return err
		}
	} else if r.FailureDomain != "" {
		if err := validateToken(r.FailureDomain, "failure domain"); err != nil {
			return err
		}
	}
	if r.Generation == 0 || len(r.Roles) == 0 || len(r.Roles) > 32 {
		return errors.New("invalid registration generation or roles")
	}
	seen := make(map[string]bool, len(r.Roles))
	for _, role := range r.Roles {
		if err := validateToken(role, "role"); err != nil {
			return err
		}
		if seen[role] {
			return errors.New("duplicate role")
		}
		seen[role] = true
	}
	if _, err := decodePublicKey(r.PublicKey); err != nil {
		return err
	}
	if r.Capacity.CPU < 0 || r.Capacity.MemoryBytes < 0 || r.Capacity.DiskBytes < 0 {
		return errors.New("negative host capacity")
	}
	return nil
}

func validateManagedOCIBinding(binding ManagedOCIBinding, failureDomain string) error {
	if binding.Region != "GRU" && binding.Region != "SFO" && binding.Region != "FRA" {
		return errors.New("managed OCI region is invalid")
	}
	const instancePrefix = "ocid1.instance."
	if !strings.HasPrefix(binding.InstanceID, instancePrefix) || len(binding.InstanceID) <= len(instancePrefix) ||
		len(binding.InstanceID) > 255 || strings.ContainsFunc(binding.InstanceID, unicode.IsSpace) {
		return errors.New("managed OCI instance ID is invalid")
	}
	if err := validateToken(binding.Owner, "managed OCI owner"); err != nil {
		return err
	}
	if binding.FleetGeneration == 0 {
		return errors.New("managed OCI fleet generation must be positive")
	}
	if len(binding.CreateKey) == 0 || len(binding.CreateKey) > 128 || strings.TrimSpace(binding.CreateKey) != binding.CreateKey ||
		strings.ContainsAny(binding.CreateKey, " \t\r\n\f\v") {
		return errors.New("managed OCI create key is invalid")
	}
	if !managedFaultDomainPattern.MatchString(failureDomain) {
		return errors.New("managed OCI fault domain is invalid")
	}
	return nil
}

func validateDesired(d Desired, cell string, r Registration) error {
	if d.Cell != cell || d.Node != r.Node || d.Environment != r.Environment {
		return errors.New("desired identity mismatch")
	}
	if err := validateToken(d.Role, "role"); err != nil {
		return err
	}
	if !slices.Contains(r.Roles, d.Role) {
		return errors.New("role is not registered")
	}
	if d.Generation == 0 {
		return errors.New("desired generation must be positive")
	}
	if d.Withdrawn {
		if d.Digest != "" || len(d.Args) != 0 || len(d.Env) != 0 {
			return errors.New("withdrawn desired contains execution data")
		}
	} else if err := validateDigest(d.Digest); err != nil {
		return err
	}
	if len(d.Args) > 64 || len(d.Env) > 64 {
		return errors.New("too many workload arguments or environment variables")
	}
	for _, arg := range d.Args {
		if len(arg) > 4096 {
			return errors.New("argument too long")
		}
	}
	for key, value := range d.Env {
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(key) || len(value) > 4096 {
			return errors.New("invalid workload environment")
		}
	}
	return nil
}
