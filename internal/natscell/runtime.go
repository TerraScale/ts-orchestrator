// Package natscell owns the regional embedded NATS server and its client connection.
// Feature slices receive the client interfaces and do not depend on this package.
package natscell

import (
	"errors"
	"sync"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ErrUnavailable matches a Start failure to reach the regional brokers or
// their JetStream API, which a retry can resolve. Configuration, credential
// and TLS material errors never match it: retrying cannot fix them.
var ErrUnavailable = errors.New("regional NATS is unavailable")

// DefaultStoreMaxBytes bounds the embedded JetStream file store when the
// operator does not specify a per-node limit.
const DefaultStoreMaxBytes int64 = 8 << 30

// TLSFiles are the certificate material for both NATS listeners and clients.
type TLSFiles struct {
	CAFile   string `json:"ca_file"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// Embedded configures the in-process regional NATS and JetStream server.
// Routes are stable seed addresses; NATS route discovery connects the remaining
// members once any seed is reachable. A persisted StoreDir is required.
type Embedded struct {
	Host                  string      `json:"host"`
	Port                  int         `json:"port"`
	RouteHost             string      `json:"route_host"`
	RoutePort             int         `json:"route_port"`
	Routes                []string    `json:"routes"`
	StoreDir              string      `json:"store_dir"`
	StoreMaxBytes         int64       `json:"store_max_bytes,omitzero"`
	TLS                   TLSFiles    `json:"tls"`
	RouteTLS              TLSFiles    `json:"route_tls"`
	Users                 []NKeyGrant `json:"users"`
	RouteUser             string      `json:"route_user"`
	RoutePasswordFile     string      `json:"route_password_file"`
	OperatorJWTFile       string      `json:"operator_jwt_file,omitempty"`
	SystemJWTFile         string      `json:"system_jwt_file,omitempty"`
	CellJWTFile           string      `json:"cell_jwt_file,omitempty"`
	SystemCredentialsFile string      `json:"system_credentials_file,omitempty"`
	// MembershipCredentialsFile is an optional system-account user limited to
	// metadata peer remove and leader step-down; see OpenMembershipAdmin.
	MembershipCredentialsFile string   `json:"membership_credentials_file,omitempty"`
	TicketPublicKeyFile       string   `json:"ticket_public_key_file,omitempty"`
	BrokerIDs                 []string `json:"broker_ids,omitempty"`
	// InterRegion describes this region's reviewed leaf topology and credentials.
	// An absent block describes an isolated cell.
	InterRegion *InterRegion `json:"interregion,omitempty"`
	// Link joins this region to the global home with one link signer. It
	// replaces InterRegion; a configuration sets one or the other.
	Link *Link `json:"link,omitempty"`
}

// NKeyGrant binds a NATS user key to one regional role. A host grant is tied
// to the hash of its admitted node identity and a private reply inbox prefix.
type NKeyGrant struct {
	PublicKey string `json:"public_key"`
	Role      string `json:"role"`
	Node      string `json:"node,omitempty"`
	// Global adds GlobalControllerPublishes to a controller in the global
	// home region. It is refused for every other role.
	Global bool `json:"global,omitempty"`
}

// Config describes a single regional cell. Every connection requires verified
// TLS and a JWT credential scoped to its regional account.
type Config struct {
	Cell            string    `json:"cell"`
	Instance        string    `json:"instance"`
	Replicas        int       `json:"replicas"`
	ClientRole      string    `json:"client_role,omitempty"`
	URL             string    `json:"url"`
	NKeySeedFile    string    `json:"nkey_seed_file"`
	CredentialsFile string    `json:"credentials_file"`
	TLS             TLSFiles  `json:"tls"`
	Embedded        *Embedded `json:"embedded"`
	// OperatorForward is a transient CLI-only TCP route. Its keys remain the
	// configured controller TLS identities; values are local Bastion forwards.
	OperatorForward map[string]string `json:"-"`
	// ReloadClientMaterial, when set, is consulted on every connect and
	// reconnect so renewed credentials take effect without a process restart.
	// It must keep the startup NATS user key; failures use the startup files.
	ReloadClientMaterial func() (ClientMaterial, error) `json:"-"`
}

// Runtime keeps the broker and client alive together. Closing it drains the
// client before stopping the server so JetStream acknowledgements can finish.
type Runtime struct {
	server          *server.Server
	conn            *nats.Conn
	js              jetstream.JetStream
	cell            string
	diagMu          sync.Mutex
	diagAt          time.Time
	diagState       string
	endpoint        string
	resolver        *accountResolver
	operator        *jwt.OperatorClaims
	systemConn      *nats.Conn
	bridge          *Bridge
	brokerTLS       *ReloadingTLS
	claimMu         sync.Mutex
	appliedSequence uint64
	serverName      string
	brokerNames     []string
	once            sync.Once
}
