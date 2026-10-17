package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// A scenario shares its issuer and CA across brokers and external clients.
type authenticatedNATS struct {
	root, cell, cellID, cellJWT                           string
	account                                               nkeys.KeyPair
	tls                                                   natscell.TLSFiles
	operatorFile, systemFile, cellFile, systemCredentials string
	ticketPublicFile, ticketPrivateFile, routePassword    string
	brokers                                               []string
}

// controller keeps process admission outside broker boundary scenarios, using
// the same test seams as the production broker-claim CLI scenario.
func (a *authenticatedNATS) controller(t *testing.T, cfg *Config) {
	t.Helper()
	cfg.NATS = a.config(t, cfg.NATS)
	cfg.Controller.BrokerTicketKeyFile = a.ticketPrivateFile
	newAcceptedSpecTrust(t, cfg)
	previousRuntime, previousMarker := controllerRuntimeProduction, controllerMarkerPresent
	previousBaked, previousBootstrap := controllerBakedInputsPresent, controllerBootstrapProduction
	previousFounder, previousClock, previousSeed := controllerFounderProduction, controllerBrokerClockProbe, rolloutSeedSlot
	controllerMarkerPresent = func() (bool, error) { return false, nil }
	controllerBakedInputsPresent = func() (bool, error) { return true, nil }
	controllerBootstrapProduction = func(context.Context, Config) error { return nil }
	controllerFounderProduction = func(context.Context) error { return nil }
	controllerRuntimeProduction = func(ctx context.Context, cfg Config, _ func() error) (*natscell.Runtime, error) {
		return natscell.Start(ctx, cfg.NATS)
	}
	clock := &testBrokerClock{}
	clock.healthy.Store(true)
	controllerBrokerClockProbe = func() brokerauth.ClockProbe { return clock }
	rolloutSeedSlot = func(cfg Config) (string, error) { return cfg.NATS.Embedded.BrokerIDs[0], nil }
	t.Cleanup(func() {
		controllerRuntimeProduction, controllerMarkerPresent = previousRuntime, previousMarker
		controllerBakedInputsPresent, controllerBootstrapProduction = previousBaked, previousBootstrap
		controllerFounderProduction, controllerBrokerClockProbe, rolloutSeedSlot = previousFounder, previousClock, previousSeed
	})
}

func newAuthenticatedNATS(t *testing.T, cell string, brokers ...string) *authenticatedNATS {
	t.Helper()
	a := &authenticatedNATS{root: t.TempDir(), cell: cell, brokers: slices.Clone(brokers)}
	a.tls, a.routePassword = testR3TLSMaterial(t, a.root)
	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	system, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	a.account, err = nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	operatorID, _ := operator.PublicKey()
	systemID, _ := system.PublicKey()
	a.cellID, _ = a.account.PublicKey()
	operatorClaim := jwt.NewOperatorClaims(operatorID)
	operatorClaim.SystemAccount = systemID
	operatorJWT, err := operatorClaim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	systemJWT, err := jwt.NewAccountClaims(systemID).Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	cellClaim := jwt.NewAccountClaims(a.cellID)
	cellClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 256 << 20, DiskStorage: 8 << 30, Streams: 100, Consumer: 100}
	a.cellJWT, err = cellClaim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, raw string) string {
		path := filepath.Join(a.root, name)
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	a.operatorFile = write("operator.jwt", operatorJWT)
	a.systemFile = write("system.jwt", systemJWT)
	a.cellFile = write("cell.jwt", a.cellJWT)
	systemUser, systemCredentials := testBrokerJWTUser(t, a.root, "system.creds", system, systemID,
		[]string{"$SYS.REQ.ACCOUNT." + a.cellID + ".CLAIMS.UPDATE"}, nil)
	systemClaim, err := jwt.DecodeUserClaims(testDecoratedJWT(t, systemCredentials))
	if err != nil {
		t.Fatal(err)
	}
	systemClaim.Sub.Allow = jwt.StringList{protocol.InboxPrefix(cell, systemUser) + ".>"}
	a.systemCredentials = testBrokerJWTUserWithClaim(t, a.root, "system.creds", system, systemClaim)
	public, _ := testEd25519(t, a.root, "ticket.key")
	a.ticketPrivateFile = filepath.Join(a.root, "ticket.key")
	a.ticketPublicFile = write("ticket.pub", base64.StdEncoding.EncodeToString(public))
	return a
}

// config retains an existing user identity while replacing seed-only auth.
func (a *authenticatedNATS) config(t *testing.T, cfg natscell.Config) natscell.Config {
	t.Helper()
	if cfg.Cell != "" && cfg.Cell != a.cell {
		t.Fatalf("fixture cell %q differs from client cell %q", a.cell, cfg.Cell)
	}
	cfg.Cell = a.cell
	if cfg.Instance == "" {
		cfg.Instance = "one"
	}
	if cfg.Replicas == 0 {
		cfg.Replicas = 1
	}
	role := cfg.ClientRole
	if role == "" {
		role = "controller"
	}
	var user nkeys.KeyPair
	var err error
	if cfg.NKeySeedFile != "" {
		seed, readErr := os.ReadFile(cfg.NKeySeedFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		user, err = nkeys.FromSeed(seed)
		clear(seed)
	} else if cfg.CredentialsFile != "" {
		credentials, readErr := os.ReadFile(cfg.CredentialsFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		user, err = nkeys.ParseDecoratedUserNKey(credentials)
		clear(credentials)
	} else {
		user, err = nkeys.CreateUser()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := jwt.NewUserClaims(public)
	claim.IssuerAccount = a.cellID
	claim.Sub.Allow = jwt.StringList{protocol.InboxPrefix(a.cell, public) + ".>"}
	switch role {
	case "controller":
		claim.Pub.Allow = natscell.ControllerPublishes(a.cell)
		claim.Pub.Allow.Add(natscell.GlobalControllerPublishes()...)
		claim.Pub.Allow.Add(natscell.GlobalControllerRequests()...)
		claim.Pub.Allow.Add("$JS.ACK.>")
		claim.Sub.Allow.Add(natscell.ControllerSubscriptions(a.cell)...)
		claim.Sub.Allow.Add(natscell.GlobalControllerRequests()...)
		claim.Sub.Allow.Add(protocol.ObservabilityGrant(a.cell), protocol.Broker(a.cell, "ticket", ">"), protocol.Broker(a.cell, "fence", cfg.Instance))
		claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	case "operator":
		claim.Pub.Allow = natscell.BrokerOperatorPublishPermissions(a.cell)
	case "host":
		claim.Pub.Allow = jwt.StringList{protocol.AgentObservation(a.cell, public, "*")}
	default:
		t.Fatalf("unsupported authenticated fixture role %q", role)
	}
	cfg.CredentialsFile = testBrokerJWTUserWithKey(t, a.root, cfg.Instance+"-"+public+".creds", a.account, user, claim)
	cfg.NKeySeedFile = ""
	cfg.TLS = a.tls
	cfg.URL = strings.ReplaceAll(cfg.URL, "nats://", "tls://")
	if cfg.Embedded != nil {
		embedded := *cfg.Embedded
		cfg.Embedded = &embedded
		embedded.Users = nil
		embedded.TLS, embedded.RouteTLS = a.tls, a.tls
		embedded.RouteUser, embedded.RoutePasswordFile = "integration-route", a.routePassword
		embedded.OperatorJWTFile, embedded.SystemJWTFile, embedded.CellJWTFile = a.operatorFile, a.systemFile, a.cellFile
		embedded.SystemCredentialsFile, embedded.TicketPublicKeyFile = a.systemCredentials, a.ticketPublicFile
		embedded.BrokerIDs = slices.Clone(a.brokers)
		if len(embedded.BrokerIDs) == 0 {
			embedded.BrokerIDs = []string{cfg.Instance}
		}
		if embedded.StoreDir == "" {
			embedded.StoreDir = filepath.Join(a.root, cfg.Instance)
		}
		if embedded.Host == "" {
			embedded.Host = "127.0.0.1"
		}
		if embedded.Port <= 0 {
			embedded.Port = reserveControllerPort(t)
		}
	}
	return cfg
}

func (a *authenticatedNATS) start(t *testing.T, ctx context.Context, cfg natscell.Config) (*natscell.Runtime, error) {
	t.Helper()
	runtime, err := natscell.Start(ctx, a.config(t, cfg))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if cfg.Embedded != nil {
		if err := runtime.ApplyCellClaim(ctx, 1, a.cellJWT); err != nil {
			return nil, fmt.Errorf("apply fixture claim: %w", err)
		}
		if err := runtime.Bridge().OpenUntil(1, a.cellJWT, time.Now().Add(5*time.Minute)); err != nil {
			return nil, fmt.Errorf("open fixture bridge: %w", err)
		}
	}
	return runtime, nil
}
