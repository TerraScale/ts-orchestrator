package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/natsconnect"
)

const databaseHostFileEnvironment = "TS_ORCH_DATABASE_HOST_FILE"

type productionDatabaseHostFile = databaseadmission.HostFileConfig

type productionDatabaseHostServices struct {
	lifecycleConnection   *nats.Conn
	lifecycleKey          nkeys.KeyPair
	connection            *nats.Conn
	key                   nkeys.KeyPair
	host, ingress, branch *databaseadmission.Service
	done                  chan struct{}
	cancel                context.CancelFunc
	once                  sync.Once
	err                   error
}

func (s *productionDatabaseHostServices) Completion() <-chan struct{} { return s.done }
func (s *productionDatabaseHostServices) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		s.cancel()
		s.err = errors.Join(s.host.Close(), s.ingress.Close(), s.branch.Close())
		if s.lifecycleConnection != nil {
			s.lifecycleConnection.Close()
		}
		if s.lifecycleKey != nil {
			s.lifecycleKey.Wipe()
		}
		s.connection.Close()
		s.key.Wipe()
	})
	return s.err
}
func startProductionDatabaseHost(ctx context.Context, options *control.OrchestratorOptions, lookup envLookup) (*productionDatabaseHostServices, error) {
	if ctx == nil || options == nil || lookup == nil {
		return nil, errors.New("database host: configuration required")
	}
	path, _ := lookup(databaseHostFileEnvironment)
	data, err := bootstrapcredentials.ReadFile(path, false, 32<<10)
	if err != nil {
		return nil, err
	}
	var config productionDatabaseHostFile
	if json.Unmarshal(data, &config, json.RejectUnknownMembers(true)) != nil || config.Version != 1 || config.Cell != options.Cell || config.Instance != options.Instance || config.Environment == "" || config.MemberID == "" {
		return nil, errors.New("database host: exact deployment identity required")
	}
	catalog, _ := lookup(keyLeaseCatalogEnvironment)
	environment, _ := lookup(keyLeaseEnvironment)
	if config.CatalogPath != catalog || config.Environment != environment {
		return nil, errors.New("database host: key lease catalog and environment differ from host admission")
	}
	u, err := url.Parse(config.NATSURL)
	if err != nil || u.Scheme != "tls" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("database host: dedicated NATS TLS endpoint required")
	}
	for _, path := range []string{config.CatalogPath, config.EngineSocket, config.IngressSocket, config.NKeyFile, config.LifecycleNKeyFile, config.TLS.CertificateFile, config.TLS.PrivateKeyFile, config.TLS.TrustBundleFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("database host: absolute file references required")
		}
	}
	if _, err := databaseadmission.HostSubject(config.ServerIdentity); err != nil {
		return nil, err
	}
	tlsConfig, err := config.TLS.LoadTLS()
	if err != nil {
		return nil, err
	}
	seed, err := bootstrapcredentials.ReadFile(config.NKeyFile, true, 1024)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	pair, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		pair.Wipe()
		return nil, errors.New("database host: dedicated user NKey required")
	}
	local, cancel := context.WithCancel(ctx)
	connection, err := natsconnect.Connect(local, natsconnect.Config{URL: config.NATSURL, TLS: tlsConfig, PublicNKey: public, Sign: pair.Sign, Timeout: 5 * time.Second}, net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		cancel()
		pair.Wipe()
		return nil, err
	}
	service := &productionDatabaseHostServices{connection: connection, key: pair, cancel: cancel, done: make(chan struct{})}
	completed := false
	defer func() {
		if !completed {
			_ = service.Close()
		}
	}()
	lifecycleSeed, err := bootstrapcredentials.ReadFile(config.LifecycleNKeyFile, true, 1024)
	if err != nil {
		return nil, err
	}
	defer clear(lifecycleSeed)
	service.lifecycleKey, err = nkeys.FromSeed(lifecycleSeed)
	if err != nil {
		return nil, err
	}
	lifecyclePublic, err := service.lifecycleKey.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(lifecyclePublic) || lifecyclePublic == public {
		return nil, errors.New("database host: distinct lifecycle publisher NKey required")
	}
	service.lifecycleConnection, err = natsconnect.Connect(local, natsconnect.Config{URL: config.NATSURL, TLS: tlsConfig, PublicNKey: lifecyclePublic, Sign: service.lifecycleKey.Sign, Timeout: 5 * time.Second}, net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	service.host, err = databaseadmission.StartHost(local, databaseadmission.HostConfig{Connection: connection, ServerIdentity: config.ServerIdentity, CatalogPath: config.CatalogPath, EngineSocket: config.EngineSocket, EngineUID: config.EngineUID, Environment: config.Environment, Region: strings.ToUpper(config.Cell), MemberID: config.MemberID})
	if err != nil {
		return nil, err
	}
	service.branch, err = databaseadmission.StartBranchRestoreHost(local, databaseadmission.HostConfig{Connection: connection, ServerIdentity: config.ServerIdentity, CatalogPath: config.CatalogPath, EngineSocket: config.EngineSocket, EngineUID: config.EngineUID, Environment: config.Environment, Region: strings.ToUpper(config.Cell), MemberID: config.MemberID})
	if err != nil {
		return nil, err
	}
	service.ingress, err = databaseadmission.StartIngress(local, databaseadmission.IngressConfig{Connection: connection, SocketPath: config.IngressSocket, AllowedUID: config.IngressUID, Lifecycle: &databaseadmission.LifecycleIngressConfig{PublisherConnection: service.lifecycleConnection, PublisherUID: config.IngressUID}})
	if err != nil {
		return nil, err
	}
	lifecycleTransport := service.lifecycleConnection.StatusChanged(nats.CLOSED, nats.DISCONNECTED, nats.RECONNECTING)
	transport := connection.StatusChanged(nats.CLOSED, nats.DISCONNECTED, nats.RECONNECTING)
	go func() {
		defer close(service.done)
		select {
		case <-local.Done():
		case <-service.host.Completion():
		case <-service.branch.Completion():
		case <-service.ingress.Completion():
		case <-lifecycleTransport:
		case <-transport:
		}
		cancel()
	}()
	completed = true
	return service, nil
}
