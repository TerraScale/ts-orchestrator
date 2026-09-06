package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

type databaseInventoryFileConfig struct {
	Address         string `json:"address"`
	CertificateFile string `json:"certificateFile"`
	KeyFile         string `json:"keyFile"`
	ServiceKeyFile  string `json:"serviceKeyFile"`
}

func (c databaseInventoryFileConfig) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	number, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || portErr != nil || number == 0 {
		return errors.New("runtime database inventory: explicit HTTPS listen address required")
	}
	for _, p := range []string{c.CertificateFile, c.KeyFile, c.ServiceKeyFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("runtime database inventory: absolute credential paths required")
		}
	}
	return nil
}

type productionDatabaseInventory struct {
	server *http.Server
	done   chan struct{}
}

func (s *productionDatabaseInventory) Close() error                { return s.server.Close() }
func (s *productionDatabaseInventory) Completion() <-chan struct{} { return s.done }
func startProductionDatabaseInventory(ctx context.Context, c databaseInventoryFileConfig, environment string, journal *databaseadmission.NATSJournal) (*productionDatabaseInventory, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	key, err := bootstrapcredentials.ReadFile(c.ServiceKeyFile, true, 4096)
	if err != nil {
		return nil, errors.New("runtime database inventory: service credential unavailable")
	}
	defer clear(key)
	credential := strings.TrimSpace(string(key))
	if len(credential) < 32 || len(credential) > 4096 {
		return nil, errors.New("runtime database inventory: invalid service credential")
	}
	certificateData, err := bootstrapcredentials.ReadFile(c.CertificateFile, false, 64<<10)
	if err != nil {
		return nil, errors.New("runtime database inventory: TLS certificate unavailable")
	}
	privateData, err := bootstrapcredentials.ReadFile(c.KeyFile, true, 64<<10)
	if err != nil {
		return nil, errors.New("runtime database inventory: TLS identity unavailable")
	}
	defer clear(privateData)
	certificate, err := tls.X509KeyPair(certificateData, privateData)
	if err != nil {
		return nil, errors.New("runtime database inventory: TLS certificate unavailable")
	}
	handler, err := databaseadmission.NewInventoryHandler(journal, environment, credential)
	if err != nil {
		return nil, err
	}
	freeze, err := databaseadmission.NewFreezeInventoryHandler(journal, environment, credential)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(databaseadmission.InventoryPath, handler)
	mux.Handle(databaseadmission.InventoryFreezePath, freeze)
	server := databaseadmission.NewInventoryHTTPSServer(c.Address, mux)
	server.TLSConfig.Certificates = []tls.Certificate{certificate}
	listener, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, err
	}
	service := &productionDatabaseInventory{server: server, done: make(chan struct{})}
	stop := context.AfterFunc(ctx, func() { _ = service.Close() })
	go func() { defer close(service.done); defer stop(); _ = server.ServeTLS(listener, "", "") }()
	return service, nil
}
