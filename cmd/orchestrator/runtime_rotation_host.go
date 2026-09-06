package main

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/natsconnect"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

const rotationHostFileEnvironment = "TS_ORCH_ROTATION_HOST_FILE"

type rotationHostFile struct {
	Version              int                         `json:"version"`
	Cell                 string                      `json:"cell"`
	NodeID               string                      `json:"node_id"`
	Listen               string                      `json:"listen"`
	SocketPath           string                      `json:"socket_path"`
	TokenFile            string                      `json:"token_file"`
	StateDir             string                      `json:"state_dir"`
	ControlTLS           placementpublisher.TLSFiles `json:"control_tls"`
	NATSURL              string                      `json:"nats_url"`
	NKeyFile             string                      `json:"nkey_file"`
	NATSIdentity         placementpublisher.TLSFiles `json:"nats_identity"`
	ControllerCandidates map[string]string           `json:"controller_candidates"`
}

type productionRotationHost struct {
	server     *http.Server
	connection *nats.Conn
	completion chan struct{}
	once       sync.Once
}

func (h *productionRotationHost) Completion() <-chan struct{} { return h.completion }
func (h *productionRotationHost) Close() error {
	if h == nil {
		return nil
	}
	var err error
	h.once.Do(func() { err = h.server.Close(); h.connection.Close() })
	return err
}

func startProductionRotationHost(ctx context.Context, options *control.OrchestratorOptions, lookup envLookup) (*productionRotationHost, error) {
	path, ok := lookup(rotationHostFileEnvironment)
	if !ok || path == "" {
		return nil, errors.New("rotation host: TS_ORCH_ROTATION_HOST_FILE is required")
	}
	data, err := bootstrapcredentials.ReadFile(path, false, 32<<10)
	if err != nil {
		return nil, err
	}
	var config rotationHostFile
	if json.Unmarshal(data, &config, json.RejectUnknownMembers(true)) != nil || config.Version != 1 || config.Cell != options.Cell || config.NodeID != options.Instance || len(config.ControllerCandidates) == 0 {
		return nil, errors.New("rotation host: exact-host configuration required")
	}
	host, port, err := net.SplitHostPort(config.Listen)
	if err != nil || net.ParseIP(host) == nil || port == "0" || port == "" {
		return nil, errors.New("rotation host: explicit listen IP and port required")
	}
	for _, path := range []string{config.SocketPath, config.TokenFile, config.StateDir, config.NKeyFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("rotation host: absolute paths required")
		}
	}
	certificate, err := bootstrapcredentials.ReadFile(config.ControlTLS.CertificateFile, false, 128<<10)
	if err != nil {
		return nil, err
	}
	defer clear(certificate)
	private, err := bootstrapcredentials.ReadFile(config.ControlTLS.PrivateKeyFile, true, 128<<10)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	trust, err := bootstrapcredentials.ReadFile(config.ControlTLS.TrustBundleFile, false, 128<<10)
	if err != nil {
		return nil, err
	}
	defer clear(trust)
	combined := append(certificate, private...)
	defer clear(combined)
	dynamic, err := keyrotation.NewDynamicTLS(combined, trust)
	if err != nil {
		return nil, err
	}
	natsTLS, err := config.NATSIdentity.LoadTLS()
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
		return nil, errors.New("rotation host: invalid NKey")
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || !nkeys.IsValidPublicUserKey(public) {
		return nil, errors.New("rotation host: user NKey required")
	}
	connection, err := natsconnect.Connect(ctx, natsconnect.Config{URL: config.NATSURL, TLS: natsTLS, PublicNKey: public, Sign: pair.Sign, Timeout: 5 * time.Second}, net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			connection.Close()
		}
	}()
	check, err := keyrotation.NewMemberPeerAuthority(connection, config.ControllerCandidates)
	if err != nil {
		return nil, err
	}
	pins := make([]string, 0, len(config.ControllerCandidates))
	for pin := range config.ControllerCandidates {
		pins = append(pins, pin)
	}
	handler, err := keyrotation.NewMemberReceiver(keyrotation.MemberReceiverConfig{NodeID: config.NodeID, SocketPath: config.SocketPath, TokenFile: config.TokenFile, StateDir: config.StateDir, ControllerSPKI: pins, CheckPeerAuthority: check, ControlTLS: dynamic})
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return nil, errors.New("rotation host: listener unavailable")
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	result := &productionRotationHost{server: server, connection: connection, completion: make(chan struct{})}
	go func() {
		defer close(result.completion)
		_ = server.Serve(tls.NewListener(listener, dynamic.TLSConfig()))
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = result.Close()
		case <-result.completion:
		}
	}()
	complete = true
	return result, nil
}
