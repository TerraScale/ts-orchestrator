package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/brokeradmission"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/natsconnect"
)

const brokerAdmissionEnvironment = "TS_ORCH_BROKER_ADMISSION_FILE"

type productionBrokerAdmissionFile struct {
	Version               int                                 `json:"version"`
	BrokerID              string                              `json:"broker_id"`
	BrokerIDs             []string                            `json:"broker_ids"`
	ReaderGrants          []brokeradmission.ReaderGrant       `json:"readers"`
	Environment           string                              `json:"environment"`
	Cluster               string                              `json:"cluster"`
	SignerPublicKeyFile   string                              `json:"signer_public_key_file"`
	SignerSHA256          string                              `json:"signer_sha256"`
	CheckpointPath        string                              `json:"checkpoint_path"`
	MinimumRevision       uint64                              `json:"minimum_revision"`
	AllowInitialBootstrap bool                                `json:"allow_initial_bootstrap"`
	Regions               map[string]brokeradmission.Accounts `json:"regions"`
	Reader                bootstrapcredentials.Reference      `json:"reader"`
}

// The dedicated reader never receives a global worker identity. Its admitted
// broker permissions permit reading desired state and publishing only its ack.
type productionBrokerSource struct {
	credentials *bootstrapcredentials.Credentials
	connection  natsconnect.Config
	brokerID    string
	verifier    *brokeradmission.Verifier
}

func (s *productionBrokerSource) connect(ctx context.Context) (*nats.Conn, error) {
	return natsconnect.Connect(ctx, s.connection, net.Dialer{Timeout: 2 * time.Second})
}
func (s *productionBrokerSource) Read(ctx context.Context) ([]byte, error) {
	conn, err := s.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return brokeradmission.ReadDesired(ctx, conn, s.verifier)
}
func (s *productionBrokerSource) Ack(ctx context.Context, wire []byte) error {
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return brokeradmission.PublishAck(ctx, conn, s.brokerID, wire, s.verifier)
}
func (s *productionBrokerSource) check(ctx context.Context, d brokeradmission.Desired) error {
	conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return brokeradmission.CheckAuthority(ctx, conn, d)
}
func (s *productionBrokerSource) Close() error { return s.credentials.Close() }

func configureEnrollmentBroker(config *bootstrap.NatsServerConfig, lookup envLookup) error {
	path, present := lookup(brokerAdmissionEnvironment)
	if !present {
		return nil
	}
	if config == nil || path == "" {
		return errors.New("broker admission: selected broker and explicit configuration required")
	}
	raw, err := bootstrapcredentials.ReadFile(path, false, 64<<10)
	if err != nil {
		return err
	}
	var file productionBrokerAdmissionFile
	if json.Unmarshal(raw, &file, json.RejectUnknownMembers(true)) != nil || file.Version != 1 || !filepath.IsAbs(file.CheckpointPath) || filepath.Clean(file.CheckpointPath) != file.CheckpointPath || len(file.Regions) == 0 {
		return brokeradmission.ErrInvalid
	}
	if _, _, err := brokeradmission.ReaderPermissions(file.BrokerID); err != nil {
		return err
	}
	policy := brokeradmission.Policy{Environment: file.Environment, Cluster: file.Cluster, Regions: file.Regions, RegionalPermissions: func(region, nodeID string) ([]string, []string, error) {
		return initialcontrol.Permissions(region, nodeID, false, false)
	}}
	if err := brokeradmission.ValidateReaderGrants(file.ReaderGrants, file.BrokerIDs, policy); err != nil {
		return err
	}
	public, err := bootstrapcredentials.ReadFile(file.SignerPublicKeyFile, false, 32<<10)
	if err != nil {
		return err
	}
	verifier, err := brokeradmission.NewVerifier(public, file.SignerSHA256)
	if err != nil {
		return err
	}
	credentials, err := bootstrapcredentials.Load(file.Reader)
	if err != nil {
		return err
	}
	matched := false
	for _, grant := range file.ReaderGrants {
		if grant.BrokerID == file.BrokerID && grant.PublicNKey == credentials.PublicIdentity().PublicNKey {
			matched = true
		}
	}
	if !matched {
		credentials.Close()
		return brokeradmission.ErrInvalid
	}
	options := nats.GetDefaultOptions()
	for _, apply := range credentials.Options {
		if err = apply(&options); err != nil {
			credentials.Close()
			return err
		}
	}
	source := &productionBrokerSource{credentials: credentials, brokerID: file.BrokerID, verifier: verifier, connection: natsconnect.Config{URL: credentials.URL, TLS: options.TLSConfig, PublicNKey: options.Nkey, Sign: options.SignatureCB, Timeout: 2 * time.Second}}
	config.Enrollment = &bootstrap.EnrollmentBrokerConfig{Verifier: verifier, Policy: policy, ReaderGrants: file.ReaderGrants, BrokerIDs: file.BrokerIDs, CheckpointPath: file.CheckpointPath, MinimumRevision: file.MinimumRevision, AllowInitialBootstrap: file.AllowInitialBootstrap, Source: source, CheckAuthority: source.check}
	return nil
}

type brokerEnrollmentRuntime struct {
	embeddedNatsRuntime
	cancel context.CancelFunc
	done   chan struct{}
}

func closeBrokerEnrollmentSource(config *bootstrap.EnrollmentBrokerConfig) {
	if config != nil {
		if closer, ok := config.Source.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}

func (r *brokerEnrollmentRuntime) Close() error {
	r.cancel()
	<-r.done
	return r.embeddedNatsRuntime.Close()
}

func reconcileBrokerEnrollment(ctx context.Context, runtime *bootstrap.NatsServer, config *bootstrap.EnrollmentBrokerConfig) embeddedNatsRuntime {
	if config == nil || config.Source == nil {
		return runtime
	}
	workerCtx, cancel := context.WithCancel(ctx)
	r := &brokerEnrollmentRuntime{embeddedNatsRuntime: runtime, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		if closer, ok := config.Source.(interface{ Close() error }); ok {
			defer closer.Close()
		}
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			bounded, stop := context.WithTimeout(workerCtx, 5*time.Second)
			wire, err := config.Source.Read(bounded)
			if err == nil {
				err = runtime.ApplyEnrollmentGrants(bounded, wire)
			}
			if err == nil {
				_ = config.Source.Ack(bounded, wire)
			}
			stop()
			// Failed reads never replace accepted state or acknowledge unapplied
			// grants. The next bounded pass retries after control recovers.
			select {
			case <-workerCtx.Done():
				return
			case <-runtime.Completion():
				return
			case <-ticker.C:
			}
		}
	}()
	return r
}
