//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net/url"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

type qualificationInitialSourceObservation struct {
	HostID        string
	Instance      string
	Lease         authority.RegionalAuthorityLeaseDocument
	Membership    directory.RegionalRuntimeMember
	LeaseRevision uint64
}

// observeInitialCandidateSource reads the admitted GRU broker itself. Fixture
// transport readiness and declarations cannot supply these observations.
func (services *qualificationRuntimeServices) observeInitialCandidateSource(ctx context.Context, sourceHost string) (qualificationInitialSourceObservation, error) {
	bad := bootstrap.ErrControlRuntimeUnavailable
	if ctx == nil {
		return qualificationInitialSourceObservation{}, bad
	}
	services.mu.Lock()
	seed, exists := services.controlSeeds[sourceHost]
	if services.closed || !exists || !seed.Selected || !services.controlReady[sourceHost] {
		services.mu.Unlock()
		return qualificationInitialSourceObservation{}, bad
	}
	seed = seed.Clone()
	services.mu.Unlock()
	defer seed.Clear()
	if err := seed.Validate(); err != nil {
		return qualificationInitialSourceObservation{}, err
	}
	config, err := initialgrant.ParseConfig([]byte(seed.Settings))
	if err != nil {
		return qualificationInitialSourceObservation{}, err
	}
	connectionConfig := config.Regional.Runtime
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(seed.Files[connectionConfig.TLS.CAFile]) {
		return qualificationInitialSourceObservation{}, bad
	}
	certificate, err := tls.X509KeyPair(seed.Files[connectionConfig.TLS.CertificateFile], seed.Files[connectionConfig.TLS.KeyFile])
	if err != nil {
		return qualificationInitialSourceObservation{}, bad
	}
	pair, err := nkeys.FromSeed(seed.Files[connectionConfig.NKeySeedFile])
	if err != nil {
		return qualificationInitialSourceObservation{}, bad
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != connectionConfig.PublicNKey {
		return qualificationInitialSourceObservation{}, bad
	}
	endpoint, err := url.Parse(config.Broker.Endpoint)
	if err != nil || endpoint.Scheme != "tls" {
		return qualificationInitialSourceObservation{}, bad
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	connection, err := nats.Connect(config.Broker.Endpoint, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: endpoint.Hostname()}), nats.Nkey(public, pair.Sign), nats.NoReconnect(), nats.Timeout(2*time.Second))
	if err != nil {
		return qualificationInitialSourceObservation{}, err
	}
	defer connection.Close()
	if connection.ConnectedServerName() != config.Broker.ServerName {
		return qualificationInitialSourceObservation{}, bad
	}
	lease, revision, err := nodeauthority.ReadRegionalCommandLease(bounded, connection, "ORCH_LEADERS")
	if err != nil {
		return qualificationInitialSourceObservation{}, err
	}
	raw, _, err := nodeauthority.ReadLeaderKV(bounded, connection, "ORCH_RUNTIME", "controller."+config.Instance)
	if err != nil {
		return qualificationInitialSourceObservation{}, err
	}
	var record directory.RegionalRuntimeMember
	now := time.Now().UTC()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &record, json.RejectUnknownMembers(true)) != nil || !record.IsValidFor(config.Cell, now) || !record.VerifySignedIdentity() || record.Instance != config.Instance || record.IdentityPublicKey != config.Membership.PublicKey || record.AuthorityEpoch != lease.Epoch || record.AuthorityRevision <= 0 || uint64(record.AuthorityRevision) > revision || record.IsAuthorityLeader != (lease.CandidateId == config.Cell+"-controller-"+config.Instance) || record.ObservedAt.After(now.Add(time.Second)) || now.Sub(record.ObservedAt) > 30*time.Second || !now.Before(record.LeaseExpiresAt) {
		return qualificationInitialSourceObservation{}, bad
	}
	after, afterRevision, err := nodeauthority.ReadRegionalCommandLease(bounded, connection, "ORCH_LEADERS")
	if err != nil || after.AuthorityId != "gru-regional" || after.Epoch != lease.Epoch || after.LeaseId != lease.LeaseId || after.CandidateId != lease.CandidateId || now.Before(after.IssuedAt) || !time.Now().Before(after.IssuedAt.Add(time.Duration(after.DurationMilliseconds)*time.Millisecond)) {
		return qualificationInitialSourceObservation{}, errors.Join(bad, err)
	}
	return qualificationInitialSourceObservation{HostID: sourceHost, Instance: config.Instance, Lease: after, Membership: record, LeaseRevision: afterRevision}, nil
}
