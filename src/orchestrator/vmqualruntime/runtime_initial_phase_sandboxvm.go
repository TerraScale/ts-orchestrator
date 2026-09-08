//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/url"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/qualificationstate"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// QualificationInitialControl observes the original finite bootstrap while
// only GRU is running. It needs no ordinary SFO/FRA leases or runtime binding.
func (factory *firecrackerFactory) QualificationInitialControl(ctx context.Context) (vmqual.InitialControlObservation, error) {
	var result vmqual.InitialControlObservation
	bad := bootstrap.ErrControlRuntimeUnavailable
	services, ok := factory.services.(*qualificationRuntimeServices)
	if ctx == nil || !ok || services == nil {
		return result, bad
	}
	services.mu.Lock()
	var source string
	var hosts []string
	for host, seed := range services.controlSeeds {
		if !services.controlReady[host] {
			services.mu.Unlock()
			return result, bad
		}
		hosts = append(hosts, host)
		if seed.Selected {
			source = host
		}
	}
	issuer := services.bootstrapIssuer
	services.mu.Unlock()
	if source == "" || len(hosts) != 2 || issuer == nil {
		return result, bad
	}
	result.GrantSHA256, result.ManifestSHA256 = make(map[string]string), make(map[string]string)
	for _, host := range hosts {
		material, err := issuer.AdmittedGrant(host)
		if err != nil {
			return result, err
		}
		grant, err := hostagent.VerifyBootstrapGrant(host, material.PublicKeyPEM, material.SignedGrant)
		if err != nil {
			return result, err
		}
		canonical, err := hostmanifest.CanonicalHostManifestJSON(grant.Manifest)
		if err != nil {
			return result, err
		}
		manifestDigest, grantDigest := sha256.Sum256(canonical), sha256.Sum256(material.SignedGrant)
		result.GrantSHA256[host], result.ManifestSHA256[host] = hex.EncodeToString(grantDigest[:]), hex.EncodeToString(manifestDigest[:])
		report, err := factory.nodeStatus(ctx, host, "initial-stage-observed")
		if err != nil {
			return result, err
		}
		if report.State != hostagent.NodeStateServing || report.Quiesced || !report.Facts.ClockMeasured || report.Facts.ClockUnhealthy || report.Facts.ManifestSha256 != result.ManifestSHA256[host] || len(report.Facts.Components) != len(grant.Manifest.Components) {
			return result, bad
		}
		seen := make(map[string]bool)
		for _, fact := range report.Facts.Components {
			if seen[fact.Name] || !fact.Installed || !fact.UnitActive || fact.Version != fact.Desired {
				return result, bad
			}
			seen[fact.Name] = true
			matched := false
			for _, spec := range grant.Manifest.Components {
				matched = matched || spec.Name == fact.Name && spec.Version == fact.Version
			}
			if !matched {
				return result, bad
			}
		}
	}
	before, err := services.observeInitialCandidateSource(ctx, source)
	if err != nil {
		return result, err
	}
	global, globalRevision, err := services.observeInitialGlobalLease(ctx, source)
	if err != nil {
		return result, err
	}
	after, err := services.observeInitialCandidateSource(ctx, source)
	if err != nil {
		return result, err
	}
	if before.Lease.LeaseId != after.Lease.LeaseId || before.Lease.Epoch != after.Lease.Epoch || before.Lease.CandidateId != after.Lease.CandidateId {
		return result, bad
	}
	latestGlobal, latestRevision, err := services.observeInitialGlobalLease(ctx, source)
	if err != nil {
		return result, err
	}
	if latestGlobal.LeaseId != global.LeaseId || latestGlobal.Epoch != global.Epoch || latestGlobal.CandidateId != global.CandidateId || latestRevision < globalRevision {
		return result, bad
	}
	result.SourceHost, result.RegionalLease, result.RegionalRevision, result.Membership = source, after.Lease, after.LeaseRevision, after.Membership
	result.GlobalLease, result.GlobalRevision, result.ObservedAt = latestGlobal, latestRevision, time.Now().UTC()
	directory := filepath.Join(services.stateRoot, "qualification-admission-"+services.plan.RunID)
	result.JournalPath = filepath.Join(directory, "initial-observed.json")
	store, err := qualificationstate.Open(directory)
	if err != nil {
		return result, err
	}
	defer store.Close()
	_, err = store.LoadOrCreate("initial-observed.json", 64<<10, func() ([]byte, error) { return json.Marshal(result, json.Deterministic(true)) }, func(raw []byte) error {
		var saved vmqual.InitialControlObservation
		if json.Unmarshal(raw, &saved, json.RejectUnknownMembers(true)) != nil || saved.SourceHost != source || saved.JournalPath != result.JournalPath || len(saved.GrantSHA256) != 2 || len(saved.ManifestSHA256) != 2 {
			return bad
		}
		for host, digest := range result.GrantSHA256 {
			if saved.GrantSHA256[host] != digest || saved.ManifestSHA256[host] != result.ManifestSHA256[host] {
				return bad
			}
		}
		return nil
	})
	return result, err
}

func (services *qualificationRuntimeServices) observeInitialGlobalLease(ctx context.Context, host string) (authority.RegionalAuthorityLeaseDocument, uint64, error) {
	var result authority.RegionalAuthorityLeaseDocument
	bad := bootstrap.ErrControlRuntimeUnavailable
	services.mu.Lock()
	seed := services.controlSeeds[host].Clone()
	services.mu.Unlock()
	defer seed.Clear()
	config, err := initialgrant.ParseConfig([]byte(seed.Settings))
	if err != nil || config.Global == nil {
		return result, 0, errors.Join(bad, err)
	}
	credentials := config.Global.Runtime
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(seed.Files[credentials.TLS.CAFile]) {
		return result, 0, bad
	}
	certificate, err := tls.X509KeyPair(seed.Files[credentials.TLS.CertificateFile], seed.Files[credentials.TLS.KeyFile])
	if err != nil {
		return result, 0, err
	}
	pair, err := nkeys.FromSeed(seed.Files[credentials.NKeySeedFile])
	if err != nil {
		return result, 0, err
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != credentials.PublicNKey {
		return result, 0, bad
	}
	endpoint, err := url.Parse(config.Broker.Endpoint)
	if err != nil || endpoint.Scheme != "tls" {
		return result, 0, bad
	}
	connection, err := nats.Connect(config.Broker.Endpoint, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: endpoint.Hostname()}), nats.Nkey(public, pair.Sign), nats.NoReconnect(), nats.Timeout(2*time.Second))
	if err != nil {
		return result, 0, err
	}
	defer connection.Close()
	if connection.ConnectedServerName() != config.Broker.ServerName {
		return result, 0, bad
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	raw, revision, err := nodeauthority.ReadLeaderKV(bounded, connection, "ORCH_LEADERS", "authority.global")
	if err != nil {
		return result, 0, err
	}
	now := time.Now().UTC()
	if len(raw) > 16<<10 || json.Unmarshal(raw, &result, json.RejectUnknownMembers(true)) != nil || result.Validate() != nil || result.AuthorityId != "global" || result.CandidateId != "global-controller-"+config.Cell+"-"+config.Instance || now.Before(result.IssuedAt) || !now.Before(result.IssuedAt.Add(time.Duration(result.DurationMilliseconds)*time.Millisecond)) {
		return result, 0, bad
	}
	return result, revision, nil
}
