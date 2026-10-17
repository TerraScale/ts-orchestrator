package rootsecret

import (
	"bytes"
	"context"
	"os"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nkeys"
)

// NetBirdJournalClient retains one native manager admission and one exact
// CURRENT. Its journal signer never leaves this private synchronous client.
type NetBirdJournalClient struct {
	mu             sync.Mutex
	original       context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	expires        time.Time
	source         NetBirdJournalSource
	material       NetBirdJournalMaterial
	credential     bootstrapmaterial.NetBirdJournalCredential
	signer         nkeys.KeyPair
	process        *rootoci.ProcessWitness
	processBinding string
	observation    region.NetBirdManagerAdmissionObservation
	bundles        vaultsecret.BundleClient
	currentID      string
	currentVersion int64
	currentSHA256  string
	currentExpiry  time.Time
}

func (*NetBirdJournalClient) String() string          { return "NetBird journal client [redacted]" }
func (client *NetBirdJournalClient) GoString() string { return client.String() }

// OpenNetBirdJournalClient uses the actual manager's principal before overlay
// startup. The operation context never becomes its retained original lifetime.
func OpenNetBirdJournalClient(ctx, original context.Context, local region.VerifiedNetBirdManager, underlay region.VerifiedNetBirdJournalUnderlay, process *rootoci.ProcessWitness) (*NetBirdJournalClient, error) {
	if ctx == nil || original == nil || original.Done() == nil || original.Err() != nil || ctx.Err() != nil || !underlay.IsVerified() ||
		checkNetBirdStartupProcess(process, "") != nil {
		return nil, ErrDelivery
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, present := os.LookupEnv(name); present {
			return nil, ErrDelivery
		}
	}
	expires := minDeadline(local.ExpiresAt(), underlay.ExpiresAt())
	ctx, cancel := netBirdStartupReadContext(ctx, original, expires)
	defer cancel()
	ctx, cancelOperation := context.WithTimeout(ctx, 30*time.Second)
	defer cancelOperation()
	observation, err := local.AdmissionObservation(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, "sa-saopaulo-1")
	if err != nil {
		return nil, ErrDelivery
	}
	source, err := LoadNetBirdJournalManagerSourceForOperation(ctx, original, factory, local, underlay)
	if err != nil {
		return nil, ErrDelivery
	}
	expires = minDeadline(expires, source.ExpiresAt())
	if deadline, ok := original.Deadline(); ok {
		expires = minDeadline(expires, deadline)
	}
	ctx, cancelSource := context.WithDeadline(ctx, expires)
	defer cancelSource()
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, ErrDelivery
	}
	boundary := func(check context.Context) error {
		if check == nil || original.Err() != nil || checkNetBirdStartupProcess(process, process.Binding()) != nil {
			return ErrDelivery
		}
		check, stop := netBirdStartupReadContext(check, original, expires)
		defer stop()
		deadline, err := source.CurrentDeadline(check)
		if err != nil || ociclient.LimitAdmission(check, deadline) != nil || original.Err() != nil {
			return ErrDelivery
		}
		return check.Err()
	}
	current, err := vaultsecret.ReadCurrent(ociclient.WithRequestGuard(ctx, boundary), &bundles, NetBirdBrokerRef(source.Source()))
	if err != nil {
		return nil, ErrDelivery
	}
	if !current.ExpiresAt.IsZero() {
		expires = minDeadline(expires, current.ExpiresAt)
	}
	ctx, cancelCurrent := context.WithDeadline(ctx, expires)
	defer cancelCurrent()
	material, err := DecodeNetBirdJournalMaterial([]byte(current.Value()))
	if err != nil {
		return nil, ErrDelivery
	}
	retained := false
	defer func() {
		if !retained {
			clearNetBirdJournalMaterial(material)
		}
	}()
	source, err = source.ForBrokerMaterial(ctx, material.NetBirdBrokerMaterial)
	if err != nil {
		return nil, ErrDelivery
	}
	_, credential, err := CheckNetBirdJournalMaterial(material, source, time.Now().UTC())
	if err != nil {
		return nil, ErrDelivery
	}
	currentCap, err := source.CurrentDeadline(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	expires = minDeadline(expires, minDeadline(currentCap, minDeadline(source.ExpiresAt(), minDeadline(material.ExpiresAt, credential.ExpiresAt))))
	if original.Err() != nil || ctx.Err() != nil || !time.Now().Before(expires) {
		return nil, ErrDelivery
	}
	lifetime, stop := context.WithDeadline(original, expires)
	client := &NetBirdJournalClient{original: original, ctx: lifetime, cancel: stop, expires: expires, source: source, material: material, credential: credential,
		process: process, processBinding: process.Binding(), observation: observation, bundles: &bundles, currentID: current.ID, currentVersion: current.Version,
		currentSHA256: netBirdDigest([]byte(current.Value())), currentExpiry: current.ExpiresAt}
	client.signer, err = nkeys.ParseDecoratedUserNKey(material.JournalCredentials)
	if err != nil {
		client.Close()
		return nil, ErrDelivery
	}
	if client.Guard(ctx) != nil {
		client.Close()
		return nil, ErrDelivery
	}
	retained = true
	context.AfterFunc(lifetime, func() { client.Close() })
	return client, nil
}

func (client *NetBirdJournalClient) Context() context.Context {
	if client == nil {
		return nil
	}
	return client.ctx
}

func (client *NetBirdJournalClient) ExpiresAt() time.Time {
	if client == nil {
		return time.Time{}
	}
	return client.expires
}

func (client *NetBirdJournalClient) Close() error {
	if client == nil {
		return nil
	}
	if client.cancel != nil {
		client.cancel()
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.signer != nil {
		client.signer.Wipe()
		client.signer = nil
	}
	clearNetBirdJournalMaterial(client.material)
	return nil
}

func (client *NetBirdJournalClient) Guard(ctx context.Context) error {
	_, err := client.CurrentDeadline(ctx)
	return err
}

func (client *NetBirdJournalClient) CurrentDeadline(ctx context.Context) (time.Time, error) {
	if client == nil {
		return time.Time{}, ErrDelivery
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.currentDeadline(ctx)
}

func (client *NetBirdJournalClient) currentDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil || client.original == nil || client.original.Err() != nil || client.ctx == nil || client.ctx.Err() != nil ||
		client.signer == nil || client.bundles == nil || !time.Now().Before(client.expires) || checkNetBirdStartupProcess(client.process, client.processBinding) != nil {
		return time.Time{}, ErrDelivery
	}
	ctx, cancel := netBirdStartupReadContext(ctx, client.ctx, client.expires)
	defer cancel()
	ctx, cancelOperation := context.WithTimeout(ctx, 30*time.Second)
	defer cancelOperation()
	deadline, err := client.source.CurrentDeadline(ctx)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	deadline = minDeadline(client.expires, deadline)
	ctx, cancelSource := context.WithDeadline(ctx, deadline)
	defer cancelSource()
	boundary := func(check context.Context) error {
		if check == nil || client.original.Err() != nil || client.ctx.Err() != nil || checkNetBirdStartupProcess(client.process, client.processBinding) != nil {
			return ErrDelivery
		}
		check, stop := netBirdStartupReadContext(check, client.ctx, deadline)
		defer stop()
		current, err := client.source.CurrentDeadline(check)
		if err != nil || ociclient.LimitAdmission(check, current) != nil || client.original.Err() != nil || client.ctx.Err() != nil {
			return ErrDelivery
		}
		return check.Err()
	}
	current, err := vaultsecret.ReadCurrent(ociclient.WithRequestGuard(ctx, boundary), client.bundles, NetBirdBrokerRef(client.source.Source()))
	if err != nil || current.ID != client.currentID || current.Version != client.currentVersion || !current.ExpiresAt.Equal(client.currentExpiry) ||
		netBirdDigest([]byte(current.Value())) != client.currentSHA256 {
		return time.Time{}, ErrDelivery
	}
	_, credential, err := CheckNetBirdJournalMaterial(client.material, client.source, time.Now().UTC())
	if err != nil || credential.ID != client.credential.ID || credential.Subject != client.credential.Subject || credential.SHA256 != client.credential.SHA256 ||
		!credential.IssuedAt.Equal(client.credential.IssuedAt) || !credential.ExpiresAt.Equal(client.credential.ExpiresAt) {
		return time.Time{}, ErrDelivery
	}
	currentCap, err := client.source.CurrentDeadline(ctx)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	deadline = minDeadline(deadline, currentCap)
	if client.original.Err() != nil || client.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(deadline) || checkNetBirdStartupProcess(client.process, client.processBinding) != nil {
		return time.Time{}, ErrDelivery
	}
	return deadline, nil
}

// These inputs never contain the journal signer or its credential bytes.
type netBirdJournalReaderInputs struct {
	material       NetBirdBrokerMaterial
	source         NetBirdBrokerSource
	recipient      region.VerifiedNetBirdManagerRecipient
	ctx            context.Context
	expires        time.Time
	currentID      string
	currentVersion int64
	currentSHA256  string
	currentExpiry  time.Time
	guard          func(context.Context) error
}

func (client *NetBirdJournalClient) brokerReaderInputs(ctx context.Context) (netBirdJournalReaderInputs, error) {
	if client == nil {
		return netBirdJournalReaderInputs{}, ErrDelivery
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	expires, err := client.currentDeadline(ctx)
	if err != nil {
		return netBirdJournalReaderInputs{}, err
	}
	material := client.material.NetBirdBrokerMaterial
	material.Schema, material.Endpoints = 1, nil
	material.Credentials = bytes.Clone(material.Credentials)
	material.CA, material.Operator, material.Account = bytes.Clone(material.CA), bytes.Clone(material.Operator), bytes.Clone(material.Account)
	material.Certificate, material.Key = bytes.Clone(material.Certificate), bytes.Clone(material.Key)
	return netBirdJournalReaderInputs{material: material, source: client.source.BrokerSource(), recipient: client.source.Recipient(), ctx: client.ctx,
		expires: expires, currentID: client.currentID, currentVersion: client.currentVersion, currentSHA256: client.currentSHA256, currentExpiry: client.currentExpiry, guard: client.Guard}, nil
}
