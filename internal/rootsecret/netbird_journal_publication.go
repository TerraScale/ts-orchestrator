package rootsecret

import (
	"context"
	"errors"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

// ErrNetBirdJournalBirthUnproven means absence supplies no first-publication
// authority. Recovery needs the genuine protected original credential birth.
var ErrNetBirdJournalBirthUnproven = errors.New("NetBird journal CURRENT is absent; protected original credential birth is unproven")

// netBirdJournalPublication never adopts another CURRENT or renews its material.
// The server joins all handlers before close wipes the retained private bytes.
type netBirdJournalPublication struct {
	source         NetBirdJournalSource
	material       NetBirdJournalMaterial
	credential     bootstrapmaterial.NetBirdJournalCredential
	ctx            context.Context
	cancel         context.CancelFunc
	expires        time.Time
	currentID      string
	currentVersion int64
	currentSHA256  string
	currentExpiry  time.Time
	bundles        ocisecrets.SecretsClient
	store          bootstrapstart.MaterialStore
}

func (*netBirdJournalPublication) String() string               { return "NetBird journal publication [redacted]" }
func (publication *netBirdJournalPublication) GoString() string { return publication.String() }

func (publication *netBirdJournalPublication) close() {
	if publication != nil {
		if publication.cancel != nil {
			publication.cancel()
		}
		clearNetBirdJournalMaterial(publication.material)
	}
}

func (publication *netBirdJournalPublication) currentDeadline(ctx context.Context) (time.Time, error) {
	if publication == nil || ctx == nil || publication.ctx == nil || publication.ctx.Err() != nil || !time.Now().Before(publication.expires) {
		return time.Time{}, ErrDelivery
	}
	ctx, stop := netBirdReadContext(ctx, publication.ctx, minDeadline(publication.expires, time.Now().Add(30*time.Second)))
	defer stop()
	deadline, err := publication.source.CurrentDeadline(ctx)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	ctx, stopSource := context.WithDeadline(ctx, minDeadline(deadline, publication.expires))
	defer stopSource()
	current, err := vaultsecret.ReadCurrent(ctx, &publication.bundles, NetBirdBrokerRef(publication.source.public))
	if err != nil || current.ID != publication.currentID || current.Version != publication.currentVersion ||
		!current.ExpiresAt.Equal(publication.currentExpiry) || netBirdDigest([]byte(current.Value())) != publication.currentSHA256 {
		return time.Time{}, ErrDelivery
	}
	deadline = minDeadline(deadline, publication.expires)
	deadline, err = checkNetBirdJournalWriterMaterial(ctx, publication.source, publication.store, deadline)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	_, credential, err := CheckNetBirdJournalMaterial(publication.material, publication.source, time.Now().UTC())
	if err != nil || credential != publication.credential || ctx.Err() != nil || publication.ctx.Err() != nil || publication.source.checkOriginal() != nil || !time.Now().Before(deadline) {
		return time.Time{}, ErrDelivery
	}
	return deadline, nil
}

// openNetBirdJournalPublication opens an existing v2 CURRENT, or conditionally
// migrates one fully authenticated v1. Absence never authorizes fresh issuance.
func openNetBirdJournalPublication(ctx context.Context, custody *NetBirdStartupCustody) (*netBirdJournalPublication, error) {
	if ctx == nil || custody == nil || os.Geteuid() != 0 {
		return nil, ErrDelivery
	}
	deadline, err := custody.CurrentDeadline(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	lifetime, cancel := context.WithDeadline(custody.Context(), deadline)
	publication := &netBirdJournalPublication{ctx: lifetime, cancel: cancel, expires: deadline}
	retained := false
	defer func() {
		if !retained {
			publication.close()
		}
	}()
	ctx, stop := netBirdReadContext(ctx, lifetime, minDeadline(deadline, time.Now().Add(30*time.Second)))
	defer stop()
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, exists := os.LookupEnv(name); exists {
			return nil, ErrDelivery
		}
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, "sa-saopaulo-1")
	if err != nil {
		return nil, ErrDelivery
	}
	publication.source, err = LoadNetBirdJournalSourceForOperation(ctx, custody, factory)
	if err != nil {
		return nil, ErrDelivery
	}
	publication.expires = minDeadline(publication.expires, publication.source.ExpiresAt())
	ctx, stopSource := context.WithDeadline(ctx, publication.expires)
	defer stopSource()
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return nil, ErrDelivery
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return nil, ErrDelivery
	}
	publication.store, err = bootstrapstart.NewMaterialStore(nil, uint32(uid), uint32(gid))
	if err != nil {
		return nil, ErrDelivery
	}
	publication.bundles, err = vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, ErrDelivery
	}
	current, err := vaultsecret.ReadCurrent(ctx, &publication.bundles, NetBirdBrokerRef(publication.source.public))
	if err != nil {
		if vaultsecret.Absent(err) {
			return nil, ErrNetBirdJournalBirthUnproven
		}
		return nil, ErrDelivery
	}
	if !current.ExpiresAt.IsZero() {
		publication.expires = minDeadline(publication.expires, current.ExpiresAt)
	}
	ctx, stopCurrent := context.WithDeadline(ctx, publication.expires)
	defer stopCurrent()
	wire := []byte(current.Value())
	defer clear(wire)
	material, decodeErr := DecodeNetBirdJournalMaterial(wire)
	if decodeErr != nil {
		previous, err := DecodeNetBirdBrokerMaterial(wire)
		if err != nil || previous.Schema != 1 {
			clear(previous.Credentials)
			clear(previous.Key)
			return nil, ErrDelivery
		}
		defer clear(previous.Credentials)
		defer clear(previous.Key)
		material, current, err = publication.migrateV1(ctx, factory, current, previous, uint32(uid), uint32(gid))
		if err != nil {
			return nil, ErrDelivery
		}
	}
	publication.material = material
	publication.source, err = publication.source.ForBrokerMaterial(ctx, material.NetBirdBrokerMaterial)
	if err != nil {
		return nil, ErrDelivery
	}
	_, publication.credential, err = CheckNetBirdJournalMaterial(material, publication.source, time.Now().UTC())
	if err != nil {
		return nil, ErrDelivery
	}
	publication.expires = minDeadline(publication.expires, minDeadline(publication.source.ExpiresAt(), minDeadline(material.ExpiresAt, publication.credential.ExpiresAt)))
	if !current.ExpiresAt.IsZero() {
		publication.expires = minDeadline(publication.expires, current.ExpiresAt)
	}
	publication.currentID, publication.currentVersion = current.ID, current.Version
	publication.currentExpiry, publication.currentSHA256 = current.ExpiresAt, netBirdDigest([]byte(current.Value()))
	// Preserve the existing reader policy; this path creates no IAM authority.
	if region.VerifyNetBirdBrokerReader(ctx, factory, publication.source.public.resolver, publication.source.public.source, publication.source.recipient) != nil {
		return nil, ErrDelivery
	}
	if _, err := publication.currentDeadline(ctx); err != nil {
		return nil, ErrDelivery
	}
	originalCancel := publication.cancel
	publication.ctx, publication.cancel = context.WithDeadline(publication.ctx, publication.expires)
	boundedCancel := publication.cancel
	publication.cancel = func() { boundedCancel(); originalCancel() }
	retained = true
	return publication, nil
}

func (publication *netBirdJournalPublication) migrateV1(ctx context.Context, factory *ociclient.Factory, original vaultsecret.Current, previous NetBirdBrokerMaterial, uid, gid uint32) (NetBirdJournalMaterial, vaultsecret.Current, error) {
	fail := func() (NetBirdJournalMaterial, vaultsecret.Current, error) {
		return NetBirdJournalMaterial{}, vaultsecret.Current{}, ErrDelivery
	}
	publication.expires = minDeadline(publication.expires, previous.ExpiresAt)
	ctx, stop := context.WithDeadline(ctx, publication.expires)
	defer stop()
	// Authenticate the original locators before the early public source strips
	// them. Cold startup without the original live overlay cannot migrate v1.
	legacy, err := LoadNetBirdBrokerSourceForOperation(ctx, publication.source.original, factory, "GRU", previous.StartupSlot)
	if err != nil {
		return fail()
	}
	if _, _, err := CheckNetBirdBrokerMaterial(previous, legacy, publication.source.recipient, time.Now().UTC()); err != nil {
		return fail()
	}
	publication.source, err = publication.source.ForBrokerMaterial(ctx, previous)
	if err != nil {
		return fail()
	}
	publication.expires = minDeadline(publication.expires, minDeadline(legacy.ExpiresAt(), publication.source.ExpiresAt()))
	guard := func(check context.Context) error {
		check, stop := netBirdReadContext(check, publication.ctx, publication.expires)
		defer stop()
		if legacy.Guard(check) != nil {
			return ErrDelivery
		}
		observed, err := vaultsecret.ReadCurrent(check, &publication.bundles, NetBirdBrokerRef(publication.source.public))
		if err != nil || observed.ID != original.ID || observed.Version != original.Version || !observed.ExpiresAt.Equal(original.ExpiresAt) ||
			netBirdDigest([]byte(observed.Value())) != netBirdDigest([]byte(original.Value())) {
			return ErrDelivery
		}
		_, err = checkNetBirdJournalWriterMaterial(check, publication.source, publication.store, publication.expires)
		if err != nil || publication.ctx.Err() != nil {
			return ErrDelivery
		}
		return check.Err()
	}
	if guard(ctx) != nil || region.VerifyNetBirdBrokerReader(ctx, factory, publication.source.public.resolver, publication.source.public.source, publication.source.recipient) != nil {
		return fail()
	}
	files := make(map[string][]byte)
	defer func() {
		for _, wire := range files {
			clear(wire)
		}
	}()
	read := func(name string) ([]byte, error) {
		if guard(ctx) != nil {
			return nil, ErrDelivery
		}
		wire, err := readNetBirdJournalWriterTLSFile(name, uid, gid)
		files[name] = wire
		if err != nil || !publication.source.public.matchesFile(name, wire) || guard(ctx) != nil {
			return nil, ErrDelivery
		}
		return wire, nil
	}
	issuer, err := bootstrapmaterial.LoadStartupControllerIssuer(ctx, publication.source.public.startup, read, time.Now().UTC())
	if err != nil {
		return fail()
	}
	defer issuer.Wipe()
	credentials, err := issuer.IssueNetBirdJournalCredentials(ctx, publication.expires, publication.source.purpose)
	if err != nil {
		return fail()
	}
	defer clear(credentials)
	material, err := NewNetBirdJournalMaterial(publication.source, previous, credentials, time.Now().UTC())
	if err != nil {
		return fail()
	}
	retained := false
	defer func() {
		if !retained {
			clearNetBirdJournalMaterial(material)
		}
	}()
	wire, err := material.Encode()
	if err != nil {
		return fail()
	}
	defer clear(wire)
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return fail()
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	if guard(ctx) != nil {
		return fail()
	}
	ref := NetBirdBrokerRef(publication.source.public)
	if _, err := vaultsecret.PublishVersion(ociclient.WithRequestGuard(ctx, guard), &management, ref, original.ID, original.Version, wire); err != nil {
		return fail()
	}
	current, err := vaultsecret.ReadCurrent(ctx, &publication.bundles, ref)
	if err != nil || current.ID != original.ID || current.Version <= original.Version || netBirdDigest([]byte(current.Value())) != netBirdDigest(wire) ||
		!current.ExpiresAt.Equal(original.ExpiresAt) {
		return fail()
	}
	retained = true
	return material, current, nil
}
