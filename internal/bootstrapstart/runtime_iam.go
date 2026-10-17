package bootstrapstart

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// VerifiedRuntimeIAM binds an installed controller to current signed scope and
// its own authenticated OCI identity. It carries no founder launch authority.
type VerifiedRuntimeIAM struct {
	original context.Context
	reader   *CurrentFounderAuthorityReader
	accepted AcceptedIdentity
	factory  *ociclient.Factory
	observer *OCIInstanceObserver
	imds     IMDSClient
	scope    bootstrap.FoundationScope
	anchor   string
	expires  time.Time
}

func VerifyRuntimeIAM(ctx context.Context, reader *CurrentFounderAuthorityReader, accepted AcceptedIdentity) (VerifiedRuntimeIAM, error) {
	if ctx == nil {
		return VerifiedRuntimeIAM{}, ErrSourceFounder
	}
	original := ctx
	current, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return VerifiedRuntimeIAM{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, current.ExpiresAt())
	defer cancel()
	scope, err := current.Anchor().FoundationScope()
	if err != nil || scope.Validate() != nil {
		return VerifiedRuntimeIAM{}, errors.Join(ErrSourceFounder, err)
	}
	config, err := currentLedgerConfig(current.Anchor(), reader.baked.Roots)
	if err != nil {
		return VerifiedRuntimeIAM{}, err
	}
	provider, err := newOCIAdmissionProvider(config)
	if err != nil {
		return VerifiedRuntimeIAM{}, err
	}
	factory, err := ociclient.New(provider, ociclient.Options{Region: current.Identity().OCIRegion})
	if err != nil {
		return VerifiedRuntimeIAM{}, err
	}
	observer, err := NewOCIInstanceObserver(config.Cell, provider)
	if err != nil {
		return VerifiedRuntimeIAM{}, err
	}
	proof := VerifiedRuntimeIAM{original: original, reader: reader, accepted: accepted.Clone(), factory: factory,
		observer: observer, imds: NewIMDSClient(), scope: scope, anchor: current.Anchor().Digest(), expires: current.ExpiresAt()}
	deadline, err := proof.CurrentDeadline(ctx)
	if err != nil {
		return VerifiedRuntimeIAM{}, err
	}
	proof.expires = deadline
	return proof, nil
}

func (proof VerifiedRuntimeIAM) IsVerified() bool {
	return proof.original != nil && proof.reader != nil && proof.factory != nil && proof.observer != nil && proof.anchor != "" && !proof.expires.IsZero()
}

// CheckOriginal checks retained lifetimes only; it performs no current reads.
func (proof VerifiedRuntimeIAM) CheckOriginal() error {
	if !proof.IsVerified() {
		return ErrSourceFounder
	}
	if err := proof.original.Err(); err != nil {
		return err
	}
	now := time.Now()
	if !now.Before(proof.expires) {
		return ErrSourceFounder
	}
	if deadline, ok := proof.original.Deadline(); ok && !now.Before(deadline) {
		return ErrSourceFounder
	}
	return nil
}

func (proof VerifiedRuntimeIAM) InstanceID() string                         { return proof.accepted.InstanceOCID }
func (proof VerifiedRuntimeIAM) FoundationScope() bootstrap.FoundationScope { return proof.scope }
func (proof VerifiedRuntimeIAM) ExpiresAt() time.Time                       { return proof.expires }

func (proof VerifiedRuntimeIAM) GuardedFactory(ctx context.Context) (*ociclient.Factory, context.Context, error) {
	if err := proof.VerifyCurrent(ctx); err != nil {
		return nil, ctx, err
	}
	return proof.factory, ociclient.WithAuthority(ctx, proof.VerifyCurrent), nil
}

func (proof VerifiedRuntimeIAM) VerifyCurrent(ctx context.Context) error {
	_, err := proof.CurrentDeadline(ctx)
	return err
}

// CurrentDeadline retains the original acquisition cancellation and purpose
// deadline plus any shorter current signed selection through verification.
func (proof VerifiedRuntimeIAM) CurrentDeadline(ctx context.Context) (time.Time, error) {
	return proof.CurrentDeadlineForOperation(ctx, ctx)
}

// CurrentDeadlineForOperation bounds reads by ctx while retaining the original
// acquisition and signed source minima independently of that temporary budget.
func (proof VerifiedRuntimeIAM) CurrentDeadlineForOperation(ctx, original context.Context) (time.Time, error) {
	if ctx == nil || original == nil || !proof.IsVerified() {
		return time.Time{}, ErrSourceFounder
	}
	if err := proof.original.Err(); err != nil {
		return time.Time{}, err
	}
	expires := proof.expires
	for _, retained := range []context.Context{original, proof.original} {
		if err := retained.Err(); err != nil {
			return time.Time{}, err
		}
		if deadline, ok := retained.Deadline(); ok && deadline.Before(expires) {
			expires = deadline
		}
	}
	ctx, cancelOriginal := context.WithDeadline(ctx, expires)
	defer cancelOriginal()
	stopOriginal := context.AfterFunc(proof.original, cancelOriginal)
	defer stopOriginal()
	stopOperationOriginal := context.AfterFunc(original, cancelOriginal)
	defer stopOperationOriginal()
	if err := proof.original.Err(); err != nil {
		return time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	now := time.Now().UTC()
	current, err := proof.reader.ReadRuntimeAuthority(ctx, proof.accepted, now)
	if err != nil {
		return time.Time{}, err
	}
	if current.ExpiresAt().Before(expires) {
		expires = current.ExpiresAt()
	}
	ctx, cancelCurrent := context.WithDeadline(ctx, expires)
	defer cancelCurrent()
	scope, err := current.Anchor().FoundationScope()
	if err != nil || scope != proof.scope || current.Anchor().Digest() != proof.anchor || current.Identity().OCIRegion != proof.factory.Region() {
		return time.Time{}, ErrSourceFounder
	}
	gate := Gate{SelfUpdate: selfupdate.NewLayout(selfupdate.DefaultRoot)}
	if err := gate.verifyRestartBinary(proof.accepted, proof.reader.baked.Roots); err != nil {
		return time.Time{}, err
	}
	instance, err := proof.imds.FetchInstanceID(ctx)
	if err != nil || instance != proof.accepted.InstanceOCID {
		return time.Time{}, errors.Join(ErrSourceFounder, err)
	}
	if err := verifyIAMInstancePrincipal(proof.factory.Provider(), proof.scope.TenancyID, instance); err != nil {
		return time.Time{}, err
	}
	descriptor, err := proof.imds.FetchDescriptor(ctx)
	if err != nil || descriptor.SchemaVersion != 1 || descriptor.Slot != proof.accepted.Slot {
		return time.Time{}, errors.Join(ErrSourceFounder, err)
	}
	manifest, manifestDeadline, err := proof.currentManifest(ctx, now)
	if err != nil {
		return time.Time{}, err
	}
	if manifestDeadline.Before(expires) {
		expires = manifestDeadline
	}
	ctx, cancelManifest := context.WithDeadline(ctx, expires)
	defer cancelManifest()
	observed, err := proof.observer.ObserveInstance(ctx, instance)
	if err != nil {
		return time.Time{}, err
	}
	for _, profile := range manifest.Profiles {
		if profile.Slot != proof.accepted.Slot {
			continue
		}
		nsgs, expected := slices.Clone(observed.NSGOCIDs), slices.Clone(profile.NetworkSecurityGroupOCIDs)
		slices.Sort(nsgs)
		slices.Sort(expected)
		if observed.InstanceOCID != instance || observed.LifecycleState != "RUNNING" || observed.ImageOCID != proof.accepted.ImageOCID ||
			observed.CompartmentOCID != profile.CompartmentOCID || observed.AvailabilityDomain != profile.AvailabilityDomain ||
			observed.FaultDomain != profile.FaultDomain || observed.Shape != profile.Shape || observed.SubnetOCID != profile.SubnetOCID ||
			!slices.Equal(nsgs, expected) || !observed.PrimaryVNIC || observed.PrimaryVNICOCID != proof.accepted.PrimaryVNICOCID || observed.PrimaryPrivateIP != proof.accepted.PrimaryPrivateIP {
			return time.Time{}, ErrSourceFounder
		}
		if err := ociclient.LimitAdmission(ctx, expires); err != nil {
			return time.Time{}, err
		}
		if err := ociclient.LimitAdmission(ctx, proof.expires); err != nil {
			return time.Time{}, err
		}
		if err := proof.original.Err(); err != nil {
			return time.Time{}, err
		}
		if err := original.Err(); err != nil {
			return time.Time{}, err
		}
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		return expires, nil
	}
	return time.Time{}, ErrSourceFounder
}

func (proof VerifiedRuntimeIAM) currentManifest(ctx context.Context, now time.Time) (bootstrap.Manifest, time.Time, error) {
	var wire []byte
	var expires time.Time
	if proof.accepted.Slot == proof.accepted.SeedSlot {
		selected, err := proof.reader.ReadCurrent(ctx, now)
		if err != nil || selected.Anchor.Digest() != proof.anchor {
			return bootstrap.Manifest{}, time.Time{}, errors.Join(ErrSourceFounder, err)
		}
		wire, expires = selected.ManifestWires[proof.accepted.Slot], selected.SelectionExpiresAt
	} else {
		selected, err := proof.reader.readCurrentCompletedPeer(ctx, now, true)
		if err != nil || selected.Anchor.Digest() != proof.anchor {
			return bootstrap.Manifest{}, time.Time{}, errors.Join(ErrSourceFounder, err)
		}
		wire, expires = selected.ManifestWires[proof.accepted.Slot], selected.SelectionExpiresAt
	}
	var manifest bootstrap.Manifest
	envelope, err := trust.DecodeEnvelope(wire)
	// The current selection reader verified these exact manifest bytes.
	if err != nil || digestWire(wire) != proof.reader.accepted.ManifestSHA256 ||
		protocol.DecodeStrict(envelope.Payload, &manifest, bootstrap.MaxManifestBytes) != nil || manifest.ImageOCID != proof.accepted.ImageOCID ||
		manifest.Slot != proof.accepted.Slot || manifest.OCIRegion != proof.factory.Region() {
		return bootstrap.Manifest{}, time.Time{}, ErrSourceFounder
	}
	if err := ctx.Err(); err != nil {
		return bootstrap.Manifest{}, time.Time{}, err
	}
	if !time.Now().Before(expires) {
		return bootstrap.Manifest{}, time.Time{}, ErrSourceFounder
	}
	return manifest, expires, nil
}

func verifyIAMInstancePrincipal(provider common.ConfigurationProvider, tenancy, instance string) error {
	actualTenancy, err := provider.TenancyOCID()
	kind, _ := provider.AuthType()
	if err != nil || actualTenancy != tenancy || kind.AuthType != common.InstancePrincipal {
		return ErrSourceFounder
	}
	key, err := provider.KeyID()
	if err != nil || len(key) > 64<<10 || !strings.HasPrefix(key, "ST$") {
		return ErrSourceFounder
	}
	parts := strings.Split(strings.TrimPrefix(key, "ST$"), ".")
	if len(parts) != 3 {
		return ErrSourceFounder
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrSourceFounder
	}
	var claims struct {
		Subject  string `json:"sub"`
		Instance string `json:"opc-instance"`
		Type     string `json:"ptype"`
		Tenancy  string `json:"tenant"`
		Expiry   int64  `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Subject != instance || claims.Instance != instance ||
		claims.Type != "instance" || claims.Tenancy != tenancy || time.Now().Unix() >= claims.Expiry {
		return ErrSourceFounder
	}
	return nil
}
