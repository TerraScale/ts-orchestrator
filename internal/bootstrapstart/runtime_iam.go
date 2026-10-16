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
	reader   *CurrentFounderAuthorityReader
	accepted AcceptedIdentity
	factory  *ociclient.Factory
	observer *OCIInstanceObserver
	imds     IMDSClient
	scope    bootstrap.FoundationScope
	anchor   string
}

func VerifyRuntimeIAM(ctx context.Context, reader *CurrentFounderAuthorityReader, accepted AcceptedIdentity) (VerifiedRuntimeIAM, error) {
	current, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return VerifiedRuntimeIAM{}, err
	}
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
	proof := VerifiedRuntimeIAM{reader: reader, accepted: accepted.Clone(), factory: factory,
		observer: observer, imds: NewIMDSClient(), scope: scope, anchor: current.Anchor().Digest()}
	if err := proof.VerifyCurrent(ctx); err != nil {
		return VerifiedRuntimeIAM{}, err
	}
	return proof, nil
}

func (proof VerifiedRuntimeIAM) IsVerified() bool {
	return proof.reader != nil && proof.factory != nil && proof.observer != nil && proof.anchor != ""
}
func (proof VerifiedRuntimeIAM) InstanceID() string                         { return proof.accepted.InstanceOCID }
func (proof VerifiedRuntimeIAM) FoundationScope() bootstrap.FoundationScope { return proof.scope }

func (proof VerifiedRuntimeIAM) GuardedFactory(ctx context.Context) (*ociclient.Factory, context.Context, error) {
	if err := proof.VerifyCurrent(ctx); err != nil {
		return nil, ctx, err
	}
	return proof.factory, ociclient.WithAuthority(ctx, proof.VerifyCurrent), nil
}

func (proof VerifiedRuntimeIAM) VerifyCurrent(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !proof.IsVerified() {
		return ErrSourceFounder
	}
	now := time.Now().UTC()
	current, err := proof.reader.ReadRuntimeAuthority(ctx, proof.accepted, now)
	if err != nil {
		return err
	}
	scope, err := current.Anchor().FoundationScope()
	if err != nil || scope != proof.scope || current.Anchor().Digest() != proof.anchor || current.Identity().OCIRegion != proof.factory.Region() {
		return ErrSourceFounder
	}
	gate := Gate{SelfUpdate: selfupdate.NewLayout(selfupdate.DefaultRoot)}
	if err := gate.verifyRestartBinary(proof.accepted, proof.reader.baked.Roots); err != nil {
		return err
	}
	instance, err := proof.imds.FetchInstanceID(ctx)
	if err != nil || instance != proof.accepted.InstanceOCID {
		return errors.Join(ErrSourceFounder, err)
	}
	if err := verifyIAMInstancePrincipal(proof.factory.Provider(), proof.scope.TenancyID, instance); err != nil {
		return err
	}
	descriptor, err := proof.imds.FetchDescriptor(ctx)
	if err != nil || descriptor.SchemaVersion != 1 || descriptor.Slot != proof.accepted.Slot {
		return errors.Join(ErrSourceFounder, err)
	}
	manifest, err := proof.currentManifest(ctx, now)
	if err != nil {
		return err
	}
	observed, err := proof.observer.ObserveInstance(ctx, instance)
	if err != nil {
		return err
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
			return ErrSourceFounder
		}
		return nil
	}
	return ErrSourceFounder
}

func (proof VerifiedRuntimeIAM) currentManifest(ctx context.Context, now time.Time) (bootstrap.Manifest, error) {
	var wire []byte
	if proof.accepted.Slot == proof.accepted.SeedSlot {
		selected, err := proof.reader.ReadCurrent(ctx, now)
		if err != nil || selected.Anchor.Digest() != proof.anchor {
			return bootstrap.Manifest{}, errors.Join(ErrSourceFounder, err)
		}
		wire = selected.ManifestWires[proof.accepted.Slot]
	} else {
		selected, err := proof.reader.readCurrentCompletedPeer(ctx, now, true)
		if err != nil || selected.Anchor.Digest() != proof.anchor {
			return bootstrap.Manifest{}, errors.Join(ErrSourceFounder, err)
		}
		wire = selected.ManifestWires[proof.accepted.Slot]
	}
	var manifest bootstrap.Manifest
	envelope, err := trust.DecodeEnvelope(wire)
	// The current selection reader verified these exact manifest bytes.
	if err != nil || digestWire(wire) != proof.reader.accepted.ManifestSHA256 ||
		protocol.DecodeStrict(envelope.Payload, &manifest, bootstrap.MaxManifestBytes) != nil || manifest.ImageOCID != proof.accepted.ImageOCID ||
		manifest.Slot != proof.accepted.Slot || manifest.OCIRegion != proof.factory.Region() {
		return bootstrap.Manifest{}, ErrSourceFounder
	}
	return manifest, nil
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
