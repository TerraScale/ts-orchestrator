package bootstrapstart

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

var ErrSourceFounder = errors.New("bootstrap source founder is not currently authorized")

// VerifiedSourceFounder binds the local seed to its root-signed recipe and a
// fresh independent OCI observation. It cannot authorize another instance.
type VerifiedSourceFounder struct {
	template bootstrap.VerifiedStartupTemplate
	factory  *ociclient.Factory
	imds     DescriptorSource
	observer InstanceObserver
	instance string
	tenancy  string
}

// VerifySourceFounder uses fixed local metadata and authenticated OCI endpoints.
// Matching an IMDS slot or a mutable instance tag alone grants no authority.
func VerifySourceFounder(ctx context.Context, factory *ociclient.Factory, template bootstrap.VerifiedStartupTemplate) (VerifiedSourceFounder, error) {
	if factory == nil || template.VerifyCurrent(time.Now().UTC()) != nil {
		return VerifiedSourceFounder{}, ErrSourceFounder
	}
	manifest, err := template.ManifestFor(template.Template().SeedSlot, nil)
	if err != nil || factory.Region() != manifest.OCIRegion {
		return VerifiedSourceFounder{}, ErrSourceFounder
	}
	var grant struct {
		TenancyID string `json:"tenancyId"`
	}
	envelope, err := trust.DecodeEnvelope(template.GrantWire())
	if err != nil || json.Unmarshal(envelope.Payload, &grant) != nil || grant.TenancyID == "" {
		return VerifiedSourceFounder{}, ErrSourceFounder
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != grant.TenancyID {
		return VerifiedSourceFounder{}, ErrSourceFounder
	}
	observer, err := NewOCIInstanceObserver(manifest.Cell, factory.Provider())
	if err != nil {
		return VerifiedSourceFounder{}, err
	}
	proof := VerifiedSourceFounder{template: template, factory: factory, imds: NewIMDSClient(), observer: observer, tenancy: tenancy}
	observed, err := proof.observe(ctx)
	if err != nil {
		return VerifiedSourceFounder{}, err
	}
	proof.instance = observed.InstanceOCID
	return proof, nil
}

func (proof VerifiedSourceFounder) IsVerified() bool {
	return proof.instance != "" && proof.template.IsVerified() && proof.factory != nil && proof.imds != nil && proof.observer != nil
}

func (proof VerifiedSourceFounder) InstanceID() string     { return proof.instance }
func (proof VerifiedSourceFounder) TenancyID() string      { return proof.tenancy }
func (proof VerifiedSourceFounder) SeedSlot() string       { return proof.template.Template().SeedSlot }
func (proof VerifiedSourceFounder) GrantDigest() string    { return proof.template.GrantDigest() }
func (proof VerifiedSourceFounder) TemplateDigest() string { return proof.template.TemplateDigest() }
func (proof VerifiedSourceFounder) PlanDigest() string     { return proof.template.PlanDigest() }
func (proof VerifiedSourceFounder) InstallationID() string { return proof.template.InstallationID() }
func (proof VerifiedSourceFounder) Generation() uint64     { return proof.template.Generation() }
func (proof VerifiedSourceFounder) ExpiresAt() time.Time   { return proof.template.ExpiresAt() }
func (proof VerifiedSourceFounder) StorageDomain() bootstrap.StorageDomain {
	manifest, _ := proof.template.ManifestFor(proof.SeedSlot(), nil)
	return manifest.StorageDomain
}

// GuardedFactory preserves the caller's context and rechecks this exact actor
// before each SDK mutation attempt, including retries.
func (proof VerifiedSourceFounder) GuardedFactory(ctx context.Context) (*ociclient.Factory, context.Context, error) {
	if err := proof.VerifyCurrent(ctx); err != nil {
		return nil, ctx, err
	}
	return proof.factory, ociclient.WithAuthority(ctx, proof.VerifyCurrent), nil
}

func (proof VerifiedSourceFounder) VerifyCurrent(ctx context.Context) error {
	if !proof.IsVerified() {
		return ErrSourceFounder
	}
	_, err := proof.observe(ctx)
	return err
}

func (proof VerifiedSourceFounder) observe(ctx context.Context) (InstanceObservation, error) {
	if err := ctx.Err(); err != nil {
		return InstanceObservation{}, err
	}
	if proof.factory == nil || proof.imds == nil || proof.observer == nil || proof.template.VerifyCurrent(time.Now().UTC()) != nil {
		return InstanceObservation{}, ErrSourceFounder
	}
	instance, err := proof.imds.FetchInstanceID(ctx)
	if err != nil || !instanceIDRE.MatchString(instance) || proof.instance != "" && instance != proof.instance {
		return InstanceObservation{}, errors.Join(ErrSourceFounder, err)
	}
	descriptor, err := proof.imds.FetchDescriptor(ctx)
	if err != nil || descriptor.SchemaVersion != 1 || descriptor.Slot != proof.SeedSlot() {
		return InstanceObservation{}, errors.Join(ErrSourceFounder, err)
	}
	if _, err := VerifyCurrentRunningBinary(proof.template.Image()); err != nil {
		return InstanceObservation{}, err
	}
	manifest, err := proof.template.ManifestFor(descriptor.Slot, nil)
	if err != nil || proof.factory.Region() != manifest.OCIRegion {
		return InstanceObservation{}, ErrSourceFounder
	}
	tenancy, err := proof.factory.Provider().TenancyOCID()
	if err != nil || tenancy != proof.tenancy {
		return InstanceObservation{}, ErrSourceFounder
	}
	observed, err := proof.observer.ObserveInstance(ctx, instance)
	if err != nil {
		return InstanceObservation{}, err
	}
	address, err := proof.template.SlotPrivateIP(descriptor.Slot)
	if err != nil {
		return InstanceObservation{}, err
	}
	for _, profile := range manifest.Profiles {
		if profile.Slot != descriptor.Slot {
			continue
		}
		nsgs, expected := slices.Clone(observed.NSGOCIDs), slices.Clone(profile.NetworkSecurityGroupOCIDs)
		slices.Sort(nsgs)
		slices.Sort(expected)
		if observed.InstanceOCID != instance || observed.LifecycleState != "RUNNING" || observed.ImageOCID != manifest.ImageOCID ||
			observed.CompartmentOCID != profile.CompartmentOCID || observed.AvailabilityDomain != profile.AvailabilityDomain ||
			observed.FaultDomain != profile.FaultDomain || observed.Shape != profile.Shape || observed.SubnetOCID != profile.SubnetOCID ||
			!slices.Equal(nsgs, expected) || !observed.PrimaryVNIC || !strings.HasPrefix(observed.PrimaryVNICOCID, "ocid1.vnic.") || observed.PrimaryPrivateIP != address {
			return InstanceObservation{}, ErrSourceFounder
		}
		return observed, nil
	}
	return InstanceObservation{}, fmt.Errorf("%w: signed seed profile is absent", ErrSourceFounder)
}
