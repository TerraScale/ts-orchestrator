package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"maps"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// OCIRIssuerIntent explicitly authorizes one first-party pull principal. Its
// group and policy names are PrincipalName+"-pull" and permit only this repo.
// It conveys no IAM authority outside that exact derived identity and policy.
type OCIRIssuerIntent struct {
	OCIRegion               string             `json:"ociRegion"`
	RepositoryCompartmentID string             `json:"repositoryCompartmentId"`
	RepositoryName          string             `json:"repositoryName"`
	RegistryNamespace       string             `json:"registryNamespace"`
	PrincipalName           string             `json:"principalName"`
	PrincipalEmail          string             `json:"principalEmail"`
	VaultTarget             vaultsecret.Target `json:"vaultTarget"`
	SecretName              string             `json:"secretName"`
}

type VerifiedOCIRIssuer struct {
	intent         OCIRIssuerIntent
	tenancyID      string
	installationID string
	generation     uint64
	grantDigest    string
	expires        time.Time
}

func (v VerifiedOCIRIssuer) Intent() OCIRIssuerIntent { return v.intent }
func (v VerifiedOCIRIssuer) TenancyID() string        { return v.tenancyID }
func (v VerifiedOCIRIssuer) InstallationID() string   { return v.installationID }
func (v VerifiedOCIRIssuer) Generation() uint64       { return v.generation }
func (v VerifiedOCIRIssuer) GrantDigest() string      { return v.grantDigest }
func (v VerifiedOCIRIssuer) ExpiresAt() time.Time     { return v.expires }
func (v VerifiedOCIRIssuer) IsVerified() bool         { return v.generation != 0 && v.grantDigest != "" }

var ocirIssuerPrincipal = regexp.MustCompile(`^[a-z][a-z0-9-]{0,95}$`)
var ocirIssuerRepository = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
var ocirIssuerNamespace = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validateOCIRIssuerIdentity(intent OCIRIssuerIntent) error {
	address, err := mail.ParseAddress(intent.PrincipalEmail)
	if !catalog.IsOCIRegion(intent.OCIRegion) || !ocirIssuerPrincipal.MatchString(intent.PrincipalName) || !readAccessSecretName.MatchString(intent.SecretName) || len(intent.SecretName) > 255 ||
		!ocirIssuerNamespace.MatchString(intent.RegistryNamespace) || !ocirIssuerRepository.MatchString(intent.RepositoryName) || len(intent.RepositoryName) > 255 || err != nil || address.Address != intent.PrincipalEmail || len(intent.PrincipalEmail) > 254 || strings.ContainsAny(intent.PrincipalEmail, "\r\n\t ") {
		return errors.New("signed OCIR issuer lacks exact bounded principal, email, repository or secret identity")
	}
	return nil
}

// ValidateFoundationOCIRIssuer checks the bounded signed recipe before the
// offline root ceremony; it grants no IAM or Vault mutation authority.
func ValidateFoundationOCIRIssuer(grant FoundationGrant) error {
	if grant.OCIRIssuance == nil {
		return errors.New("foundation has no first-party OCIR issuance recipe")
	}
	intent := *grant.OCIRIssuance
	if err := validateOCIRIssuerIdentity(intent); err != nil {
		return err
	}
	footprint := ApprovedFootprint{TenancyID: grant.TenancyID, ParentCompartmentID: grant.ParentCompartmentID, SharedCompartmentID: grant.SharedCompartmentID, Regions: grant.Regions}
	if err := validateFootprint(footprint); err != nil {
		return err
	}
	for _, regional := range grant.Regions {
		if regional.Plan["region"] != intent.OCIRegion {
			continue
		}
		cell := regional.Plan["cell"].(string)
		ids := regional.Plan["resource_ids"].(map[string]any)
		for _, field := range []struct {
			value string
			keys  []string
		}{
			{intent.RepositoryCompartmentID, []string{"control_compartment", "workload_compartment"}},
			{intent.VaultTarget.CompartmentID, []string{"control_compartment"}},
			{intent.VaultTarget.VaultID, []string{"vault"}},
			{intent.VaultTarget.KeyID, []string{"key"}},
		} {
			matched := false
			for _, key := range field.keys {
				if pinned, _ := ids[key].(string); pinned != "" {
					kind, region := "compartment", ""
					if key == "vault" || key == "key" {
						kind, region = key, intent.OCIRegion
					}
					if field.value == pinned && strings.HasPrefix(pinned, "ocid1."+kind+".oc1."+region+".") && len(pinned) <= 255 && !strings.ContainsAny(pinned, " \t\r\n") {
						matched = true
					}
				} else if grant.SchemaVersion == 2 {
					reference, _ := FoundationResourceReference(cell, key)
					if field.value == reference {
						matched = true
					}
				}
			}
			if !matched {
				return errors.New("OCIR recipe resource differs from its exact signed regional role")
			}
		}
		return nil
	}
	return errors.New("OCIR recipe is outside the signed foundation footprint")
}

func (s *SignedFootprint) OCIRIssuer(ctx context.Context) (VerifiedOCIRIssuer, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	footprint, expires, err := s.verifyGrant(wire)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	if grant.OCIRIssuance == nil {
		return VerifiedOCIRIssuer{}, errors.New("same root grant does not authorize first-party OCIR issuance")
	}
	if err := ValidateFoundationOCIRIssuer(grant); err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	copyIntent := *grant.OCIRIssuance
	intent := &copyIntent
	owned := false
	for _, regional := range footprint.Regions {
		if regional.Plan["region"] != intent.OCIRegion {
			continue
		}
		ids := regional.Plan["resource_ids"].(map[string]any)
		if strings.HasPrefix(intent.RepositoryCompartmentID, "foundation:") || strings.HasPrefix(intent.VaultTarget.CompartmentID, "foundation:") || strings.HasPrefix(intent.VaultTarget.VaultID, "foundation:") || strings.HasPrefix(intent.VaultTarget.KeyID, "foundation:") {
			cell := regional.Plan["cell"].(string)
			bindings, err := s.resourceBindings(ctx, cell, wire)
			if err != nil {
				return VerifiedOCIRIssuer{}, err
			}
			ids = maps.Clone(ids)
			for _, field := range []struct {
				value *string
				keys  []string
			}{
				{&intent.RepositoryCompartmentID, []string{"control_compartment", "workload_compartment"}},
				{&intent.VaultTarget.CompartmentID, []string{"control_compartment"}},
				{&intent.VaultTarget.VaultID, []string{"vault"}},
				{&intent.VaultTarget.KeyID, []string{"key"}},
			} {
				if !strings.HasPrefix(*field.value, "foundation:") {
					continue
				}
				matched := false
				for _, key := range field.keys {
					reference, _ := FoundationResourceReference(cell, key)
					if *field.value != reference {
						continue
					}
					id, err := bindings.Resolve(reference)
					if err != nil {
						return VerifiedOCIRIssuer{}, err
					}
					if pinned, _ := ids[key].(string); pinned != "" && pinned != id {
						return VerifiedOCIRIssuer{}, errors.New("OCIR resource binding differs from signed exact identity")
					}
					*field.value, ids[key], matched = id, id, true
					break
				}
				if !matched {
					return VerifiedOCIRIssuer{}, errors.New("OCIR logical resource is outside its signed regional role")
				}
			}
		}
		target := intent.VaultTarget
		owned = target.CompartmentID == ids["control_compartment"] && target.VaultID == ids["vault"] && target.KeyID == ids["key"] &&
			strings.HasPrefix(target.CompartmentID, "ocid1.compartment.oc1..") && strings.HasPrefix(target.VaultID, "ocid1.vault.oc1."+intent.OCIRegion+".") && strings.HasPrefix(target.KeyID, "ocid1.key.oc1."+intent.OCIRegion+".") &&
			strings.HasPrefix(intent.RepositoryCompartmentID, "ocid1.compartment.oc1..") && (intent.RepositoryCompartmentID == ids["control_compartment"] || intent.RepositoryCompartmentID == ids["workload_compartment"])
	}
	if !owned {
		return VerifiedOCIRIssuer{}, errors.New("signed OCIR issuer differs from approved owned regional repository and Vault identities")
	}
	digest := sha256.Sum256(wire)
	return VerifiedOCIRIssuer{intent: *intent, tenancyID: grant.TenancyID, installationID: grant.InstallationID, generation: grant.Generation, grantDigest: hex.EncodeToString(digest[:]), expires: expires}, nil
}

// OCIRIssuer also requires the current reconciled regional foundation; a
// desired plan alone never authorizes credentials for an unverified Vault.
func (r FoundationResolver) OCIRIssuer(ctx context.Context) (VerifiedOCIRIssuer, error) {
	reader, ok := r.Footprint.(interface {
		OCIRIssuer(context.Context) (VerifiedOCIRIssuer, error)
	})
	if !ok {
		return VerifiedOCIRIssuer{}, errors.New("foundation reader has no signed OCIR issuance authority")
	}
	verified, err := reader.OCIRIssuer(ctx)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	entry, ok := catalog.CellForOCIRegion(verified.intent.OCIRegion)
	if !ok {
		return VerifiedOCIRIssuer{}, errors.New("OCIR issuer region is outside approved catalog")
	}
	record, err := r.Resolve(ctx, entry.Cell)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	target, err := record.VaultTarget()
	if err != nil || record.Generation != verified.generation || target != verified.intent.VaultTarget || !time.Now().Before(verified.expires) {
		return VerifiedOCIRIssuer{}, errors.New("OCIR issuer differs from current reconciled foundation")
	}
	return verified, nil
}

// GuardOCIRIssuer revalidates the exact grant. The producer must also check its
// durable operation epoch and hold the tenancy-wide IAM write serialization.
func (r FoundationResolver) GuardOCIRIssuer(ctx context.Context, expected VerifiedOCIRIssuer) error {
	if !expected.IsVerified() || !time.Now().Before(expected.expires) {
		return errors.New("OCIR issuance authority is absent or expired")
	}
	current, err := r.OCIRIssuer(ctx)
	if err != nil {
		return err
	}
	if current.grantDigest != expected.grantDigest || current.generation != expected.generation || current.intent != expected.intent || current.tenancyID != expected.tenancyID || current.installationID != expected.installationID {
		return errors.New("OCIR issuance signed scope changed")
	}
	return ctx.Err()
}
