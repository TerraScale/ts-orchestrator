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

	"github.com/distribution/reference"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// OCIRIssuerIntent explicitly authorizes one first-party pull principal. Its
// group and policy names are PrincipalName+"-pull" and permit only this repo.
// It conveys no IAM authority outside that exact derived identity and policy.
type OCIRIssuerIntent struct {
	OCIRegion               string             `json:"ociRegion"`
	RegistryHost            string             `json:"registryHost"`
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
func (v VerifiedOCIRIssuer) ImageRepository() string {
	return v.intent.RegistryHost + "/" + v.intent.RegistryNamespace + "/" + v.intent.RepositoryName
}

var ocirIssuerPrincipal = regexp.MustCompile(`^[a-z][a-z0-9-]{0,95}$`)
var ocirIssuerRepository = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
var ocirIssuerNamespace = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// OCIRServiceIdentity derives desired identities for explicit root approval;
// these names never prove that an existing IAM or Vault resource is owned.
func OCIRServiceIdentity(installationID, imageRepository string) (principalName, principalEmail, secretName string, err error) {
	if !entityid.Valid(installationID) {
		return "", "", "", errors.New("OCIR service identity requires an exact installation ID")
	}
	if _, _, _, err := parseOCIRRepository(imageRepository); err != nil {
		return "", "", "", err
	}
	digest := sha256.Sum256([]byte(installationID + "\x00" + imageRepository))
	name := "ts-ocir-" + hex.EncodeToString(digest[:16])
	return name, name + "@terrascale.tech", name + "-pull", nil
}

func parseOCIRRepository(imageRepository string) (ociRegion, namespace, repository string, err error) {
	ref, parseErr := reference.ParseNormalizedNamed(imageRepository)
	if parseErr != nil || ref.String() != imageRepository || !reference.IsNameOnly(ref) {
		return "", "", "", errors.New("OCIR repository must be an exact canonical name without a tag or digest")
	}
	host := reference.Domain(ref)
	namespace, repository, ok := strings.Cut(reference.Path(ref), "/")
	if !ok || !ocirIssuerNamespace.MatchString(namespace) || !ocirIssuerRepository.MatchString(repository) || len(repository) > 255 {
		return "", "", "", errors.New("OCIR repository lacks an exact bounded namespace and repository")
	}
	for _, entry := range catalog.Entries() {
		if host == strings.ToLower(entry.OCIRegionKey)+".ocir.io" || host == entry.OCIRegion+".ocir.io" {
			return entry.OCIRegion, namespace, repository, nil
		}
	}
	return "", "", "", errors.New("OCIR repository host is outside the approved region catalog")
}

func validateOCIRIssuerIdentity(intent OCIRIssuerIntent) error {
	ociRegion, namespace, repository, repositoryErr := parseOCIRRepository(intent.RegistryHost + "/" + intent.RegistryNamespace + "/" + intent.RepositoryName)
	address, err := mail.ParseAddress(intent.PrincipalEmail)
	if repositoryErr != nil || ociRegion != intent.OCIRegion || namespace != intent.RegistryNamespace || repository != intent.RepositoryName || !ocirIssuerPrincipal.MatchString(intent.PrincipalName) || !readAccessSecretName.MatchString(intent.SecretName) || len(intent.SecretName) > 255 ||
		!ocirIssuerNamespace.MatchString(intent.RegistryNamespace) || !ocirIssuerRepository.MatchString(intent.RepositoryName) || len(intent.RepositoryName) > 255 || err != nil || address.Address != intent.PrincipalEmail || len(intent.PrincipalEmail) > 254 || strings.ContainsAny(intent.PrincipalEmail, "\r\n\t ") {
		return errors.New("signed OCIR issuer lacks exact bounded principal, email, repository or secret identity")
	}
	return nil
}

// ValidateFoundationOCIRIssuer checks the bounded signed recipe before the
// offline root ceremony; it grants no IAM or Vault mutation authority.
func ValidateFoundationOCIRIssuer(grant FoundationGrant) error {
	if len(grant.OCIRIssuances) > 64 || len(grant.ReleaseAuthorities) > 64 {
		return errors.New("foundation OCIR issuance and release authorities exceed the bounded repository set")
	}
	approved := make(map[string]bool, len(grant.ReleaseAuthorities))
	physical := make(map[string]string, len(grant.ReleaseAuthorities))
	for _, authority := range grant.ReleaseAuthorities {
		ociRegion, namespace, repository, err := parseOCIRRepository(authority.ImageRepository)
		if err != nil {
			return err
		}
		key := ociRegion + "/" + namespace + "/" + repository
		if previous, exists := physical[key]; exists && previous != authority.ImageRepository {
			return errors.New("release authorities alias the same physical OCIR repository")
		}
		physical[key], approved[authority.ImageRepository] = authority.ImageRepository, true
	}
	principals, emails, recipients := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, intent := range grant.OCIRIssuances {
		if err := validateOCIRIssuerIdentity(intent); err != nil {
			return err
		}
		repository := intent.RegistryHost + "/" + intent.RegistryNamespace + "/" + intent.RepositoryName
		email := strings.ToLower(intent.PrincipalEmail)
		recipient := intent.VaultTarget.VaultID + "\x00" + intent.SecretName
		if !approved[repository] || principals[intent.PrincipalName] || emails[email] || recipients[recipient] {
			return errors.New("OCIR issuance is duplicate, unbound or reuses another repository's IAM or Vault recipient")
		}
		delete(approved, repository)
		principals[intent.PrincipalName], emails[email], recipients[recipient] = true, true, true
		if err := validateOCIRIssuerResources(grant, intent); err != nil {
			return err
		}
	}
	if len(approved) != 0 {
		return errors.New("OCIR issuance omits an approved release repository")
	}
	return nil
}

func validateOCIRIssuerResources(grant FoundationGrant, intent OCIRIssuerIntent) error {
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

// OCIRIssuers returns one sealed scope per exact approved release repository.
func (s *SignedFootprint) OCIRIssuers(ctx context.Context) ([]VerifiedOCIRIssuer, error) {
	return s.ocirIssuers(ctx, "")
}

func (s *SignedFootprint) OCIRIssuer(ctx context.Context, imageRepository string) (VerifiedOCIRIssuer, error) {
	if _, _, _, err := parseOCIRRepository(imageRepository); err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	issuers, err := s.ocirIssuers(ctx, imageRepository)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	if len(issuers) != 1 {
		return VerifiedOCIRIssuer{}, errors.New("same root grant has no exact OCIR repository issuance authority")
	}
	return issuers[0], nil
}

func (s *SignedFootprint) ocirIssuers(ctx context.Context, imageRepository string) ([]VerifiedOCIRIssuer, error) {
	wire, err := s.readGrant(ctx)
	if err != nil {
		return nil, err
	}
	footprint, expires, err := s.verifyGrant(wire)
	if err != nil {
		return nil, err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return nil, err
	}
	var grant FoundationGrant
	if err := json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if err := ValidateFoundationOCIRIssuer(grant); err != nil {
		return nil, err
	}
	issuers := make([]VerifiedOCIRIssuer, 0, len(grant.OCIRIssuances))
	for _, intent := range grant.OCIRIssuances {
		if imageRepository != "" && intent.RegistryHost+"/"+intent.RegistryNamespace+"/"+intent.RepositoryName != imageRepository {
			continue
		}
		verified, err := s.resolveOCIRIssuer(ctx, wire, footprint, grant, intent, expires)
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, verified)
	}
	return issuers, nil
}

func (s *SignedFootprint) resolveOCIRIssuer(ctx context.Context, wire []byte, footprint ApprovedFootprint, grant FoundationGrant, copyIntent OCIRIssuerIntent, expires time.Time) (VerifiedOCIRIssuer, error) {
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

// OCIRIssuers also requires every credential's current reconciled foundation.
func (r FoundationResolver) OCIRIssuers(ctx context.Context) ([]VerifiedOCIRIssuer, error) {
	reader, ok := r.Footprint.(interface {
		OCIRIssuers(context.Context) ([]VerifiedOCIRIssuer, error)
	})
	if !ok {
		return nil, errors.New("foundation reader has no signed OCIR issuance authority")
	}
	issuers, err := reader.OCIRIssuers(ctx)
	if err != nil {
		return nil, err
	}
	for _, verified := range issuers {
		if err := r.validateReconciledOCIRIssuer(ctx, verified); err != nil {
			return nil, err
		}
	}
	return issuers, nil
}

// OCIRIssuer requires only the selected repository's reconciled foundation;
// a desired plan alone never authorizes credentials for an unverified Vault.
func (r FoundationResolver) OCIRIssuer(ctx context.Context, imageRepository string) (VerifiedOCIRIssuer, error) {
	reader, ok := r.Footprint.(interface {
		OCIRIssuer(context.Context, string) (VerifiedOCIRIssuer, error)
	})
	if !ok {
		return VerifiedOCIRIssuer{}, errors.New("foundation reader has no signed OCIR issuance authority")
	}
	verified, err := reader.OCIRIssuer(ctx, imageRepository)
	if err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	if verified.ImageRepository() != imageRepository {
		return VerifiedOCIRIssuer{}, errors.New("OCIR issuer differs from the exact requested repository")
	}
	if err := r.validateReconciledOCIRIssuer(ctx, verified); err != nil {
		return VerifiedOCIRIssuer{}, err
	}
	return verified, nil
}

func (r FoundationResolver) validateReconciledOCIRIssuer(ctx context.Context, verified VerifiedOCIRIssuer) error {
	if !verified.IsVerified() {
		return errors.New("OCIR issuer lacks signed authority")
	}
	entry, ok := catalog.CellForOCIRegion(verified.intent.OCIRegion)
	if !ok {
		return errors.New("OCIR issuer region is outside approved catalog")
	}
	record, err := r.Resolve(ctx, entry.Cell)
	if err != nil {
		return err
	}
	target, err := record.VaultTarget()
	if err != nil || record.Generation != verified.generation || target != verified.intent.VaultTarget || !time.Now().Before(verified.expires) {
		return errors.New("OCIR issuer differs from current reconciled foundation")
	}
	return nil
}

// GuardOCIRIssuer revalidates the exact grant. The producer must also check its
// durable operation epoch and hold the tenancy-wide IAM write serialization.
func (r FoundationResolver) GuardOCIRIssuer(ctx context.Context, expected VerifiedOCIRIssuer) error {
	if !expected.IsVerified() || !time.Now().Before(expected.expires) {
		return errors.New("OCIR issuance authority is absent or expired")
	}
	current, err := r.OCIRIssuer(ctx, expected.ImageRepository())
	if err != nil {
		return err
	}
	if current.grantDigest != expected.grantDigest || current.generation != expected.generation || current.intent != expected.intent || current.tenancyID != expected.tenancyID || current.installationID != expected.installationID {
		return errors.New("OCIR issuance signed scope changed")
	}
	return ctx.Err()
}
