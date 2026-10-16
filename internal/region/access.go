package region

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

var ErrReadAccessPending = errors.New("root-authorized regional read access is not available")

// ReadAccessIntent authorizes exact TLS origins and an existing Vault secret.
// It describes destinations, not host admission or observed serving health.
type ReadAccessIntent struct {
	URLs       []string        `json:"urls"`
	UsageToken vaultsecret.Ref `json:"usageToken"`
}

// VerifiedReadAccess carries only references covered by the current root grant.
type VerifiedReadAccess struct {
	intent     ReadAccessIntent
	target     vaultsecret.Target
	cell       string
	region     string
	generation uint64
	expires    time.Time
}

func (v VerifiedReadAccess) URLs() []string              { return slices.Clone(v.intent.URLs) }
func (v VerifiedReadAccess) UsageToken() vaultsecret.Ref { return v.intent.UsageToken }
func (v VerifiedReadAccess) Cell() string                { return v.cell }
func (v VerifiedReadAccess) OCIRegion() string           { return v.region }
func (v VerifiedReadAccess) ExpiresAt() time.Time        { return v.expires }
func (v VerifiedReadAccess) IsVerified() bool {
	return v.generation != 0 && time.Now().Before(v.expires)
}

var readAccessSecretName = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func validateReadAccess(intent ReadAccessIntent, target vaultsecret.Target) error {
	if intent.UsageToken.Vault != target.VaultID || len(intent.UsageToken.Name) > 255 || !readAccessSecretName.MatchString(intent.UsageToken.Name) || len(intent.URLs) == 0 || len(intent.URLs) > 64 {
		return errors.New("signed read access lacks exact owned Vault references or bounded origins")
	}
	seen := make(map[string]bool, len(intent.URLs))
	for _, origin := range intent.URLs {
		u, err := url.Parse(origin)
		if err != nil || len(origin) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Path != "" && u.Path != "/" || u.RawPath != "" || strings.ContainsAny(origin, "\r\n\t ") {
			return errors.New("signed read access requires exact HTTPS origins without credentials, paths or redirects")
		}
		if strings.HasSuffix(u.Host, ":") {
			return errors.New("signed read access has an empty port")
		}
		if port := u.Port(); port != "" {
			number, err := strconv.Atoi(port)
			if err != nil || number < 1 || number > 65535 {
				return errors.New("signed read access has an invalid port")
			}
		}
		key := strings.ToLower(u.Host)
		if seen[key] {
			return errors.New("signed read access repeats an origin")
		}
		seen[key] = true
	}
	return nil
}

func (s *SignedFootprint) AuthorizedReadAccess(ctx context.Context, cell string) (VerifiedReadAccess, error) {
	footprint, expires, err := s.authorizedRegions(ctx)
	if err != nil {
		return VerifiedReadAccess{}, err
	}
	if cell == "" {
		home, ok := catalog.CellForOCIRegion(s.home.OCIRegion)
		if !ok {
			return VerifiedReadAccess{}, errors.New("signed home region is outside the catalog")
		}
		cell = home.Cell
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != cell {
			continue
		}
		if intent.ReadAccess == nil {
			return VerifiedReadAccess{}, ErrReadAccessPending
		}
		ids, _ := intent.Plan["resource_ids"].(map[string]any)
		target := vaultsecret.Target{}
		target.CompartmentID, _ = ids["control_compartment"].(string)
		target.VaultID, _ = ids["vault"].(string)
		target.KeyID, _ = ids["key"].(string)
		entry, ok := catalog.Lookup(cell)
		if !ok || intent.Plan["region"] != entry.OCIRegion || target.CompartmentID == "" || target.KeyID == "" || !strings.HasPrefix(target.VaultID, "ocid1.vault.oc1."+entry.OCIRegion+".") || !strings.HasPrefix(target.KeyID, "ocid1.key.oc1."+entry.OCIRegion+".") {
			return VerifiedReadAccess{}, errors.New("signed read access lacks owned regional control, Vault and key identities")
		}
		if err := validateReadAccess(*intent.ReadAccess, target); err != nil {
			return VerifiedReadAccess{}, err
		}
		read := *intent.ReadAccess
		read.URLs = slices.Clone(read.URLs)
		return VerifiedReadAccess{intent: read, target: target, cell: cell, region: entry.OCIRegion, generation: intent.Generation, expires: expires}, nil
	}
	return VerifiedReadAccess{}, ErrReadAccessPending
}

// ReadAccess requires the same signed intent and its current reconciled record.
func (r FoundationResolver) ReadAccess(ctx context.Context, cell string) (VerifiedReadAccess, error) {
	reader, ok := r.Footprint.(interface {
		AuthorizedReadAccess(context.Context, string) (VerifiedReadAccess, error)
	})
	if !ok {
		return VerifiedReadAccess{}, ErrReadAccessPending
	}
	access, err := reader.AuthorizedReadAccess(ctx, cell)
	if err != nil {
		return VerifiedReadAccess{}, err
	}
	record, err := r.Resolve(ctx, access.Cell())
	if errors.Is(err, ErrFoundationMissing) {
		return VerifiedReadAccess{}, errors.Join(ErrReadAccessPending, err)
	}
	if err != nil {
		return VerifiedReadAccess{}, err
	}
	if err := ctx.Err(); err != nil {
		return VerifiedReadAccess{}, err
	}
	target, err := record.VaultTarget()
	if err != nil || target != access.target || record.Generation != access.generation || !access.IsVerified() {
		return VerifiedReadAccess{}, errors.New("read access differs from its current reconciled foundation")
	}
	return access, nil
}
