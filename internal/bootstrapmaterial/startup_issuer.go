package bootstrapmaterial

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// LoadStartupControllerIssuer loads online keys only through the sealed source
// inventory; a derived startup is never represented as a material generation.
func LoadStartupControllerIssuer(ctx context.Context, authority bootstrap.DerivedStartupAuthority, read func(string) ([]byte, error), now time.Time) (*ControllerIssuer, error) {
	if !authority.IsVerified() || read == nil || now.IsZero() {
		return nil, ErrMaterial
	}
	if err := authority.VerifyCurrent(ctx, now); err != nil {
		return nil, err
	}
	wire := authority.MaterialRecord()
	var record Record
	manifest := authority.Manifest()
	if digest(wire) != authority.MaterialSHA256() || json.Unmarshal(wire, &record, json.RejectUnknownMembers(true)) != nil ||
		record.Config.Environment != manifest.Environment || strings.ToUpper(record.Config.Cell) != string(manifest.Cell) ||
		record.Config.DeploymentID != manifest.DeploymentID || record.Config.ClusterID != manifest.ClusterID {
		return nil, ErrMaterial
	}
	account, err := StartupControllerAccountFile(authority)
	if err != nil {
		return nil, err
	}
	issuer, err := loadControllerIssuerFiles(record, account, read, now)
	if err != nil {
		return nil, err
	}
	issuer.identity.expiresAt = minTime(issuer.identity.expiresAt, authority.ExpiresAt())
	if current := time.Now(); current.After(now) {
		now = current
	}
	if err := authority.VerifyCurrent(ctx, now); err != nil {
		issuer.Wipe()
		return nil, err
	}
	issuer.startup = authority
	return issuer, nil
}

// StartupControllerAccountFile returns the account pin actually installed by
// the sealed startup. HOME's signed Link publication replaces only cell.jwt.
func StartupControllerAccountFile(authority bootstrap.DerivedStartupAuthority) (File, error) {
	var record Record
	if !authority.IsVerified() || json.Unmarshal(authority.MaterialRecord(), &record, json.RejectUnknownMembers(true)) != nil {
		return File{}, ErrMaterial
	}
	var account File
	for _, file := range record.Files {
		if file.Name == "cell.jwt" {
			if account.Name != "" {
				return File{}, ErrMaterial
			}
			account = file
		}
	}
	if account.Name == "" {
		return File{}, ErrMaterial
	}
	linkWire := authority.LinkMaterialRecord()
	if authority.Manifest().Cell == "GRU" && len(linkWire) != 0 {
		var link LinkRecord
		if json.Unmarshal(linkWire, &link, json.RejectUnknownMembers(true)) != nil || link.SchemaVersion != 1 ||
			link.SourceSHA256 != authority.MaterialSHA256() || link.HomeSHA256 != authority.MaterialSHA256() ||
			link.HomeLinkSHA256 != "" || link.HomeAccount != record.Public.CellAccountNKey ||
			!reflect.DeepEqual(link.Config, record.Config) || !reflect.DeepEqual(link.Public, record.Public) {
			return File{}, ErrMaterial
		}
		var replacement File
		for _, file := range link.Files {
			if file.Name == "link-cell.jwt" {
				if replacement.Name != "" || file.Purpose != account.Purpose || file.Slot != account.Slot || file.MaxBytes <= 0 || file.MaxBytes > maxInterRegionFile {
					return File{}, ErrMaterial
				}
				replacement = file
			}
		}
		if replacement.Name == "" {
			return File{}, ErrMaterial
		}
		replacement.Name = "cell.jwt"
		account = replacement
	}
	refs := authority.Manifest().Secrets
	index := slices.IndexFunc(refs, func(ref bootstrap.SecretReference) bool { return ref.TargetFile == "cell.jwt" })
	if index < 0 || refs[index].Purpose != account.Purpose || refs[index].Slot != account.Slot || refs[index].SHA256 != account.SHA256 || refs[index].MaxBytes != account.MaxBytes {
		return File{}, ErrMaterial
	}
	return account, nil
}

func loadRecordedControllerIssuer(record Record, read func(string) ([]byte, error), now time.Time) (*ControllerIssuer, error) {
	for _, file := range record.Files {
		if file.Name == "cell.jwt" {
			return loadControllerIssuerFiles(record, file, read, now)
		}
	}
	return nil, ErrMaterial
}

func loadControllerIssuerFiles(record Record, accountPin File, read func(string) ([]byte, error), now time.Time) (*ControllerIssuer, error) {
	if record.SchemaVersion != 1 || record.Config.validate() != nil || now.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) ||
		record.ExpiresAt.Sub(record.IssuedAt) != time.Duration(record.Config.ValidityHours)*time.Hour ||
		!nkeys.IsValidPublicOperatorKey(record.Public.OperatorNKey) || !nkeys.IsValidPublicAccountKey(record.Public.CellAccountNKey) ||
		!nkeys.IsValidPublicAccountKey(record.Public.ControllerAccountSignerNKey) ||
		record.Public.ControllerAccountSignerNKey == record.Public.CellAccountNKey || record.Public.ControllerAccountSignerNKey == record.Public.HostNATSIssuerNKey {
		return nil, ErrMaterial
	}
	inventory := make(map[string]File, len(record.Files))
	for _, file := range record.Files {
		purpose, slot := classify(file.Name)
		if _, exists := inventory[file.Name]; exists || purpose == "" || file.Purpose != purpose || file.Slot != slot || file.MaxBytes <= 0 || file.MaxBytes > bootstrap.MaxSecretBytes {
			return nil, ErrMaterial
		}
		inventory[file.Name] = file
	}
	files := make(map[string][]byte)
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	for _, name := range []string{"ca.pem", "operator.jwt", "cell.jwt", "controller-tls-issuer-cert.pem", "controller-tls-issuer-key.pem", "controller-account-signer.seed"} {
		file, exists := inventory[name]
		if !exists {
			return nil, ErrMaterial
		}
		if name == "cell.jwt" {
			if accountPin.Name != file.Name || accountPin.Purpose != file.Purpose || accountPin.Slot != file.Slot {
				return nil, ErrMaterial
			}
			file = accountPin
		}
		body, err := read(name)
		if err != nil {
			return nil, err
		}
		files[name] = bytes.Clone(body)
		if int64(len(body)) != file.MaxBytes || digest(body) != file.SHA256 {
			return nil, ErrMaterial
		}
	}
	check := generationCheck{now: now}
	roots := check.bundle("ca.pem", files["ca.pem"])
	cert, err := controllerIssuer(files["controller-tls-issuer-key.pem"], files["controller-tls-issuer-cert.pem"], roots)
	if err != nil {
		return nil, err
	}
	check.certificate("controller-tls-issuer-cert.pem", cert)
	if cert.NotAfter.After(minTime(record.ExpiresAt, record.IssuedAt.Add(controllerIssuedLifetime))) ||
		cert.KeyUsage != x509.KeyUsageCertSign || !cert.BasicConstraintsValid ||
		len(cert.PermittedDNSDomains)+len(cert.PermittedURIDomains)+len(cert.PermittedIPRanges)+len(cert.PermittedEmailAddresses)+
			len(cert.ExcludedDNSDomains)+len(cert.ExcludedURIDomains)+len(cert.ExcludedIPRanges)+len(cert.ExcludedEmailAddresses) != 0 {
		return nil, ErrMaterial
	}
	operator, err := jwt.DecodeOperatorClaims(strings.TrimSpace(string(files["operator.jwt"])))
	if err != nil || operator.Subject != record.Public.OperatorNKey || operator.Issuer != operator.Subject ||
		!operator.DidSign(operator) || operator.SystemAccount != record.Public.SystemAccountNKey || len(operator.SigningKeys) != 0 || operator.Expires == 0 {
		return nil, ErrMaterial
	}
	validation := jwt.CreateValidationResults()
	operator.Validate(validation)
	check.jwt("operator.jwt", operator.IssuedAt, operator.Expires)
	account, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(files["cell.jwt"])))
	if err != nil || account.Subject != record.Public.CellAccountNKey || account.Issuer != record.Public.OperatorNKey || !operator.DidSign(account) || account.Expires == 0 {
		return nil, ErrMaterial
	}
	account.Validate(validation)
	check.jwt("cell.jwt", account.IssuedAt, account.Expires)
	scope, exists := account.SigningKeys.GetScope(record.Public.ControllerAccountSignerNKey)
	if !exists || scope != nil || validation.IsBlocking(true) || len(check.problems) != 0 {
		return nil, ErrMaterial
	}
	for key, scope := range account.SigningKeys {
		if scope == nil && key != record.Public.ControllerAccountSignerNKey {
			return nil, ErrMaterial
		}
	}
	return loadControllerIssuer(issuerIdentity{Cell: strings.ToUpper(record.Config.Cell), Environment: record.Config.Environment,
		Operator: record.Public.OperatorNKey, CellAccount: record.Public.CellAccountNKey, AccountSigner: record.Public.ControllerAccountSignerNKey,
		lifetime: controllerIssuedLifetime, expiresAt: minTime(record.ExpiresAt, minTime(time.Unix(operator.Expires, 0), time.Unix(account.Expires, 0)))},
		files["controller-tls-issuer-cert.pem"], files["controller-tls-issuer-key.pem"], files["controller-account-signer.seed"])
}
