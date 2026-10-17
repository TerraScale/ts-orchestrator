package natscell

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
)

// ValidateProductionCredentials checks all broker and controller credentials.
// Each private file must belong to the current process; production bootstrap
// validates the root broker and ordinary controller portions separately.
func ValidateProductionCredentials(cfg Config) error {
	if err := ValidateProductionBrokerCredentials(cfg); err != nil {
		return err
	}
	return ValidateProductionControllerCredentials(cfg)
}

// ValidateProductionBrokerCredentials checks privileged broker users, every TLS
// role and the route password as their owner. The production caller is root.
func ValidateProductionBrokerCredentials(cfg Config) error {
	systemID, cellID, err := productionCredentialAccounts(cfg)
	if err != nil {
		return err
	}
	e := cfg.Embedded
	if err := validateSystemCredentials(e.SystemCredentialsFile, cfg.Cell, cellID, systemID); err != nil {
		return err
	}
	systemUser, _, err := credentialUser(e.SystemCredentialsFile)
	if err != nil {
		return fmt.Errorf("system account credentials: %w", err)
	}
	result := jwt.CreateValidationResults()
	systemUser.Validate(result)
	if result.IsBlocking(true) {
		return errors.New("system user JWT is not currently valid")
	}
	if e.MembershipCredentialsFile != "" {
		if err := ValidateMembershipCredentials(e.MembershipCredentialsFile, cfg.Cell, systemID); err != nil {
			return err
		}
	}
	for label, files := range map[string]TLSFiles{"client": cfg.TLS, "listener": e.TLS, "route": e.RouteTLS} {
		if err := validateCurrentTLSFiles(files, label); err != nil {
			return fmt.Errorf("%s TLS material: %w", label, err)
		}
	}
	if e.InterRegion != nil {
		if e.InterRegion.Listen != nil {
			if err := validateCurrentTLSFiles(e.InterRegion.Listen.TLS, "listener"); err != nil {
				return fmt.Errorf("interregion listener TLS material: %w", err)
			}
		}
		for _, remote := range e.InterRegion.Remotes {
			if err := validateCurrentTLSFiles(remote.TLS, "client"); err != nil {
				return fmt.Errorf("interregion remote %q TLS material: %w", remote.Peer, err)
			}
		}
	}
	if e.Link != nil {
		role := "client"
		if cfg.Cell == LinkHome {
			role = "listener"
		}
		if err := validateCurrentTLSFiles(e.Link.TLS, role); err != nil {
			return fmt.Errorf("link TLS material: %w", err)
		}
	}
	if cfg.Replicas > 1 {
		password, err := readPrivateFile(e.RoutePasswordFile, 4096)
		if err != nil {
			return fmt.Errorf("NATS route secret: %w", err)
		}
		defer clear(password)
		if len(strings.TrimSpace(string(password))) < 16 {
			return errors.New("NATS route secret is too short")
		}
	}
	return nil
}

// ValidateProductionControllerCredentials checks public account trust and the
// controller user key, JWT and grants under the actual service UID. Broker TLS,
// SYSTEM, membership and route secrets remain exclusively in the root preflight.
func ValidateProductionControllerCredentials(cfg Config) error {
	_, cellID, err := productionCredentialAccounts(cfg)
	if err != nil {
		return err
	}
	controller, _, err := credentialUser(cfg.CredentialsFile)
	if err != nil || credentialAccount(controller) != cellID {
		return errors.New("controller credentials do not belong to the regional cell account")
	}
	result := jwt.CreateValidationResults()
	controller.Validate(result)
	if result.IsBlocking(true) {
		return errors.New("controller user JWT is not currently valid")
	}
	if err := ValidateBrokerControllerCredentials(cfg.CredentialsFile, cfg.Cell, cfg.Instance); err != nil {
		return err
	}
	return nil
}

func productionCredentialAccounts(cfg Config) (systemID, cellID string, err error) {
	if cfg.Embedded == nil || cfg.ClientRole != "" && cfg.ClientRole != "controller" {
		return "", "", errors.New("controller credential preflight requires a production embedded broker")
	}
	if err := cfg.validate(); err != nil {
		return "", "", err
	}
	operator, systemRaw, cellRaw, systemID, cellID, err := loadOperatorAccounts(cfg.Embedded)
	if err != nil {
		return "", "", err
	}
	system, err := jwt.DecodeAccountClaims(systemRaw)
	if err != nil {
		return "", "", fmt.Errorf("decode system account JWT: %w", err)
	}
	cell, err := jwt.DecodeAccountClaims(cellRaw)
	if err != nil {
		return "", "", fmt.Errorf("decode cell account JWT: %w", err)
	}
	for label, claim := range map[string]jwt.Claims{"operator": operator, "system": system, "cell": cell} {
		result := jwt.CreateValidationResults()
		claim.Validate(result)
		if result.IsBlocking(true) {
			return "", "", fmt.Errorf("%s JWT is not currently valid", label)
		}
	}
	return systemID, cellID, nil
}

func validateCurrentTLSFiles(files TLSFiles, role string) error {
	config, err := loadTLS(files, false)
	if err != nil {
		return err
	}
	if len(config.Certificates) != 1 || len(config.Certificates[0].Certificate) == 0 {
		return errors.New("TLS certificate chain is missing")
	}
	leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		return fmt.Errorf("parse TLS leaf certificate: %w", err)
	}
	return verifyTLSLeaf(leaf, config.Certificates[0].Certificate[1:], config.RootCAs, role)
}

// verifyTLSLeaf checks that a leaf is current and chains to roots for each
// usage its role needs: client, listener or route (both ends).
func verifyTLSLeaf(leaf *x509.Certificate, chain [][]byte, roots *x509.CertPool, role string) error {
	intermediates := x509.NewCertPool()
	for _, der := range chain {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse TLS intermediate certificate: %w", err)
		}
		intermediates.AddCert(certificate)
	}
	var usages []x509.ExtKeyUsage
	switch role {
	case "client":
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "listener":
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "route":
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	default:
		return fmt.Errorf("unsupported TLS certificate role %q", role)
	}
	for _, usage := range usages {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(),
			KeyUsages: []x509.ExtKeyUsage{usage},
		}); err != nil {
			return fmt.Errorf("verify current TLS certificate chain: %w", err)
		}
	}
	return nil
}
