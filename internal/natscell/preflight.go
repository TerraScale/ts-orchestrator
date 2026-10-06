package natscell

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
)

// ValidateProductionCredentials checks the configured production broker
// credentials without opening a listener, connecting to NATS, or changing
// local state. It must run as the account that will start the broker: the
// private-file readers enforce ownership by the current process user.
func ValidateProductionCredentials(cfg Config) error {
	if cfg.Lab || cfg.Embedded == nil || cfg.ClientRole != "" && cfg.ClientRole != "controller" {
		return errors.New("controller credential preflight requires a production embedded broker")
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	e := cfg.Embedded
	operator, systemRaw, cellRaw, _, cellID, err := loadOperatorAccounts(e)
	if err != nil {
		return err
	}
	system, err := jwt.DecodeAccountClaims(systemRaw)
	if err != nil {
		return fmt.Errorf("decode system account JWT: %w", err)
	}
	cell, err := jwt.DecodeAccountClaims(cellRaw)
	if err != nil {
		return fmt.Errorf("decode cell account JWT: %w", err)
	}
	for label, claim := range map[string]jwt.Claims{"operator": operator, "system": system, "cell": cell} {
		result := jwt.CreateValidationResults()
		claim.Validate(result)
		if result.IsBlocking(true) {
			return fmt.Errorf("%s JWT is not currently valid", label)
		}
	}
	if err := validateSystemCredentials(e.SystemCredentialsFile, cfg.Cell, cellID, system.Subject); err != nil {
		return err
	}
	systemUser, _, err := credentialUser(e.SystemCredentialsFile)
	if err != nil {
		return fmt.Errorf("system account credentials: %w", err)
	}
	controller, _, err := credentialUser(cfg.CredentialsFile)
	if err != nil || credentialAccount(controller) != cellID {
		return errors.New("controller credentials do not belong to the regional cell account")
	}
	for label, claim := range map[string]*jwt.UserClaims{"system": systemUser, "controller": controller} {
		result := jwt.CreateValidationResults()
		claim.Validate(result)
		if result.IsBlocking(true) {
			return fmt.Errorf("%s user JWT is not currently valid", label)
		}
	}
	if err := ValidateBrokerControllerCredentials(cfg.CredentialsFile, cfg.Cell, cfg.Instance); err != nil {
		return err
	}
	// The optional membership user is checked at admission, not first at
	// shutdown when it is needed for the metadata step-down.
	if e.MembershipCredentialsFile != "" {
		if err := ValidateMembershipCredentials(e.MembershipCredentialsFile, cfg.Cell, system.Subject); err != nil {
			return err
		}
	}
	for label, files := range map[string]TLSFiles{"client": cfg.TLS, "listener": e.TLS, "route": e.RouteTLS} {
		if err := validateCurrentTLSFiles(files, label); err != nil {
			return fmt.Errorf("%s TLS material: %w", label, err)
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
