package bootstrapmaterial

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// CheckGenerationFiles reads every file a material generation pins (TS-568)
// and checks its digest, size and meaning with the rules the running cell
// applies:
//   - ca.pem holds one to four self-signed root CAs;
//   - the controller TLS issuer and the host TLS issuer are path-length-zero
//     intermediates signed by a CA in the bundle, not CAs of the bundle, with
//     single-block EC keys that match; the controller issuer serves and
//     dials, the host issuer is client-only and name-constrained to the
//     cell's hosts, as hostenroll loads it;
//   - the account signer seed is AccountSigner;
//   - operator.jwt is the operator's own, names the system account and has
//     no signing keys; system.jwt and cell.jwt are signed by it; cell.jwt
//     has JetStream and exactly two signing keys, the host scope of
//     HostSigner and the unscoped AccountSigner;
//   - system.creds is a system account user with only its claim-update and
//     reply grants.
//
// Everything must be valid at now. It returns the first expiry, which
// bounds the generation's signature. A cell.jwt replacement is also checked
// against the running claim (issue time, exports) when a broker applies it.
func CheckGenerationFiles(generation bootstrap.MaterialGeneration, read func(name string) ([]byte, error), now time.Time,
) (time.Time, error) {
	if err := generation.Validate(); err != nil {
		return time.Time{}, err
	}
	files := map[string][]byte{}
	for _, secret := range generation.Secrets {
		data, err := read(secret.TargetFile)
		if err != nil {
			return time.Time{}, fmt.Errorf("read %s: %w", secret.TargetFile, err)
		}
		digest := sha256.Sum256(data)
		if int64(len(data)) > secret.MaxBytes || hex.EncodeToString(digest[:]) != secret.SHA256 {
			return time.Time{}, fmt.Errorf("%w: %s differs from its pinned digest or size",
				bootstrap.ErrMaterialGenerationInvalid, secret.TargetFile)
		}
		files[secret.TargetFile] = data
	}
	cell := strings.ToLower(string(generation.Cell))
	check := generationCheck{now: now}
	var roots []*x509.Certificate
	for rest := files["ca.pem"]; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			if len(strings.TrimSpace(string(rest))) != 0 {
				check.fail("ca.pem has trailing data that is not a certificate")
			}
			break
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if block.Type != "CERTIFICATE" || err != nil || !ca.IsCA || !ca.BasicConstraintsValid ||
			ca.KeyUsage&x509.KeyUsageCertSign == 0 || ca.CheckSignatureFrom(ca) != nil {
			check.fail("ca.pem holds something other than a self-signed CA")
			continue
		}
		check.certificate("ca.pem", ca)
		roots = append(roots, ca)
	}
	if len(roots) == 0 || len(roots) > 4 {
		check.fail("ca.pem must hold one to four CAs")
	}
	if issuer, err := controllerIssuer(files["controller-tls-issuer-key.pem"], files["controller-tls-issuer-cert.pem"], roots); err != nil {
		check.fail(err.Error())
	} else {
		check.certificate("controller-tls-issuer-cert.pem", issuer)
	}
	if _, issuer, _, err := hostenroll.ParseTLSIssuer(files["host-tls-issuer-key.pem"], files["host-tls-issuer-cert.pem"],
		roots); err != nil {
		check.fail(err.Error())
	} else {
		domain := "hosts." + cell + ".terrascale.internal"
		if !issuer.PermittedDNSDomainsCritical || !slices.Equal(issuer.PermittedDNSDomains, []string{"." + domain}) ||
			!slices.Equal(issuer.PermittedURIDomains, []string{domain}) {
			check.fail("the host TLS issuer is not constrained to the cell's hosts")
		}
		check.certificate("host-tls-issuer-cert.pem", issuer)
	}
	if signer, err := nkeys.FromSeed([]byte(strings.TrimSpace(string(files["controller-account-signer.seed"])))); err != nil {
		check.fail("controller-account-signer.seed is not an NKey seed")
	} else {
		public, _ := signer.PublicKey()
		signer.Wipe()
		if public != generation.AccountSigner {
			check.fail("controller-account-signer.seed is not the generation's account signer")
		}
	}
	operator, err := jwt.DecodeOperatorClaims(strings.TrimSpace(string(files["operator.jwt"])))
	// Decoding verifies each signature against the claim's issuer; the
	// issuer checks and DidSign tie those signers to the operator.
	if err != nil || operator.Subject != generation.Operator || operator.Issuer != generation.Operator ||
		!operator.DidSign(operator) || operator.SystemAccount != generation.SystemAccount || len(operator.SigningKeys) != 0 {
		check.fail("operator.jwt is not the operator's own JWT naming the system account, without signing keys")
		operator = nil
	} else {
		check.jwt("operator.jwt", operator.IssuedAt, operator.Expires)
	}
	system, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(files["system.jwt"])))
	if err != nil || system.Subject != generation.SystemAccount || system.Issuer != generation.Operator ||
		operator == nil || !operator.DidSign(system) {
		check.fail("system.jwt is not the system account signed by the operator")
	} else {
		check.jwt("system.jwt", system.IssuedAt, system.Expires)
	}
	cellClaim, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(files["cell.jwt"])))
	if err != nil || cellClaim.Subject != generation.CellAccount || cellClaim.Issuer != generation.Operator ||
		operator == nil || !operator.DidSign(cellClaim) {
		check.fail("cell.jwt is not the cell account signed by the operator")
	} else {
		hostScope, hostScoped := cellClaim.SigningKeys.GetScope(generation.HostSigner)
		accountScope, accountSigner := cellClaim.SigningKeys.GetScope(generation.AccountSigner)
		if len(cellClaim.SigningKeys) != 2 || !hostScoped || !reflect.DeepEqual(hostScope, expectedHostScope(cell, generation.HostSigner)) ||
			!accountSigner || accountScope != nil {
			check.fail("cell.jwt must have exactly the host scope and the unscoped account signer as signing keys")
		}
		if cellClaim.Limits.JetStreamLimits == (jwt.JetStreamLimits{}) {
			check.fail("cell.jwt grants no JetStream")
		}
		check.jwt("cell.jwt", cellClaim.IssuedAt, cellClaim.Expires)
	}
	if err := natscell.ValidateSystemCredentials(files["system.creds"], cell, generation.CellAccount,
		generation.SystemAccount); err != nil {
		check.fail(err.Error())
	} else if raw, err := jwt.ParseDecoratedJWT(files["system.creds"]); err == nil {
		if user, err := jwt.DecodeUserClaims(raw); err == nil {
			check.jwt("system.creds", user.IssuedAt, user.Expires)
		}
	}
	if len(check.problems) != 0 {
		return time.Time{}, fmt.Errorf("%w: %s", bootstrap.ErrMaterialGenerationInvalid, strings.Join(check.problems, "; "))
	}
	return check.first, nil
}

// controllerIssuer checks the controller TLS issuer: a single EC key and
// certificate that match, a path-length-zero intermediate for server and
// client leaves, signed by a CA in roots and not itself one of them.
func controllerIssuer(keyPEM, certPEM []byte, roots []*x509.Certificate) (*x509.Certificate, error) {
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("controller TLS issuer key format is invalid")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("controller TLS issuer key format is invalid")
	}
	certBlock, rest := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("controller TLS issuer certificate format is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, errors.New("controller TLS issuer certificate format is invalid")
	}
	signed := false
	for _, root := range roots {
		if root.Equal(cert) {
			return nil, errors.New("the controller TLS issuer is a CA of the bundle")
		}
		signed = signed || cert.CheckSignatureFrom(root) == nil
	}
	usages := slices.Sorted(slices.Values(cert.ExtKeyUsage))
	public, ecdsaKey := cert.PublicKey.(*ecdsa.PublicKey)
	if !signed || cert.CheckSignatureFrom(cert) == nil || !cert.IsCA || !cert.MaxPathLenZero ||
		cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!slices.Equal(usages, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) ||
		!ecdsaKey || !public.Equal(&key.PublicKey) {
		return nil, errors.New("the controller TLS issuer is not a bundle-signed, leaf-only server and client intermediate")
	}
	return cert, nil
}

// generationCheck collects problems and the first expiry.
type generationCheck struct {
	now      time.Time
	first    time.Time
	problems []string
}

func (check *generationCheck) fail(problem string) { check.problems = append(check.problems, problem) }

func (check *generationCheck) expires(name string, notAfter time.Time) {
	if !check.now.Before(notAfter) {
		check.fail(name + " has expired")
	}
	if check.first.IsZero() || notAfter.Before(check.first) {
		check.first = notAfter
	}
}

func (check *generationCheck) certificate(name string, certificate *x509.Certificate) {
	if check.now.Before(certificate.NotBefore) {
		check.fail(name + " is not yet valid")
	}
	check.expires(name, certificate.NotAfter)
}

// jwt checks a JWT was issued by now, within the trust envelope's clock
// skew, and records its expiry; zero means it never expires.
func (check *generationCheck) jwt(name string, issuedAt, expires int64) {
	if time.Unix(issuedAt, 0).After(check.now.Add(bootstrap.ManifestClockSkew)) {
		check.fail(name + " is issued in the future")
	}
	if expires != 0 {
		check.expires(name, time.Unix(expires, 0).UTC())
	}
}
