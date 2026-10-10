package bootstrapmaterial

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/roleidentity"
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
//     has JetStream and exactly these signing keys: the host scope of
//     HostSigner, in v1 the role scope of RoleSigner, the
//     unscoped AccountSigner when the controller issuers are pinned, and
//     the link signer when its scope is the link's (TS-803);
//   - system.creds is a system account user with only its claim-update and
//     reply grants;
//   - v1 (TS-668): the interregion or link files and controller configs, see
//     generationCheck.interRegion.
//
// A slot's own files (its interregion leaf TLS, and its controller config,
// read as controller-<slot>.json) are checked when read has them: a read
// that returns fs.ErrNotExist skips them, since a controller holds only its
// own. Everything must be valid at now. It returns the first expiry, which
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
		if secret.Slot != "" && errors.Is(err, fs.ErrNotExist) {
			continue
		}
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
	configs := map[string][]byte{}
	for _, pin := range generation.ControllerConfigs {
		name := "controller-" + pin.Slot + ".json"
		data, err := read(name)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("read %s: %w", name, err)
		}
		if int64(len(data)) != pin.Size || digest(data) != pin.SHA256 {
			return time.Time{}, fmt.Errorf("%w: %s differs from its pinned digest or size",
				bootstrap.ErrMaterialGenerationInvalid, name)
		}
		configs[pin.Slot] = data
	}
	cell := strings.ToLower(string(generation.Cell))
	check := generationCheck{now: now}
	roots := check.bundle("ca.pem", files["ca.pem"])
	// The v1 contract may pin no controller issuers; Validate ties them to
	// AccountSigner.
	issuing := generation.AccountSigner != ""
	if issuing {
		check.controllerIssuers(generation, files, roots)
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
		system = nil
	} else {
		check.jwt("system.jwt", system.IssuedAt, system.Expires)
	}
	cellClaim, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(files["cell.jwt"])))
	if err != nil || cellClaim.Subject != generation.CellAccount || cellClaim.Issuer != generation.Operator ||
		operator == nil || !operator.DidSign(cellClaim) {
		check.fail("cell.jwt is not the cell account signed by the operator")
		cellClaim = nil
	} else {
		hostScope, hostScoped := cellClaim.SigningKeys.GetScope(generation.HostSigner)
		keys := hostScoped && reflect.DeepEqual(hostScope, expectedHostScope(cell, generation.HostSigner))
		if issuing {
			accountScope, accountSigner := cellClaim.SigningKeys.GetScope(generation.AccountSigner)
			keys = keys && accountSigner && accountScope == nil
		}
		if generation.RoleSigner != "" {
			roleScope, roleScoped := cellClaim.SigningKeys.GetScope(generation.RoleSigner)
			keys = keys && roleScoped && reflect.DeepEqual(roleScope, roleidentity.Scope(generation.RoleSigner))
		}
		linked := natscell.VerifyLinkScope(cellClaim) == nil
		if !keys || len(cellClaim.SigningKeys) != 1+boolInt(issuing)+boolInt(generation.RoleSigner != "")+boolInt(linked) {
			check.fail("cell.jwt must have exactly the host scope, in v1 the role scope, with controller " +
				"issuers the unscoped account signer, and a link's signer as signing keys")
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
	check.interRegion(generation, files, configs, operator, system, cellClaim)
	if len(check.problems) != 0 {
		return time.Time{}, fmt.Errorf("%w: %s", bootstrap.ErrMaterialGenerationInvalid, strings.Join(check.problems, "; "))
	}
	return check.first, nil
}

// controllerIssuers checks the controller TLS issuer and the account signer.
func (check *generationCheck) controllerIssuers(generation bootstrap.MaterialGeneration, files map[string][]byte,
	roots []*x509.Certificate,
) {
	if issuer, err := controllerIssuer(files["controller-tls-issuer-key.pem"], files["controller-tls-issuer-cert.pem"],
		roots); err != nil {
		check.fail(err.Error())
	} else {
		check.certificate("controller-tls-issuer-cert.pem", issuer)
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
}

// interRegion checks a v1 generation's interregion files (TS-668) or link
// files (TS-803) and the controller configs read supplied:
//   - interregion.jwt is an account of its own, signed by the operator;
//   - interregion-ca.pem holds one to four self-signed CAs, and each slot's
//     leaf TLS is a matching certificate and key, not a CA, that chains to
//     one for server or client use and holds only DNS names under
//     .interregion.terrascale.internal;
//   - a child's leaf-<parent>.creds is a leaf user without permissions of
//     its own, issued by a scoped signing key of another interregion account;
//   - a spoke's link.creds is a link user for its own cell (natscell
//     ValidateLinkCredentialBytes);
//   - each config carries interregion material exactly when interregion.jwt
//     is pinned, and a link exactly when the CA is pinned without it. Its
//     block then passes startup's validation, references only pinned files,
//     by absolute path, pins on each remote the account that issued its
//     credentials, and its contract accepts system.jwt, cell.jwt and
//     interregion.jwt (natscell VerifyClaims: LeafNodeConn 0 and so on); the
//     home's cell.jwt carries the link signer (natscell VerifyLinkScope).
//
// The contract comes from a config, so pinned interregion files need one.
func (check *generationCheck) interRegion(generation bootstrap.MaterialGeneration, files, configs map[string][]byte,
	operator *jwt.OperatorClaims, system, cellClaim *jwt.AccountClaims,
) {
	pinned := map[string]bool{}
	for _, secret := range generation.Secrets {
		pinned[secret.TargetFile] = true
	}
	var interregion *jwt.AccountClaims
	if pinned["interregion.jwt"] {
		claim, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(files["interregion.jwt"])))
		if err != nil || claim.Issuer != generation.Operator || operator == nil || !operator.DidSign(claim) ||
			!nkeys.IsValidPublicAccountKey(claim.Subject) || slices.Contains([]string{generation.SystemAccount,
			generation.CellAccount, generation.HostSigner, generation.AccountSigner, generation.RoleSigner}, claim.Subject) {
			check.fail("interregion.jwt is not an interregion account signed by the operator")
		} else {
			interregion = claim
			check.jwt("interregion.jwt", claim.IssuedAt, claim.Expires)
		}
	}
	if pinned["interregion-ca.pem"] {
		roots := x509.NewCertPool()
		for _, ca := range check.bundle("interregion-ca.pem", files["interregion-ca.pem"]) {
			roots.AddCert(ca)
		}
		// Another slot's pair is absent; half a pair fails as a mismatch.
		for _, slot := range generation.ControllerSlots {
			if cert, key := bootstrap.InterRegionTLSFiles(slot); files[cert] != nil || files[key] != nil {
				check.interRegionLeaf(cert, files[cert], files[key], roots)
			}
		}
	}
	if pinned[bootstrap.LinkCredentialsFile] {
		data := files[bootstrap.LinkCredentialsFile]
		if err := natscell.ValidateLinkCredentialBytes(data, strings.ToLower(string(generation.Cell))); err != nil {
			check.fail(bootstrap.LinkCredentialsFile + ": " + err.Error())
		} else if raw, err := jwt.ParseDecoratedJWT(data); err == nil {
			if user, err := jwt.DecodeUserClaims(raw); err == nil {
				check.jwt(bootstrap.LinkCredentialsFile, user.IssuedAt, user.Expires)
			}
		}
	}
	leafAccounts := map[string]string{}
	for name := range pinned {
		if strings.HasPrefix(name, "leaf-") {
			account, err := check.leafCredentials(name, files[name])
			if err != nil || interregion != nil && account == interregion.Subject {
				check.fail(name + " is not a leaf user of another region's interregion account without permissions of its own")
			}
			leafAccounts[name] = account
		}
	}
	contracts := 0
	for _, slot := range generation.ControllerSlots {
		if files[slot+".creds"] != nil && configs[slot] == nil {
			check.fail(slot + ".creds needs its controller config")
		}
		if data, supplied := configs[slot]; supplied &&
			check.controllerConfig(generation, slot, data, files, pinned, leafAccounts, system, cellClaim, interregion) {
			contracts++
		}
	}
	if pinned["interregion-ca.pem"] && contracts == 0 {
		check.fail("the interregion files need a controller config to check their contract against")
	}
}

// interRegionLeaf checks one slot's interregion leaf certificate and key.
func (check *generationCheck) interRegionLeaf(name string, certPEM, keyPEM []byte, roots *x509.CertPool) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		check.fail(name + " and its key are not a matching certificate and key")
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		check.fail(name + " is not a certificate")
		return
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if intermediate, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(intermediate)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: check.now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}})
	named := len(leaf.IPAddresses) == 0 && len(leaf.URIs) == 0 && len(leaf.EmailAddresses) == 0
	for _, dns := range leaf.DNSNames {
		named = named && strings.HasSuffix(dns, "."+interRegionDomain)
	}
	if err != nil || leaf.IsCA || !named {
		check.fail(name + " is not a leaf of the interregion CA with names only under " + interRegionDomain)
	}
	check.certificate(name, leaf)
}

// leafCredentials returns the interregion account that issued a leaf user
// through a scoped signing key, as natscell's remote check requires: no
// permissions or limits of its own, the seed matching the JWT.
func (check *generationCheck) leafCredentials(name string, data []byte) (string, error) {
	raw, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		return "", err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return "", err
	}
	pair, err := nkeys.ParseDecoratedUserNKey(data)
	if err != nil {
		return "", err
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil || public != claim.Subject || !nkeys.IsValidPublicAccountKey(claim.IssuerAccount) ||
		claim.Issuer == claim.IssuerAccount || !claim.HasEmptyPermissions() {
		return "", errors.New("not a scoped leaf user")
	}
	check.jwt(name, claim.IssuedAt, claim.Expires)
	return claim.IssuerAccount, nil
}

// controllerConfig checks one supplied controller config and reports whether
// its interregion contract was applied. app.Config cannot be imported here:
// the nats, global and optional observability blocks are decoded strictly.
func (check *generationCheck) controllerConfig(generation bootstrap.MaterialGeneration, slot string, data []byte,
	files map[string][]byte, pinned map[string]bool, leafAccounts map[string]string, system, cellClaim, interregion *jwt.AccountClaims,
) bool {
	name := "controller-" + slot + ".json"
	var top map[string]jsontext.Value
	var version int
	var nats natscell.Config
	if protocol.DecodeStrict(data, &top, bootstrap.MaxControllerConfigBytes) != nil ||
		protocol.DecodeStrict(top["version"], &version, bootstrap.MaxControllerConfigBytes) != nil || version != 1 || top["controller"] == nil ||
		top["nats"] == nil || protocol.DecodeStrict(top["nats"], &nats, bootstrap.MaxControllerConfigBytes) != nil {
		check.fail(name + " is not a controller config")
		return false
	}
	if data := top["observability"]; data != nil {
		var telemetry observability.Config
		if protocol.DecodeStrict(data, &telemetry, bootstrap.MaxControllerConfigBytes) != nil || telemetry.Validate() != nil {
			check.fail(name + " has invalid observability settings")
			return false
		}
	}
	var ir *natscell.InterRegion
	var link *natscell.Link
	if nats.Embedded != nil {
		ir, link = nats.Embedded.InterRegion, nats.Embedded.Link
	}
	home, err := ir.GlobalControlHome(nats.Cell)
	if err != nil {
		check.fail(name + " has an invalid global home: " + err.Error())
		return false
	}
	if link != nil {
		home = natscell.LinkHome
	}
	var controller map[string]jsontext.Value
	if protocol.DecodeStrict(top["controller"], &controller, bootstrap.MaxControllerConfigBytes) != nil {
		check.fail(name + " has no controller settings")
		return false
	}
	if data := controller["global"]; data != nil {
		var global struct {
			Home string `json:"home"`
		}
		if protocol.DecodeStrict(data, &global, bootstrap.MaxControllerConfigBytes) != nil {
			check.fail(name + " has invalid global controller settings")
			return false
		}
		if global.Home != "" && global.Home != home {
			check.fail(name + " has a global home inconsistent with its interregion topology")
			return false
		}
	}
	if credsName := slot + ".creds"; pinned[credsName] {
		if nats.Cell != strings.ToLower(string(generation.Cell)) || nats.Instance != slot ||
			nats.CredentialsFile != filepath.Join(bootstrap.MaterialDirectory, credsName) || files[credsName] == nil {
			check.fail(credsName + " must be present and referenced at its installed path by its own cell and slot's config")
			return false
		}
		var peers []string
		if ir != nil {
			peers = ir.Peers
		}
		if err := CheckControllerObservabilityCredentials(files[credsName], nats.Cell, slot, generation.CellAccount, peers, home == nats.Cell); err != nil {
			check.fail(credsName + ": " + err.Error())
		} else if raw, err := jwt.ParseDecoratedJWT(files[credsName]); err == nil {
			claim, err := jwt.DecodeUserClaims(raw)
			if err != nil {
				check.fail(credsName + ": " + err.Error())
			} else {
				check.jwt(credsName, claim.IssuedAt, claim.Expires)
			}
		}
		if home == nats.Cell {
			if err := natscell.ValidateGlobalControllerCredentialBytes(files[credsName]); err != nil {
				check.fail(credsName + ": " + err.Error())
			}
		}
	}
	if (ir != nil) != pinned["interregion.jwt"] || (link != nil) != (pinned["interregion-ca.pem"] && !pinned["interregion.jwt"]) {
		check.fail(name + " must reference interregion or link material exactly when the generation pins its files")
		return false
	} else if link != nil {
		return check.link(generation, slot, name, nats, pinned, cellClaim)
	} else if ir == nil {
		return false
	}
	contract, links, err := ir.Contract(nats.Cell)
	if err != nil || nats.Cell != strings.ToLower(string(generation.Cell)) {
		check.fail(name + " has no valid interregion block for this cell")
		return false
	}
	if system != nil && cellClaim != nil && interregion != nil {
		if err := contract.VerifyClaims(system, cellClaim, interregion, links); err != nil {
			check.fail("system.jwt, cell.jwt and interregion.jwt fail the interregion contract of " + name + ": " + err.Error())
		}
	}
	cert, key := bootstrap.InterRegionTLSFiles(slot)
	file := func(path, want string) bool {
		return path == filepath.Join(bootstrap.MaterialDirectory, want) && pinned[want]
	}
	tlsFiles := func(files natscell.TLSFiles) bool {
		return file(files.CAFile, "interregion-ca.pem") && file(files.CertFile, cert) && file(files.KeyFile, key)
	}
	pinnedOnly := file(ir.AccountJWTFile, "interregion.jwt") && file(nats.Embedded.CellJWTFile, "cell.jwt") &&
		file(nats.Embedded.SystemJWTFile, "system.jwt") && (ir.Listen == nil || tlsFiles(ir.Listen.TLS))
	dialed := map[string]bool{}
	for _, remote := range ir.Remotes {
		creds := "leaf-" + remote.Peer + ".creds"
		pinnedOnly = pinnedOnly && tlsFiles(remote.TLS) && file(remote.CredentialsFile, creds) &&
			remote.PeerAccount == leafAccounts[creds]
		dialed[creds] = true
	}
	for creds := range leafAccounts {
		pinnedOnly = pinnedOnly && dialed[creds]
	}
	if !pinnedOnly {
		check.fail(name + "'s interregion block references a file this generation does not pin, " +
			"or a remote account that did not issue its credentials")
	}
	return true
}

// link checks one config's link block: only pinned files, by absolute path,
// the slot's own leaf TLS, link.creds exactly on a spoke, and on the home a
// cell.jwt that carries the link signer.
func (check *generationCheck) link(generation bootstrap.MaterialGeneration, slot, name string, nats natscell.Config,
	pinned map[string]bool, cellClaim *jwt.AccountClaims,
) bool {
	if nats.Cell != strings.ToLower(string(generation.Cell)) {
		check.fail(name + " has no valid link block for this cell")
		return false
	}
	file := func(path, want string) bool {
		return path == filepath.Join(bootstrap.MaterialDirectory, want) && pinned[want]
	}
	link := nats.Embedded.Link
	cert, key := bootstrap.InterRegionTLSFiles(slot)
	credentials := link.CredentialsFile == "" && !pinned[bootstrap.LinkCredentialsFile]
	if nats.Cell != natscell.LinkHome {
		credentials = file(link.CredentialsFile, bootstrap.LinkCredentialsFile)
	}
	if !credentials || !file(link.TLS.CAFile, "interregion-ca.pem") || !file(link.TLS.CertFile, cert) ||
		!file(link.TLS.KeyFile, key) || !file(nats.Embedded.CellJWTFile, "cell.jwt") || !file(nats.Embedded.SystemJWTFile, "system.jwt") {
		check.fail(name + "'s link block references a file this generation does not pin, or link credentials on the home")
	}
	if nats.Cell == natscell.LinkHome && cellClaim != nil {
		if err := natscell.VerifyLinkScope(cellClaim); err != nil {
			check.fail("cell.jwt fails the link home check of " + name + ": " + err.Error())
		}
	}
	return true
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

// bundle parses one to four self-signed CAs.
func (check *generationCheck) bundle(name string, data []byte) []*x509.Certificate {
	var roots []*x509.Certificate
	for rest := data; ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			if len(strings.TrimSpace(string(rest))) != 0 {
				check.fail(name + " has trailing data that is not a certificate")
			}
			break
		}
		ca, err := x509.ParseCertificate(block.Bytes)
		if block.Type != "CERTIFICATE" || err != nil || !ca.IsCA || !ca.BasicConstraintsValid ||
			ca.KeyUsage&x509.KeyUsageCertSign == 0 || ca.CheckSignatureFrom(ca) != nil {
			check.fail(name + " holds something other than a self-signed CA")
			continue
		}
		check.certificate(name, ca)
		roots = append(roots, ca)
	}
	if len(roots) == 0 || len(roots) > 4 {
		check.fail(name + " must hold one to four CAs")
	}
	return roots
}

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
