// Package functionmaterial prepares and reads task-bound function credentials
// through the existing authority log and OCI Vault.
package functionmaterial

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
)

var ErrMaterial = errors.New("function material is not current for the admitted task and recipient")

// Binding identifies the actual task and admitted host, independently of task labels.
type Binding struct {
	TaskID, ServiceID, NodeID, InstanceID, Region, HostID, Fingerprint string
}

// Recipient is installed from the host's authenticated bootstrap and local node.
type Recipient struct{ NodeID, InstanceID, Region, HostID string }

// PublicTrust contains only verified generation metadata and public broker material.
// Its zero value cannot authorize a delivery.
type PublicTrust struct {
	generation bootstrap.VerifiedMaterialGeneration
	operator   *jwt.OperatorClaims
	brokerCA   []byte
	brokerURL  string
	expiresAt  time.Time
}

func NewPublicTrust(generation bootstrap.VerifiedMaterialGeneration, operatorJWT, brokerCA []byte, brokerURL string) (PublicTrust, error) {
	if generation.Fingerprint() == "" || !time.Now().Before(generation.ExpiresAt()) {
		return PublicTrust{}, ErrMaterial
	}
	gen := generation.Generation()
	pinned := func(name string, value []byte) bool {
		for _, ref := range gen.Secrets {
			if ref.TargetFile == name {
				return len(value) > 0 && int64(len(value)) <= ref.MaxBytes && sum(value) == ref.SHA256
			}
		}
		return false
	}
	operator, err := jwt.DecodeOperatorClaims(strings.TrimSpace(string(operatorJWT)))
	if err != nil || !pinned("operator.jwt", operatorJWT) || !pinned("ca.pem", brokerCA) ||
		operator.Subject != gen.Operator || operator.Issuer != gen.Operator || !operator.DidSign(operator) {
		return PublicTrust{}, ErrMaterial
	}
	validation := jwt.CreateValidationResults()
	operator.Validate(validation)
	if validation.IsBlocking(true) {
		return PublicTrust{}, ErrMaterial
	}
	endpoint, err := url.Parse(brokerURL)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return PublicTrust{}, ErrMaterial
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(brokerCA) {
		return PublicTrust{}, ErrMaterial
	}
	expires := generation.ExpiresAt()
	if operator.Expires != 0 {
		expires = minTime(expires, time.Unix(operator.Expires, 0))
	}
	return PublicTrust{generation: generation, operator: operator, brokerCA: bytes.Clone(brokerCA), brokerURL: brokerURL, expiresAt: expires}, nil
}

type intentReader interface {
	ReadFunctionIntent(context.Context, string, string) (authority.LogEntry, error)
	ReadFunctionGrant(context.Context, string) (authority.LogEntry, error)
}

// Reader holds no controller broker connection or signing key.
type Reader struct {
	Authority          intentReader
	Artifacts          jetstream.ObjectStore
	Roots              func() trust.Keyring
	Accounts           *brokerauth.Store
	Bundles            vaultsecret.BundleClient
	VaultID            string
	Trust              PublicTrust
	Recipient          Recipient
	AuthorizeRecipient func(context.Context, Binding) error
}

type storedMaterial struct {
	Schema          int               `json:"schema"`
	Binding         Binding           `json:"binding"`
	TenantID        string            `json:"tenant_id"`
	FunctionID      string            `json:"function_id"`
	EnvelopeSHA256  string            `json:"envelope_sha256"`
	IntentSequence  uint64            `json:"intent_sequence"`
	AccountSequence uint64            `json:"account_sequence"`
	Generation      string            `json:"generation"`
	ExpiresAt       time.Time         `json:"expires_at"`
	Files           map[string][]byte `json:"files"`
}

// VerifiedDelivery is constructed only after current intent, recipient grant,
// exact Vault readback and narrow credential checks all agree.
type VerifiedDelivery struct {
	binding  Binding
	function release.VerifiedFunction
	minimum  uint64
	expires  time.Time
	files    map[string][]byte
}

func (delivery VerifiedDelivery) Binding() Binding                   { return delivery.binding }
func (delivery VerifiedDelivery) Function() release.VerifiedFunction { return delivery.function }
func (delivery VerifiedDelivery) MinimumSequence() uint64            { return delivery.minimum }
func (delivery VerifiedDelivery) ExpiresAt() time.Time               { return delivery.expires }
func (delivery VerifiedDelivery) Valid() bool {
	return delivery.function.Valid() && time.Now().Before(delivery.expires) && len(delivery.files) == 10
}
func (delivery VerifiedDelivery) Files() map[string][]byte {
	files := make(map[string][]byte, len(delivery.files))
	for name, value := range delivery.files {
		files[name] = bytes.Clone(value)
	}
	return files
}

func sum(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func secretRef(vault string, binding Binding) (vaultsecret.Ref, error) {
	if err := bindingGrant(binding, strings.Repeat("a", 64)).Validate(); err != nil {
		return vaultsecret.Ref{}, ErrMaterial
	}
	region, known := catalog.CellForOCIRegion(binding.Region)
	if !known {
		return vaultsecret.Ref{}, ErrMaterial
	}
	wire, err := json.Marshal(binding)
	if err != nil {
		return vaultsecret.Ref{}, err
	}
	return vaultsecret.Ref{Vault: vault, Name: region.Name() + "-function-worker-" + sum(wire)}, nil
}

func (reader Reader) currentAccount(ctx context.Context, proof release.VerifiedFunction) (brokerauth.Claim, error) {
	if reader.Accounts == nil || reader.Trust.operator == nil || !time.Now().Before(reader.Trust.expiresAt) || !proof.Valid() {
		return brokerauth.Claim{}, ErrMaterial
	}
	generation := reader.Trust.generation.Generation()
	claim := proof.Claim()
	if claim.Environment != generation.Environment || claim.Cell != string(generation.Cell) {
		return brokerauth.Claim{}, ErrMaterial
	}
	account, err := reader.Accounts.Read(ctx, generation.CellAccount)
	if err != nil {
		return brokerauth.Claim{}, err
	}
	decoded, err := brokerauth.DecodeAccountJWT(account.JWT, generation.CellAccount)
	if err != nil || account.Sequence == 0 || account.Account != generation.CellAccount || account.Cell != strings.ToLower(string(generation.Cell)) || !reader.Trust.operator.DidSign(decoded) {
		return brokerauth.Claim{}, ErrMaterial
	}
	scope, registered := decoded.SigningKeys.GetScope(generation.AccountSigner)
	if !registered || scope != nil {
		return brokerauth.Claim{}, ErrMaterial
	}
	return account, nil
}

func verifyTLS(files map[string][]byte, proof release.VerifiedFunction) (time.Time, error) {
	certificate, err := tls.X509KeyPair(files["ingress-cert.pem"], files["ingress-key.pem"])
	if err != nil || len(certificate.Certificate) == 0 {
		return time.Time{}, ErrMaterial
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		return time.Time{}, ErrMaterial
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(files["ingress-ca.pem"]) {
		return time.Time{}, ErrMaterial
	}
	intermediates := x509.NewCertPool()
	for _, der := range certificate.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return time.Time{}, ErrMaterial
		}
		intermediates.AddCert(cert)
	}
	claim := proof.Claim()
	dns := claim.FunctionID + "." + strings.ToLower(claim.TenantID) + ".functions." + strings.ToLower(claim.Cell) + ".terrascale.internal"
	uri := "spiffe://terrascale.tech/tenants/" + claim.TenantID + "/functions/" + claim.FunctionID
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != uri || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != dns || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return time.Time{}, ErrMaterial
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, DNSName: dns, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return time.Time{}, ErrMaterial
	}
	return leaf.NotAfter, nil
}

func bindingGrant(binding Binding, manifest string) authority.FunctionBinding {
	return authority.FunctionBinding{TaskID: binding.TaskID, ServiceID: binding.ServiceID, NodeID: binding.NodeID, InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID, Fingerprint: binding.Fingerprint, MaterialManifestSHA256: manifest}
}

func filesFor(proof release.VerifiedFunction, minimum uint64, roots trust.Keyring, material storedMaterial, brokerURL string) (map[string][]byte, error) {
	claim := proof.Claim()
	delegation, err := trust.DecodeEnvelope(proof.Delegation())
	if err != nil {
		return nil, err
	}
	root := roots[delegation.KeyID]
	if len(root) != 32 {
		return nil, ErrMaterial
	}
	deployment, err := json.Marshal(functions.ProcessDeployment{Environment: claim.Environment, Cell: claim.Cell, TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, MinimumSequence: minimum, BrokerURL: brokerURL, ExpiresAt: material.ExpiresAt})
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, 10)
	for name, value := range material.Files {
		files[name] = bytes.Clone(value)
	}
	files["deployment.json"], files["root.pub"], files["module.wasm"] = deployment, bytes.Clone(root), proof.Module()
	files["receipt.json"], files["delegation.json"] = proof.Envelope(), proof.Delegation()
	return files, nil
}
