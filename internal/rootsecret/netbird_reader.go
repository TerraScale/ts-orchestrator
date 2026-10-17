package rootsecret

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const NetBirdBrokerMaterialLimit = 16 << 10

// Address is an untrusted mesh locator. ServerName is the original source's
// signed controller slot and is authenticated by the pinned TLS issuer.
type NetBirdBrokerEndpoint struct {
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
}

// NetBirdBrokerMaterial is encoded only for the exact regional Vault secret.
// Formatting hides the entire payload, including all leaf and user keys.
type NetBirdBrokerMaterial struct {
	Schema          int                     `json:"schema"`
	InstallationID  string                  `json:"installation_id"`
	DeploymentID    string                  `json:"deployment_id"`
	Environment     string                  `json:"environment"`
	Cell            string                  `json:"cell"`
	GrantSHA256     string                  `json:"grant_sha256"`
	TemplateSHA256  string                  `json:"template_sha256"`
	SourceSHA256    string                  `json:"source_sha256"`
	InventorySHA256 string                  `json:"inventory_sha256"`
	StartupSHA256   string                  `json:"startup_sha256"`
	StartupSlot     string                  `json:"startup_slot"`
	ManagerInstance string                  `json:"manager_instance"`
	ManagerStore    string                  `json:"manager_store"`
	RecipientSHA256 string                  `json:"recipient_sha256"`
	Endpoints       []NetBirdBrokerEndpoint `json:"endpoints"`
	Credentials     []byte                  `json:"credentials"`
	CA              []byte                  `json:"ca"`
	Operator        []byte                  `json:"operator"`
	Account         []byte                  `json:"account"`
	Certificate     []byte                  `json:"certificate"`
	Key             []byte                  `json:"key"`
	IssuedAt        time.Time               `json:"issued_at"`
	ExpiresAt       time.Time               `json:"expires_at"`
}

func (NetBirdBrokerMaterial) String() string     { return "NetBird broker material [redacted]" }
func (m NetBirdBrokerMaterial) GoString() string { return m.String() }

func (m NetBirdBrokerMaterial) Encode() ([]byte, error) {
	wire, err := json.Marshal(m)
	if err != nil || len(wire) == 0 || len(wire) > NetBirdBrokerMaterialLimit {
		clear(wire)
		return nil, ErrDelivery
	}
	return wire, nil
}

func DecodeNetBirdBrokerMaterial(wire []byte) (NetBirdBrokerMaterial, error) {
	var m NetBirdBrokerMaterial
	if len(wire) == 0 || len(wire) > NetBirdBrokerMaterialLimit || json.Unmarshal(wire, &m, json.RejectUnknownMembers(true)) != nil {
		return NetBirdBrokerMaterial{}, ErrDelivery
	}
	return m, nil
}

func NetBirdBrokerRef(source NetBirdBrokerSource) vaultsecret.Ref {
	return vaultsecret.Ref{Vault: source.source.Template().VaultTarget().VaultOCID, Name: strings.ToLower(string(source.source.Manifest().Cell)) + "-1-netbird-broker"}
}

func NetBirdRecipientDigest(recipient region.VerifiedNetBirdManagerRecipient) string {
	target := recipient.VaultTarget()
	wire, _ := json.Marshal([]string{recipient.InstallationID(), recipient.GrantDigest(), recipient.InstanceID(), recipient.PrivateIP(), recipient.StoreGeneration(), target.CompartmentID, target.VaultID, target.KeyID, recipient.AuthorityExpiresAt().UTC().Format(time.RFC3339Nano)})
	return netBirdDigest(wire)
}

// NewNetBirdBrokerMaterial binds freshly issued leaf material to genuine public
// startup and recipient proofs. It does not publish or grant IAM authority.
func NewNetBirdBrokerMaterial(source NetBirdBrokerSource, recipient region.VerifiedNetBirdManagerRecipient, credentials, cert, key, ca, operator, account []byte) (NetBirdBrokerMaterial, error) {
	manifest := source.startup.Manifest()
	raw, err := jwt.ParseDecoratedJWT(credentials)
	if err != nil {
		return NetBirdBrokerMaterial{}, ErrDelivery
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return NetBirdBrokerMaterial{}, ErrDelivery
	}
	m := NetBirdBrokerMaterial{Schema: 1, InstallationID: source.source.Template().InstallationID(), DeploymentID: manifest.DeploymentID, Environment: manifest.Environment, Cell: string(manifest.Cell),
		GrantSHA256: source.source.Template().GrantDigest(), TemplateSHA256: source.startup.TemplateDigest(), SourceSHA256: source.startup.SourceSHA256(), InventorySHA256: netBirdDigest(source.source.Inventory()),
		StartupSHA256: source.startup.Digest(), StartupSlot: manifest.Slot, ManagerInstance: recipient.InstanceID(), ManagerStore: recipient.StoreGeneration(), RecipientSHA256: NetBirdRecipientDigest(recipient),
		Endpoints: slices.Clone(source.endpoints), Credentials: bytes.Clone(credentials), Certificate: bytes.Clone(cert), Key: bytes.Clone(key), CA: bytes.Clone(ca), Operator: bytes.Clone(operator), Account: bytes.Clone(account),
		IssuedAt: time.Unix(claim.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(claim.Expires, 0).UTC()}
	if _, _, err := CheckNetBirdBrokerMaterial(m, source, recipient, time.Now().UTC()); err != nil {
		return NetBirdBrokerMaterial{}, err
	}
	return m, nil
}

// CheckNetBirdBrokerMaterial authenticates every payload field independently of
// Vault. Callers separately recheck both retained opaque proofs around effects.
func CheckNetBirdBrokerMaterial(m NetBirdBrokerMaterial, s NetBirdBrokerSource, r region.VerifiedNetBirdManagerRecipient, now time.Time) (*tls.Config, string, error) {
	manifest := s.startup.Manifest()
	if !s.source.IsVerified() || !s.startup.IsVerified() || !r.IsVerified() || m.Schema != 1 || m.InstallationID != s.source.Template().InstallationID() || m.InstallationID != r.InstallationID() ||
		m.DeploymentID != manifest.DeploymentID || m.Environment != manifest.Environment || m.Cell != string(manifest.Cell) || m.GrantSHA256 != s.source.Template().GrantDigest() ||
		m.TemplateSHA256 != s.startup.TemplateDigest() || m.SourceSHA256 != s.startup.SourceSHA256() || m.InventorySHA256 != netBirdDigest(s.source.Inventory()) ||
		m.StartupSHA256 != s.startup.Digest() || m.StartupSlot != manifest.Slot || m.ManagerInstance != r.InstanceID() || m.ManagerStore != r.StoreGeneration() || m.RecipientSHA256 != NetBirdRecipientDigest(r) ||
		!slices.Equal(m.Endpoints, s.endpoints) || m.IssuedAt.IsZero() || m.IssuedAt.After(now) || !m.IssuedAt.Before(m.ExpiresAt) || !now.Before(m.ExpiresAt) ||
		!now.Before(s.ExpiresAt()) || !now.Before(r.ExpiresAt()) || m.ExpiresAt.After(s.source.AuthorityExpiresAt()) || m.ExpiresAt.After(s.startup.AuthorityExpiresAt()) || m.ExpiresAt.After(r.AuthorityExpiresAt()) {
		return nil, "", ErrDelivery
	}
	for name, wire := range map[string][]byte{"ca.pem": m.CA, "operator.jwt": m.Operator, "cell.jwt": m.Account} {
		if !s.matchesFile(name, wire) {
			return nil, "", ErrDelivery
		}
	}
	operator, err := jwt.DecodeOperatorClaims(strings.TrimSpace(string(m.Operator)))
	if err != nil || operator.Subject != s.record.Public.OperatorNKey || operator.Issuer != operator.Subject || !operator.DidSign(operator) {
		return nil, "", ErrDelivery
	}
	account, err := jwt.DecodeAccountClaims(strings.TrimSpace(string(m.Account)))
	if err != nil || account.Subject != s.record.Public.CellAccountNKey || !operator.DidSign(account) {
		return nil, "", ErrDelivery
	}
	scope, ok := account.SigningKeys.GetScope(s.record.Public.ControllerAccountSignerNKey)
	if !ok || scope != nil {
		return nil, "", ErrDelivery
	}
	validation := jwt.CreateValidationResults()
	operator.Validate(validation)
	account.Validate(validation)
	if validation.IsBlocking(true) || operator.Expires == 0 || account.Expires == 0 || m.ExpiresAt.After(time.Unix(operator.Expires, 0)) || m.ExpiresAt.After(time.Unix(account.Expires, 0)) ||
		bootstrapmaterial.CheckNetBirdReadCredentials(m.Credentials, strings.ToLower(m.Cell), s.record.Public.CellAccountNKey, s.record.Public.ControllerAccountSignerNKey, m.ExpiresAt, now) != nil {
		return nil, "", ErrDelivery
	}
	raw, err := jwt.ParseDecoratedJWT(m.Credentials)
	if err != nil {
		return nil, "", ErrDelivery
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil || !m.ExpiresAt.Equal(time.Unix(claim.Expires, 0)) || !m.IssuedAt.Equal(time.Unix(claim.IssuedAt, 0)) {
		return nil, "", ErrDelivery
	}
	pair, err := nkeys.ParseDecoratedUserNKey(m.Credentials)
	if err != nil {
		return nil, "", ErrDelivery
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil || public != claim.Subject {
		return nil, "", ErrDelivery
	}
	certificate, err := tls.X509KeyPair(m.Certificate, m.Key)
	if err != nil || len(certificate.Certificate) != 2 {
		return nil, "", ErrDelivery
	}
	issuer, err := x509.ParseCertificate(certificate.Certificate[1])
	if err != nil || !s.matchesDER("controller-tls-issuer-cert.pem", issuer.Raw) {
		return nil, "", ErrDelivery
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 2 || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		leaf.Subject.CommonName != "terrascale-"+strings.ToLower(m.Cell)+"-netbird-manager" || !slices.Equal(leaf.DNSNames, []string{"netbird-manager"}) || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP(r.PrivateIP())) || len(leaf.URIs)+len(leaf.EmailAddresses) != 0 || leaf.NotAfter.After(m.ExpiresAt) {
		return nil, "", ErrDelivery
	}
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	intermediates.AddCert(issuer)
	if !roots.AppendCertsFromPEM(m.CA) {
		return nil, "", ErrDelivery
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 {
		return nil, "", ErrDelivery
	}
	for _, cert := range chains[0] {
		if cert.NotAfter.Before(m.ExpiresAt) {
			return nil, "", ErrDelivery
		}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}, VerifyConnection: func(state tls.ConnectionState) error {
		if !slices.Contains(manifest.ControllerSlots, state.ServerName) {
			return ErrDelivery
		}
		for _, chain := range state.VerifiedChains {
			if len(chain) >= 2 && bytes.Equal(chain[1].Raw, issuer.Raw) {
				return nil
			}
		}
		return ErrDelivery
	}}, public, nil
}

func (s NetBirdBrokerSource) matchesFile(name string, wire []byte) bool {
	if name == "cell.jwt" {
		file, err := bootstrapmaterial.StartupControllerAccountFile(s.startup)
		return err == nil && file.MaxBytes == int64(len(wire)) && file.SHA256 == netBirdDigest(wire)
	}
	for _, file := range s.record.Files {
		if file.Name == name {
			return file.MaxBytes == int64(len(wire)) && file.SHA256 == netBirdDigest(wire)
		}
	}
	return false
}

func (s NetBirdBrokerSource) matchesDER(name string, der []byte) bool {
	return s.matchesFile(name, pemCertificate(der))
}

// NetBirdReader retains one delivery and one authenticated connection forever.
// Any drift, expiry or disconnect terminates it; reopening needs fresh admission.
type NetBirdReader struct {
	conn     *nats.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	signer   nkeys.KeyPair
	material NetBirdBrokerMaterial
	source   NetBirdBrokerSource
	endpoint NetBirdBrokerEndpoint
	guard    func(context.Context) error
}

func (*NetBirdReader) String() string     { return "NetBird reader [redacted]" }
func (r *NetBirdReader) GoString() string { return r.String() }

// Source is the same independently authenticated regional source retained at open.
func (r *NetBirdReader) Source() NetBirdBrokerSource {
	if r == nil {
		return NetBirdBrokerSource{}
	}
	return r.source
}

func (r *NetBirdReader) Conn() *nats.Conn {
	if r == nil {
		return nil
	}
	return r.conn
}
func (r *NetBirdReader) Context() context.Context {
	if r == nil {
		return nil
	}
	return r.ctx
}

func (r *NetBirdReader) Guard(ctx context.Context) error {
	if r == nil || ctx == nil || ctx.Err() != nil || r.ctx == nil || r.ctx.Err() != nil || r.conn == nil || !r.conn.IsConnected() ||
		r.conn.ConnectedUrl() != strings.Replace(r.endpoint.Address, "tls://", "nats://", 1) || r.guard == nil || r.guard(ctx) != nil {
		if r != nil && r.cancel != nil {
			r.cancel()
			if r.conn != nil {
				r.conn.Close()
			}
		}
		return ErrDelivery
	}
	return nil
}

func (r *NetBirdReader) SignReadOpen(nonce string) (rootoci.NetBirdReadOpen, error) {
	if !entityid.Valid(nonce) || r == nil || r.Guard(r.ctx) != nil {
		return rootoci.NetBirdReadOpen{}, ErrDelivery
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.signer == nil {
		return rootoci.NetBirdReadOpen{}, ErrDelivery
	}
	public, err := r.signer.PublicKey()
	if err != nil {
		return rootoci.NetBirdReadOpen{}, ErrDelivery
	}
	proof := rootoci.NetBirdReadOpen{Schema: 1, Cell: r.material.Cell, User: public, SourceSHA256: r.material.SourceSHA256, Nonce: nonce, ExpiresAt: r.material.ExpiresAt}
	proof.Signature, err = r.signer.Sign(NetBirdReadOpenSigningBytes(proof))
	if err != nil || r.Guard(r.ctx) != nil {
		return rootoci.NetBirdReadOpen{}, ErrDelivery
	}
	return proof, nil
}

func NetBirdReadOpenSigningBytes(proof rootoci.NetBirdReadOpen) []byte {
	wire, _ := json.Marshal([]string{"ts-netbird-read-open-v1", proof.Cell, proof.User, proof.SourceSHA256, proof.Nonce, proof.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	return wire
}

func pemCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func OpenNetBirdReader(ctx context.Context, local region.VerifiedNetBirdManager, cell string) (*NetBirdReader, error) {
	if os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil {
		return nil, ErrDelivery
	}
	deadline := local.ExpiresAt()
	originalCtx, cancelOriginal := context.WithDeadline(ctx, deadline)
	retained := false
	defer func() {
		if !retained {
			cancelOriginal()
		}
	}()
	ctx, cancelOperation := context.WithTimeout(originalCtx, 30*time.Second)
	defer cancelOperation()
	if local.Check(ctx) != nil {
		return nil, ErrDelivery
	}
	for _, name := range ociclient.SecretUnsafeEnv {
		if _, ok := os.LookupEnv(name); ok {
			return nil, ErrDelivery
		}
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, "sa-saopaulo-1")
	if err != nil {
		return nil, ErrDelivery
	}
	source, err := LoadNetBirdBrokerSourceForOperation(ctx, originalCtx, factory, cell, "")
	if err != nil {
		return nil, ErrDelivery
	}
	deadline = minDeadline(deadline, source.ExpiresAt())
	ctx, cancelSource := context.WithDeadline(ctx, deadline)
	defer cancelSource()
	regional, err := factory.ForRegion(source.record.Config.Region)
	if err != nil {
		return nil, ErrDelivery
	}
	recipient, err := region.VerifyNetBirdManagerRecipientForOperation(ctx, originalCtx, regional, source.resolver, source.source)
	if err != nil {
		return nil, ErrDelivery
	}
	deadline = minDeadline(deadline, recipient.ExpiresAt())
	ctx, cancelRecipient := context.WithDeadline(ctx, deadline)
	defer cancelRecipient()
	instance, err := bootstrapstart.NewIMDSClient().FetchInstanceID(ctx)
	if err != nil || instance != recipient.InstanceID() || local.StoreGeneration() != recipient.StoreGeneration() || local.VaultTarget() != recipient.VaultTarget() {
		return nil, ErrDelivery
	}
	client, err := vaultsecret.SecretsClient(regional)
	if err != nil {
		return nil, ErrDelivery
	}
	boundary := func(check context.Context) error {
		if check == nil {
			return ErrDelivery
		}
		check, stop := netBirdReadContext(check, originalCtx, deadline)
		defer stop()
		if check.Err() != nil || originalCtx.Err() != nil || local.Check(check) != nil || source.Guard(check) != nil || recipient.Check(check) != nil {
			return ErrDelivery
		}
		current, err := bootstrapstart.NewIMDSClient().FetchInstanceID(check)
		if err != nil || current != instance || local.StoreGeneration() != recipient.StoreGeneration() || local.VaultTarget() != recipient.VaultTarget() {
			return ErrDelivery
		}
		return check.Err()
	}
	if boundary(ctx) != nil {
		return nil, ErrDelivery
	}
	original, err := vaultsecret.ReadCurrent(ociclient.WithRequestGuard(ctx, boundary), &client, NetBirdBrokerRef(source))
	if err != nil {
		return nil, ErrDelivery
	}
	if !original.ExpiresAt.IsZero() {
		deadline = minDeadline(deadline, original.ExpiresAt)
	}
	ctx, cancelCurrent := context.WithDeadline(ctx, deadline)
	defer cancelCurrent()
	if boundary(ctx) != nil {
		return nil, ErrDelivery
	}
	material, err := DecodeNetBirdBrokerMaterial([]byte(original.Value()))
	if err != nil {
		return nil, ErrDelivery
	}
	deadline = minDeadline(deadline, material.ExpiresAt)
	ctx, cancelMaterial := context.WithDeadline(ctx, deadline)
	defer cancelMaterial()
	if material.StartupSlot != source.startup.Manifest().Slot {
		source, err = source.ForStartupSlot(ctx, material.StartupSlot)
		if err != nil {
			return nil, ErrDelivery
		}
	}
	tlsConfig, _, err := CheckNetBirdBrokerMaterial(material, source, recipient, time.Now().UTC())
	if err != nil {
		return nil, ErrDelivery
	}
	readerCtx, cancelReader := context.WithDeadline(originalCtx, deadline)
	cancel := func() { cancelReader(); cancelOriginal() }
	r := &NetBirdReader{ctx: readerCtx, cancel: cancel, material: material, source: source}
	secretID, secretVersion, secretExpiry := original.ID, original.Version, original.ExpiresAt
	contentDigest := netBirdDigest([]byte(original.Value()))
	r.guard = func(check context.Context) error {
		if check == nil {
			return ErrDelivery
		}
		check, stopReader := netBirdReadContext(check, readerCtx, deadline)
		defer stopReader()
		check, stop := context.WithTimeout(check, 30*time.Second)
		defer stop()
		if readerCtx.Err() != nil || boundary(check) != nil {
			return ErrDelivery
		}
		current, err := vaultsecret.ReadCurrent(ociclient.WithRequestGuard(check, boundary), &client, NetBirdBrokerRef(source))
		if err != nil || current.ID != secretID || current.Version != secretVersion || !current.ExpiresAt.Equal(secretExpiry) || netBirdDigest([]byte(current.Value())) != contentDigest {
			return ErrDelivery
		}
		if _, _, err := CheckNetBirdBrokerMaterial(material, source, recipient, time.Now().UTC()); err != nil {
			return ErrDelivery
		}
		if boundary(check) != nil {
			return ErrDelivery
		}
		return readerCtx.Err()
	}
	connected, err := connectNetBirdReader(ctx, r, tlsConfig)
	if err != nil {
		return nil, err
	}
	retained = true
	return connected, nil
}

// Both strict-v1 and same-CURRENT journal readers use the same single session.
func connectNetBirdReader(ctx context.Context, r *NetBirdReader, tlsConfig *tls.Config) (*NetBirdReader, error) {
	readerCtx := r.ctx
	fail := func() (*NetBirdReader, error) {
		r.cancel()
		if r.conn != nil {
			r.conn.Close()
		}
		if r.signer != nil {
			r.signer.Wipe()
		}
		return nil, ErrDelivery
	}
	if r.guard(ctx) != nil {
		return fail()
	}
	var err error
	r.signer, err = nkeys.ParseDecoratedUserNKey(r.material.Credentials)
	if err != nil {
		return fail()
	}
	// The first authenticated connection is the sole session; never reconnect.
	var connectionCtx context.Context
	for _, endpoint := range r.material.Endpoints {
		if r.guard(ctx) != nil {
			return fail()
		}
		config := tlsConfig.Clone()
		config.ServerName = endpoint.ServerName
		r.conn, connectionCtx, err = natscell.ConnectMemorySingleLeaseForOperation(ctx, readerCtx, strings.ToLower(r.material.Cell), endpoint.Address, r.material.Credentials, config)
		if errors.Is(err, natscell.ErrMemorySessionLost) {
			return fail()
		}
		if err == nil {
			r.endpoint = endpoint
			break
		}
	}
	if err != nil || r.conn == nil {
		return fail()
	}
	r.ctx = connectionCtx
	context.AfterFunc(connectionCtx, r.cancel)
	if r.Guard(ctx) != nil {
		return fail()
	}
	context.AfterFunc(readerCtx, func() { r.conn.Close(); r.mu.Lock(); defer r.mu.Unlock(); r.signer.Wipe() })
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-readerCtx.Done():
				return
			case <-ticker.C:
				if r.Guard(readerCtx) != nil {
					return
				}
			}
		}
	}()
	return r, nil
}
