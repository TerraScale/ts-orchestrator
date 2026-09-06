package keyrotation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/certificates"
	cm "github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"github.com/oracle/oci-go-sdk/v65/common"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// OCIIdentityPrincipal binds each distinct private identity to one consumer.
type OCIIdentityPrincipal struct {
	ID       string `json:"id"`
	SPIFFEID string `json:"spiffe_id"`
	Control  bool   `json:"control"`
}
type OCIIdentityIssuerConfig struct {
	Provider                                      common.ConfigurationProvider
	Region, CompartmentID, CertificateAuthorityID string
	Principals                                    []OCIIdentityPrincipal
	KeyVault                                      security.CapabilityVault
	Authority                                     func(context.Context) error
}
type OCIIdentityIssuer struct {
	config     OCIIdentityIssuerConfig
	management ociIdentityManagement
	retrieval  ociIdentityRetrieval
}

type ociIdentityManagement interface {
	ListCertificates(context.Context, cm.ListCertificatesRequest) (cm.ListCertificatesResponse, error)
	CreateCertificate(context.Context, cm.CreateCertificateRequest) (cm.CreateCertificateResponse, error)
	ScheduleCertificateDeletion(context.Context, cm.ScheduleCertificateDeletionRequest) (cm.ScheduleCertificateDeletionResponse, error)
}
type ociIdentityRetrieval interface {
	GetCertificateBundle(context.Context, certificates.GetCertificateBundleRequest) (certificates.GetCertificateBundleResponse, error)
}

var errOCIIdentity = errors.New("key rotation: OCI identity authority unavailable")

func NewOCIIdentityIssuer(c OCIIdentityIssuerConfig) (*OCIIdentityIssuer, error) {
	if isNil(c.Provider) || c.Region == "" || c.CompartmentID == "" || c.CertificateAuthorityID == "" || c.Authority == nil || isNil(c.KeyVault) || len(c.Principals) == 0 {
		return nil, errOCIIdentity
	}
	if (OCIIdentityIssuerFileConfig{Region: c.Region, CompartmentID: c.CompartmentID, CertificateAuthorityID: c.CertificateAuthorityID, Principals: c.Principals}).Validate() != nil {
		return nil, errOCIIdentity
	}
	m, e := cm.NewCertificatesManagementClientWithConfigurationProvider(c.Provider)
	if e != nil {
		return nil, errOCIIdentity
	}
	r, e := certificates.NewCertificatesClientWithConfigurationProvider(c.Provider)
	if e != nil {
		return nil, errOCIIdentity
	}
	m.SetRegion(c.Region)
	r.SetRegion(c.Region)
	m.HTTPClient = NewOCIAuthorityDispatcher(c.Region, c.Authority)
	r.HTTPClient = NewOCIAuthorityDispatcher(c.Region, c.Authority)
	c.Principals = append([]OCIIdentityPrincipal(nil), c.Principals...)
	return &OCIIdentityIssuer{c, m, r}, nil
}
func identityHash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func identityName(ref string, p OCIIdentityPrincipal) string {
	return "rotation-" + identityHash(ref+"/"+p.ID)
}
func identityMetadata(r security.IdentityRequest, ref, seed string) map[string]string {
	return map[string]string{"rotation-reference": ref, "rotation-generation": strconv.FormatUint(r.Generation, 10), "rotation-not-before": r.NotBefore.UTC().Format(time.RFC3339Nano), "rotation-expires": r.ExpiresAt.UTC().Format(time.RFC3339Nano), "rotation-seed": seed}
}
func (i *OCIIdentityIssuer) lookup(ctx context.Context, ref string, p OCIIdentityPrincipal) (*cm.CertificateSummary, error) {
	if err := i.config.Authority(ctx); err != nil {
		return nil, errOCIIdentity
	}
	noRetry := common.NoRetryPolicy()
	r, e := ociAuthorityCall(ctx, func() (cm.ListCertificatesResponse, error) {
		return i.management.ListCertificates(ctx, cm.ListCertificatesRequest{CompartmentId: new(i.config.CompartmentID), IssuerCertificateAuthorityId: new(i.config.CertificateAuthorityID), Name: new(identityName(ref, p)), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	})
	if e != nil || r.OpcNextPage != nil && *r.OpcNextPage != "" || len(r.Items) > 1 {
		return nil, errOCIIdentity
	}
	if len(r.Items) == 0 {
		return nil, nil
	}
	c := r.Items[0]
	if c.Name == nil || *c.Name != identityName(ref, p) || c.Id == nil || c.CompartmentId == nil || *c.CompartmentId != i.config.CompartmentID || c.IssuerCertificateAuthorityId == nil || *c.IssuerCertificateAuthorityId != i.config.CertificateAuthorityID || c.FreeformTags["rotation-reference"] != ref {
		return nil, errOCIIdentity
	}
	return &c, nil
}
func identityPrivate(seed []byte) (*ecdsa.PrivateKey, error) {
	if len(seed) != 32 {
		return nil, errOCIIdentity
	}
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(seed)
	n := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	d.Mod(d, n)
	d.Add(d, big.NewInt(1))
	x, y := curve.ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}
func (i *OCIIdentityIssuer) Issue(ctx context.Context, r security.IdentityRequest) (security.IdentityMaterial, error) {
	if !validOperationKey(r.OperationID) || !validOperationKey(r.IdempotencyKey) || r.Generation == 0 || r.NotBefore.IsZero() || !r.ExpiresAt.After(r.NotBefore) {
		return security.IdentityMaterial{}, errOCIIdentity
	}
	raw, _ := json.Marshal(struct {
		Request    security.IdentityRequest
		Principals []OCIIdentityPrincipal
		CA         string
	}{r, i.config.Principals, i.config.CertificateAuthorityID})
	ref := "oci-identity:" + identityHash(string(raw))
	for _, p := range i.config.Principals {
		existing, e := i.lookup(ctx, ref, p)
		if e != nil {
			return security.IdentityMaterial{}, e
		}
		if existing != nil {
			continue
		}
		seed, e := i.config.KeyVault.Generate(ctx, security.CapabilityRequest{OperationID: r.OperationID, Generation: r.Generation, Bucket: r.NotBefore.Unix() / int64(security.CapabilityPeriod/time.Second), NotBefore: r.NotBefore, ExpiresAt: r.ExpiresAt, IdempotencyKey: "identity-seed/" + identityHash(ref+"/"+p.ID)})
		if e != nil {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		if seed.Version != r.Generation || !seed.NotBefore.Equal(r.NotBefore) || !seed.ExpiresAt.Equal(r.ExpiresAt) {
			clear(seed.Key)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		key, e := identityPrivate(seed.Key)
		clear(seed.Key)
		if e != nil {
			return security.IdentityMaterial{}, e
		}
		uri, _ := url.Parse(p.SPIFFEID)
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: p.ID}, URIs: []*url.URL{uri}}, key)
		key.D.SetInt64(0)
		if e != nil {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
		if e = i.config.Authority(ctx); e != nil {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		noRetry := common.NoRetryPolicy()
		_, e = ociAuthorityCall(ctx, func() (cm.CreateCertificateResponse, error) {
			return i.management.CreateCertificate(ctx, cm.CreateCertificateRequest{CreateCertificateDetails: cm.CreateCertificateDetails{Name: new(identityName(ref, p)), CompartmentId: new(i.config.CompartmentID), FreeformTags: identityMetadata(r, ref, seed.Reference), CertificateConfig: cm.CreateCertificateManagedExternallyIssuedByInternalCaConfigDetails{IssuerCertificateAuthorityId: new(i.config.CertificateAuthorityID), CsrPem: &csrPEM, Validity: &cm.Validity{TimeOfValidityNotBefore: &common.SDKTime{Time: r.NotBefore.Truncate(time.Second)}, TimeOfValidityNotAfter: &common.SDKTime{Time: r.ExpiresAt.Add(time.Second - time.Nanosecond).Truncate(time.Second)}}}}, OpcRetryToken: new(identityHash(ref + "/" + p.ID)), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		})
		// OCI names are unique within a compartment. A lost create acknowledgement
		// is recovered by the durable provider metadata on the next lookup.
		if e != nil {
			recovered, re := i.lookup(ctx, ref, p)
			if re != nil || recovered == nil {
				return security.IdentityMaterial{}, errOCIIdentity
			}
		}
	}
	// Certificate creation is asynchronous. Keep the operation pending until
	// OCI reports all resources active; cancellation leaves provider receipts
	// available to the next attempt.
	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		ready := true
		for _, p := range i.config.Principals {
			c, err := i.lookup(waitCtx, ref, p)
			if err != nil || c == nil {
				return security.IdentityMaterial{}, errOCIIdentity
			}
			if c.LifecycleState != cm.CertificateLifecycleStateActive {
				if c.LifecycleState != cm.CertificateLifecycleStateCreating {
					return security.IdentityMaterial{}, errOCIIdentity
				}
				ready = false
			}
		}
		if ready {
			return i.Fetch(waitCtx, ref)
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return security.IdentityMaterial{}, errOCIIdentity
		case <-timer.C:
		}
	}
}
func (i *OCIIdentityIssuer) Fetch(ctx context.Context, ref string) (security.IdentityMaterial, error) {
	result := security.IdentityMaterial{Reference: ref}
	workload, control := map[string][]byte{}, map[string][]byte{}
	defer func() {
		for _, b := range workload {
			clear(b)
		}
		for _, b := range control {
			clear(b)
		}
	}()
	if !strings.HasPrefix(ref, "oci-identity:") || len(ref) != 77 {
		return security.IdentityMaterial{}, errOCIIdentity
	}
	for _, p := range i.config.Principals {
		c, e := i.lookup(ctx, ref, p)
		if e != nil || c == nil || c.LifecycleState != cm.CertificateLifecycleStateActive || c.TimeOfDeletion != nil {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		generation, e := strconv.ParseUint(c.FreeformTags["rotation-generation"], 10, 64)
		nb, en := time.Parse(time.RFC3339Nano, c.FreeformTags["rotation-not-before"])
		expiry, ee := time.Parse(time.RFC3339Nano, c.FreeformTags["rotation-expires"])
		if e != nil || en != nil || ee != nil || generation == 0 || !expiry.After(nb) {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		if result.Version == 0 {
			result.Version = generation
			result.NotBefore = nb
			result.ExpiresAt = expiry
		} else if result.Version != generation || !result.NotBefore.Equal(nb) || !result.ExpiresAt.Equal(expiry) {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		seed, e := i.config.KeyVault.Fetch(ctx, c.FreeformTags["rotation-seed"])
		if e != nil {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		if seed.Version != generation || !seed.NotBefore.Equal(nb) || !seed.ExpiresAt.Equal(expiry) {
			clear(seed.Key)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		key, e := identityPrivate(seed.Key)
		clear(seed.Key)
		if e != nil {
			return security.IdentityMaterial{}, e
		}
		private, e := x509.MarshalPKCS8PrivateKey(key)
		key.D.SetInt64(0)
		if e != nil {
			return security.IdentityMaterial{}, errOCIIdentity
		}
		if e = i.config.Authority(ctx); e != nil {
			clear(private)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		noRetry := common.NoRetryPolicy()
		response, e := ociAuthorityCall(ctx, func() (certificates.GetCertificateBundleResponse, error) {
			return i.retrieval.GetCertificateBundle(ctx, certificates.GetCertificateBundleRequest{CertificateId: c.Id, VersionNumber: new(int64(1)), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
		})
		bundle, ok := response.CertificateBundle.(certificates.CertificateBundlePublicOnly)
		if e != nil || !ok || bundle.CertificatePem == nil || bundle.CertChainPem == nil || bundle.CertificateId == nil || *bundle.CertificateId != *c.Id || bundle.VersionNumber == nil || *bundle.VersionNumber != 1 || bundle.RevocationStatus != nil {
			clear(private)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		clear(private)
		pair, e := tls.X509KeyPair([]byte(*bundle.CertificatePem), keyPEM)
		if e != nil || pair.Leaf == nil || len(pair.Leaf.URIs) != 1 || pair.Leaf.URIs[0].String() != p.SPIFFEID || pair.Leaf.NotBefore.After(nb) || pair.Leaf.NotAfter.Before(expiry) {
			clear(keyPEM)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(*bundle.CertChainPem)) {
			clear(keyPEM)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		if _, e = pair.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: nb.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
			clear(keyPEM)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		if result.TrustBundle == nil {
			result.TrustBundle = []byte(*bundle.CertChainPem)
		} else if string(result.TrustBundle) != *bundle.CertChainPem {
			clear(keyPEM)
			return security.IdentityMaterial{}, errOCIIdentity
		}
		combined := append([]byte(*bundle.CertificatePem+"\n"+*bundle.CertChainPem+"\n"), keyPEM...)
		clear(keyPEM)
		if p.Control {
			control[p.ID] = combined
		} else {
			workload[p.ID] = combined
		}
	}
	result.WorkloadTLS, _ = json.Marshal(workload)
	result.ControlTLS, _ = json.Marshal(control)
	return result, nil
}
func (i *OCIIdentityIssuer) Retire(ctx context.Context, ref, idempotencyKey string) error {
	if !validOperationKey(idempotencyKey) || !strings.HasPrefix(ref, "oci-identity:") || len(ref) != 77 {
		return errOCIIdentity
	}
	for _, p := range i.config.Principals {
		c, e := i.lookup(ctx, ref, p)
		if e != nil || c == nil {
			return errOCIIdentity
		}
		if c.TimeOfDeletion == nil {
			if e = i.config.Authority(ctx); e != nil {
				return errOCIIdentity
			}
			noRetry := common.NoRetryPolicy()
			_, e = ociAuthorityCall(ctx, func() (cm.ScheduleCertificateDeletionResponse, error) {
				return i.management.ScheduleCertificateDeletion(ctx, cm.ScheduleCertificateDeletionRequest{CertificateId: c.Id, ScheduleCertificateDeletionDetails: cm.ScheduleCertificateDeletionDetails{}, RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
			})
			if e != nil {
				return errOCIIdentity
			}
		}
		if e = i.config.KeyVault.Retire(ctx, c.FreeformTags["rotation-seed"], idempotencyKey+"/"+identityHash(p.ID)); e != nil {
			return errOCIIdentity
		}
	}
	return nil
}
