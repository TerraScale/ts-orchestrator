package provider

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// The certificate reconciler creates and repairs each Region's TLS
// certificates (estate Region.Certificates: member-control for the
// <region>.api hostnames) through the OCI Certificates management service
// (20210224). Certificates are issued by the owner's private CA and renewed
// as new versions under the same OCID, so consumers never rebind.
//
// The reconciler only observes and converges certificate metadata — names,
// subject alternative names, and expiry. Private keys and certificate
// contents stay inside OCI; renewal versions are requested, never imported.
// Renewal actions carry a reason (SAN drift, expiry window, expired) so plan
// summaries and drills can tell an expiry repair from routine rotation.
// Like the vault reconciler, a FAILED certificate needs an owner decision
// and is refused loudly instead of retried into CA quota.

// certHostnamePattern mirrors the estate's hostname rule for DNS names.
var certHostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// certificateValidityDays is the lifetime requested for each issued version.
// With the declared 30-day renewal window this rotates versions roughly
// every two months; the window, not this constant, drives renewal timing.
const certificateValidityDays = 90

// certificateListBound caps one observation pass. A Region declares a
// handful of certificates; a compartment listing beyond this is a surprise
// worth failing on, not silently truncating.
const certificateListBound = 128

// CertDisplayName derives the deterministic certificate display name for a
// Region. The compartment is tenancy-global, so the Region code keeps names
// unambiguous across regions sharing one compartment.
func CertDisplayName(regionCode, certName string) string {
	return "terrascale-" + regionCode + "-" + certName
}

type ObservedCert struct {
	ID             string
	DisplayName    string
	LifecycleState string
	DNSNames       []string
	ExpiresAtUnix  int64
}

type CertsObserved struct {
	Certs []ObservedCert
}

// CertGateway is the OCI Certificates management seam for certificate
// reconciliation. Renewal creates a new version under the same certificate
// OCID; the authority that issues versions is fixed at gateway construction.
type CertGateway interface {
	ListCertificates(ctx context.Context) ([]ObservedCert, error)
	CreateCertificate(ctx context.Context, displayName string, dnsNames []string) (ObservedCert, error)
	RenewCertificate(ctx context.Context, certID string, dnsNames []string) (ObservedCert, error)
}

type CreateCertificateAction struct {
	Name        string
	DisplayName string
	DNSNames    []string
}

func (a CreateCertificateAction) Kind() OCIActionKind { return OCIActionCreateCertificate }
func (a CreateCertificateAction) Summary() string     { return "create certificate " + a.DisplayName }

// RenewReason is why a renewal is planned. It is the repair signal: plan
// summaries, bootstrap output, and drills (I-9: expire a certificate) key on
// it to tell an expiry repair from routine rotation or SAN drift.
type RenewReason string

const (
	// RenewReasonDrift: the observed SAN set no longer equals the
	// declaration; the new version restores exact coverage.
	RenewReasonDrift RenewReason = "san-drift"
	// RenewReasonWindow: the current version expires inside the declared
	// renewal window; rotation is routine.
	RenewReasonWindow RenewReason = "expiry-window"
	// RenewReasonExpired: the current version has already expired. The
	// renewal is repair (GOAL self-healing: expired certificates rotate),
	// and consumers keep serving on the prior version only until it lands.
	RenewReasonExpired RenewReason = "expired"
)

type RenewCertificateAction struct {
	CertID      string
	DisplayName string
	DNSNames    []string
	Reason      RenewReason
}

func (a RenewCertificateAction) Kind() OCIActionKind { return OCIActionRenewCertificate }
func (a RenewCertificateAction) Summary() string {
	return "renew certificate " + a.DisplayName + " (" + string(a.Reason) + ")"
}

// CertReconciler converges one Region's certificates toward the declaration.
// Now is an optional clock for expiry tests; it defaults to time.Now.
type CertReconciler struct {
	Gateway CertGateway
	Now     func() time.Time
}

var _ OCIReconciler[estate.Region, CertsObserved] = (*CertReconciler)(nil)

func (r *CertReconciler) now() time.Time {
	if r != nil && r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *CertReconciler) Observe(ctx context.Context, declared estate.Region) (CertsObserved, error) {
	if r == nil || r.Gateway == nil {
		return CertsObserved{}, &InvalidOperationError{Message: "certificate reconciler is unavailable"}
	}
	if ctx == nil {
		return CertsObserved{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return CertsObserved{}, err
	}
	certs, err := r.Gateway.ListCertificates(ctx)
	if err != nil {
		return CertsObserved{}, err
	}
	observed := CertsObserved{}
	seen := make(map[string]bool, len(certs))
	for _, cert := range certs {
		if cert.LifecycleState == "DELETED" || cert.LifecycleState == "DELETING" {
			continue
		}
		if seen[cert.DisplayName] {
			return CertsObserved{}, &InvalidDataError{Message: "multiple certificates share the display name " + cert.DisplayName}
		}
		seen[cert.DisplayName] = true
		observed.Certs = append(observed.Certs, cert)
	}
	return observed, nil
}

func (r *CertReconciler) Reconcile(ctx context.Context, declared estate.Region, observed CertsObserved) (OCIPlan, error) {
	if ctx == nil {
		return OCIPlan{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return OCIPlan{}, err
	}
	byName := make(map[string]ObservedCert, len(observed.Certs))
	for _, cert := range observed.Certs {
		if _, dup := byName[cert.DisplayName]; dup {
			return OCIPlan{}, &InvalidDataError{Message: "multiple certificates share the display name " + cert.DisplayName}
		}
		byName[cert.DisplayName] = cert
	}
	plan := OCIPlan{}
	// Region certificate coverage must be unambiguous: when two declared
	// certificates cover the same hostname, consumers cannot tell which one
	// serves it and independent renewals would flap. Exact hostnames only —
	// wildcards are not declarable here.
	coveredBy := make(map[string]string)
	for _, declaredCert := range declared.Certificates {
		if declaredCert.RenewBeforeHours == 0 || len(declaredCert.DNSNames) == 0 {
			return OCIPlan{}, &errs.Argument{Message: "declared certificate " + declaredCert.Name + " has no renewal window or DNS names"}
		}
		if err := validateCertDNSNames(declaredCert.DNSNames); err != nil {
			return OCIPlan{}, err
		}
		for _, name := range declaredCert.DNSNames {
			if other, dup := coveredBy[name]; dup {
				return OCIPlan{}, &errs.Argument{Message: "declared certificates " + other + " and " + declaredCert.Name + " both cover " + name + "; hostname coverage must be unambiguous"}
			}
			coveredBy[name] = declaredCert.Name
		}
		display := CertDisplayName(declared.Code, declaredCert.Name)
		observedCert, exists := byName[display]
		if !exists {
			plan.Actions = append(plan.Actions, CreateCertificateAction{Name: declaredCert.Name, DisplayName: display, DNSNames: append([]string(nil), declaredCert.DNSNames...)})
			continue
		}
		switch observedCert.LifecycleState {
		case "ACTIVE":
		case "CREATING", "UPDATING":
			// Issuance or renewal is in flight; the next pass observes the
			// settled version.
			continue
		case "FAILED":
			// Failed issuance needs an owner decision: blind retries burn
			// CA quota and can mask a compromised chain.
			return OCIPlan{}, &InvalidDataError{Message: "observed certificate " + display + " failed issuance and needs an owner decision"}
		default:
			return OCIPlan{}, &InvalidDataError{Message: "observed certificate " + display + " lifecycle is unknown"}
		}
		if !sameCertDNSNames(observedCert.DNSNames, declaredCert.DNSNames) {
			plan.Actions = append(plan.Actions, RenewCertificateAction{CertID: observedCert.ID, DisplayName: display, DNSNames: append([]string(nil), declaredCert.DNSNames...), Reason: RenewReasonDrift})
			continue
		}
		if observedCert.ExpiresAtUnix <= 0 {
			return OCIPlan{}, &InvalidDataError{Message: "observed certificate " + display + " has no expiry evidence"}
		}
		windowSeconds := uint64(declaredCert.RenewBeforeHours) * 3600
		remaining := observedCert.ExpiresAtUnix - r.now().Unix()
		if remaining <= int64(windowSeconds) {
			reason := RenewReasonWindow
			if remaining <= 0 {
				reason = RenewReasonExpired
			}
			plan.Actions = append(plan.Actions, RenewCertificateAction{CertID: observedCert.ID, DisplayName: display, DNSNames: append([]string(nil), declaredCert.DNSNames...), Reason: reason})
		}
	}
	return plan, nil
}

func (r *CertReconciler) Apply(ctx context.Context, declared estate.Region, observed CertsObserved, plan OCIPlan) error {
	if r == nil || r.Gateway == nil {
		return &InvalidOperationError{Message: "certificate reconciler is unavailable"}
	}
	if ctx == nil {
		return &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	byName := make(map[string]ObservedCert, len(observed.Certs))
	for _, cert := range observed.Certs {
		byName[cert.DisplayName] = cert
	}
	for _, action := range plan.Actions {
		switch a := action.(type) {
		case CreateCertificateAction:
			if a.DisplayName != CertDisplayName(declared.Code, a.Name) {
				return &InvalidDataError{Message: "certificate create does not match the declared region and name"}
			}
			if _, exists := byName[a.DisplayName]; exists {
				return &InvalidOperationError{Message: "certificate " + a.DisplayName + " already exists; re-observe before applying"}
			}
			if err := validateCertDNSNames(a.DNSNames); err != nil {
				return err
			}
			if _, err := r.Gateway.CreateCertificate(ctx, a.DisplayName, a.DNSNames); err != nil {
				return err
			}
			byName[a.DisplayName] = ObservedCert{DisplayName: a.DisplayName, DNSNames: a.DNSNames}
		case RenewCertificateAction:
			existing, exists := byName[a.DisplayName]
			if !exists || existing.ID != a.CertID {
				return &InvalidOperationError{Message: "certificate " + a.DisplayName + " changed under the plan; re-observe before applying"}
			}
			if !isOCID(a.CertID, "certificate") {
				return &errs.Argument{Message: "certificate renew requires a certificate identity"}
			}
			switch a.Reason {
			case RenewReasonDrift, RenewReasonWindow, RenewReasonExpired:
			default:
				return &InvalidOperationError{Message: "certificate renewal for " + a.DisplayName + " carries no reason; re-observe before applying"}
			}
			if err := validateCertDNSNames(a.DNSNames); err != nil {
				return err
			}
			if _, err := r.Gateway.RenewCertificate(ctx, a.CertID, a.DNSNames); err != nil {
				return err
			}
		default:
			return &InvalidOperationError{Message: "certificate reconciler received a foreign action"}
		}
	}
	return nil
}

// sameCertDNSNames reports whether the observed SAN set already equals the
// declaration, ignoring order. Extra names widen the certificate scope, so
// they renew exactly like missing ones.
func sameCertDNSNames(observed, declared []string) bool {
	if len(observed) != len(declared) {
		return false
	}
	remaining := append([]string(nil), observed...)
	for _, name := range declared {
		found := -1
		for i, candidate := range remaining {
			if candidate == name {
				found = i
				break
			}
		}
		if found < 0 {
			return false
		}
		remaining = append(remaining[:found], remaining[found+1:]...)
	}
	return true
}

func validateCertDNSNames(names []string) error {
	if len(names) == 0 || len(names) > 64 {
		return &errs.Argument{Message: "certificate DNS names are invalid"}
	}
	for _, name := range names {
		if len(name) > 253 || !certHostnamePattern.MatchString(name) {
			return &errs.Argument{Message: "certificate DNS name is not a valid hostname: " + name}
		}
	}
	return nil
}

// OCICertificatesGateway is the real Certificates management gateway over
// the signed transport. The issuing CA is owner configuration (O-4): every
// created version is issued by that authority, never imported, so private
// keys are generated and held inside OCI.
type OCICertificatesGateway struct {
	Certs         *OCIHTTPTransport
	CompartmentID string
	AuthorityID   string
	MaxListed     int
}

var _ CertGateway = (*OCICertificatesGateway)(nil)

// NewOCICertificatesGateway validates the transport, compartment scope, and
// issuing authority.
func NewOCICertificatesGateway(certs *OCIHTTPTransport, compartmentID, authorityID string) (*OCICertificatesGateway, error) {
	if certs == nil || certs.Config.Service != OCIServiceCertificates {
		return nil, &errs.Argument{Message: "certificate gateway requires the certificates transport"}
	}
	if !isOCID(compartmentID, "compartment") {
		return nil, &errs.Argument{Message: "certificate gateway requires a compartment identity"}
	}
	if !isOCID(authorityID, "certificateauthority") {
		return nil, &errs.Argument{Message: "certificate gateway requires an issuing authority identity"}
	}
	return &OCICertificatesGateway{Certs: certs, CompartmentID: compartmentID, AuthorityID: authorityID, MaxListed: certificateListBound}, nil
}

type ociCertSummaryDocument struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	LifecycleState string `json:"lifecycleState"`
}

type ociCertSubjectAlternativeName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type ociCertValidity struct {
	TimeOfValidityNotBefore string `json:"timeOfValidityNotBefore"`
	TimeOfValidityNotAfter  string `json:"timeOfValidityNotAfter"`
}

type ociCertDetailDocument struct {
	ID                      string                          `json:"id"`
	Name                    string                          `json:"name"`
	LifecycleState          string                          `json:"lifecycleState"`
	SubjectAlternativeNames []ociCertSubjectAlternativeName `json:"subjectAlternativeNames"`
	TimeExpiresAt           string                          `json:"timeExpiresAt"`
	CurrentVersion          *struct {
		SubjectAlternativeNames []ociCertSubjectAlternativeName `json:"subjectAlternativeNames"`
		Validity                *ociCertValidity                `json:"validity"`
	} `json:"currentVersion"`
}

func (g *OCICertificatesGateway) ListCertificates(ctx context.Context) ([]ObservedCert, error) {
	list, err := g.listCertificateSummaries(ctx)
	if err != nil {
		return nil, err
	}
	certs := make([]ObservedCert, 0, len(list))
	for _, item := range list {
		if !isOCID(item.ID, "certificate") || item.Name == "" {
			return nil, &InvalidDataError{Message: "OCI certificate list response is invalid"}
		}
		var document ociCertDetailDocument
		if err := doOCIJSON(ctx, g.Certs, http.MethodGet, "/20210224/certificates/"+url.PathEscape(item.ID), nil, nil, &document); err != nil {
			return nil, err
		}
		observed, err := observedCert(document)
		if err != nil {
			return nil, err
		}
		certs = append(certs, observed)
	}
	return certs, nil
}

// observedCert reduces a certificate document to the metadata the
// reconciler owns: identity, lifecycle, DNS SANs, and version expiry.
func observedCert(document ociCertDetailDocument) (ObservedCert, error) {
	if !isOCID(document.ID, "certificate") || document.Name == "" {
		return ObservedCert{}, &InvalidDataError{Message: "OCI certificate response is invalid"}
	}
	names := document.SubjectAlternativeNames
	expiry := document.TimeExpiresAt
	if document.CurrentVersion != nil {
		if len(document.CurrentVersion.SubjectAlternativeNames) > 0 {
			names = document.CurrentVersion.SubjectAlternativeNames
		}
		if document.CurrentVersion.Validity != nil && document.CurrentVersion.Validity.TimeOfValidityNotAfter != "" {
			expiry = document.CurrentVersion.Validity.TimeOfValidityNotAfter
		}
	}
	dnsNames := make([]string, 0, len(names))
	for _, name := range names {
		if name.Type != "DNS" || len(name.Value) == 0 || len(name.Value) > 253 || strings.ContainsAny(name.Value, "\r\n\x00 ") {
			return ObservedCert{}, &InvalidDataError{Message: "OCI certificate subject alternative name is invalid"}
		}
		dnsNames = append(dnsNames, name.Value)
	}
	sort.Strings(dnsNames)
	var expiresAt int64
	if expiry != "" {
		parsed, err := time.Parse(time.RFC3339, expiry)
		if err != nil {
			return ObservedCert{}, &InvalidDataError{Message: "OCI certificate expiry is invalid"}
		}
		expiresAt = parsed.Unix()
	}
	if document.LifecycleState == "ACTIVE" && (len(dnsNames) == 0 || expiresAt <= 0) {
		return ObservedCert{}, &InvalidDataError{Message: "OCI active certificate has no usable version evidence"}
	}
	return ObservedCert{ID: document.ID, DisplayName: document.Name, LifecycleState: document.LifecycleState, DNSNames: dnsNames, ExpiresAtUnix: expiresAt}, nil
}

func certRenewalValidity(now time.Time) ociCertValidity {
	return ociCertValidity{
		TimeOfValidityNotBefore: now.UTC().Format(time.RFC3339),
		TimeOfValidityNotAfter:  now.UTC().AddDate(0, 0, certificateValidityDays).Format(time.RFC3339),
	}
}

func certSubjectAlternativeNames(dnsNames []string) []ociCertSubjectAlternativeName {
	names := make([]ociCertSubjectAlternativeName, 0, len(dnsNames))
	for _, name := range dnsNames {
		names = append(names, ociCertSubjectAlternativeName{Type: "DNS", Value: name})
	}
	return names
}

func (g *OCICertificatesGateway) CreateCertificate(ctx context.Context, displayName string, dnsNames []string) (ObservedCert, error) {
	if !validEstateName(displayName) {
		return ObservedCert{}, &errs.Argument{Message: "certificate create request is invalid"}
	}
	if err := validateCertDNSNames(dnsNames); err != nil {
		return ObservedCert{}, err
	}
	var document ociCertDetailDocument
	if err := doOCIJSON(ctx, g.Certs, http.MethodPost, "/20210224/certificates", struct {
		CompartmentID              string                          `json:"compartmentId"`
		Name                       string                          `json:"name"`
		CertificateConfigType      string                          `json:"certificateConfigType"`
		CertificateProfileType     string                          `json:"certificateProfileType"`
		IssuerCertificateAuthority string                          `json:"issuerCertificateAuthorityId"`
		Subject                    map[string]string               `json:"subject"`
		SubjectAlternativeNames    []ociCertSubjectAlternativeName `json:"subjectAlternativeNames"`
	}{CompartmentID: g.CompartmentID, Name: displayName, CertificateConfigType: "ISSUED_BY_INTERNAL_CA",
		CertificateProfileType: "TLS_SERVER", IssuerCertificateAuthority: g.AuthorityID,
		Subject: map[string]string{"commonName": dnsNames[0]}, SubjectAlternativeNames: certSubjectAlternativeNames(dnsNames)}, nil, &document); err != nil {
		return ObservedCert{}, err
	}
	return observedCert(document)
}

// RenewCertificate requests a new version under the same certificate OCID,
// carrying the declared SAN set and a fresh validity window. Consumers keep
// the same OCID, so rotation needs no rebinding.
func (g *OCICertificatesGateway) RenewCertificate(ctx context.Context, certID string, dnsNames []string) (ObservedCert, error) {
	if !isOCID(certID, "certificate") {
		return ObservedCert{}, &errs.Argument{Message: "certificate renew requires a certificate identity"}
	}
	if err := validateCertDNSNames(dnsNames); err != nil {
		return ObservedCert{}, err
	}
	now := time.Now()
	validity := certRenewalValidity(now)
	var document ociCertDetailDocument
	if err := doOCIJSON(ctx, g.Certs, http.MethodPut, "/20210224/certificates/"+url.PathEscape(certID), struct {
		CertificateConfigType   string                          `json:"certificateConfigType"`
		Subject                 map[string]string               `json:"subject"`
		SubjectAlternativeNames []ociCertSubjectAlternativeName `json:"subjectAlternativeNames"`
		Validity                ociCertValidity                 `json:"validity"`
	}{CertificateConfigType: "ISSUED_BY_INTERNAL_CA",
		Subject: map[string]string{"commonName": dnsNames[0]}, SubjectAlternativeNames: certSubjectAlternativeNames(dnsNames), Validity: validity}, nil, &document); err != nil {
		return ObservedCert{}, err
	}
	return observedCert(document)
}
