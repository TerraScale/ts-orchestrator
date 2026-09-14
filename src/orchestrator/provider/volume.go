package provider

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

const BytesPerGiB uint64 = 1 << 30

type VolumeObservation struct {
	VolumeId      ProviderResourceId
	CompartmentId ProviderCompartmentId
	Size          ProviderByteCount
	ETag          string
}
type VolumeReadRequest struct {
	VolumeId      ProviderResourceId
	CompartmentId ProviderCompartmentId
}
type VolumeUpdateRequest struct {
	VolumeId      ProviderResourceId
	CompartmentId ProviderCompartmentId
	NewSize       ProviderByteCount
	IfMatch       string
}
type VolumeTransport interface {
	GetVolume(context.Context, VolumeReadRequest) (*VolumeObservation, error)
	UpdateVolume(context.Context, VolumeUpdateRequest) (*VolumeObservation, error)
}

// HTTPVolumeTransport is the deliberately small OCI Block Volume SDK seam.
// It sends only validated OCIDs and a bounded If-Match fence.
type HTTPVolumeTransport struct{ OCI *OCIHTTPTransport }

func (t HTTPVolumeTransport) GetVolume(ctx context.Context, r VolumeReadRequest) (*VolumeObservation, error) {
	if t.OCI == nil || !isOCID(r.VolumeId.Value, "volume") || !isOCID(r.CompartmentId.Value, "compartment") {
		return nil, &errs.Argument{Message: "volume read identity is invalid"}
	}
	resp, err := t.OCI.Do(ctx, http.MethodGet, "/20160918/volumes/"+url.PathEscape(r.VolumeId.Value), nil)
	if err != nil {
		return nil, err
	}
	return DecodeVolumeResponse(resp)
}
func (t HTTPVolumeTransport) UpdateVolume(ctx context.Context, r VolumeUpdateRequest) (*VolumeObservation, error) {
	if t.OCI == nil || !isOCID(r.VolumeId.Value, "volume") || !isOCID(r.CompartmentId.Value, "compartment") || !isSafeETag(r.IfMatch) || r.NewSize.Value == 0 || r.NewSize.Value%BytesPerGiB != 0 {
		return nil, &errs.Argument{Message: "volume update request is invalid"}
	}
	payload := struct {
		SizeInGBs uint64 `json:"sizeInGBs"`
	}{r.NewSize.Value / BytesPerGiB}
	resp, err := t.OCI.DoWithHeaders(ctx, http.MethodPut, "/20160918/volumes/"+url.PathEscape(r.VolumeId.Value), bytes.NewReader(mustJSON(payload)), map[string]string{"If-Match": r.IfMatch})
	if err != nil {
		return nil, err
	}
	return DecodeVolumeResponse(resp)
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// Compatibility names for callers ported from the C# contracts.
type OciBlockVolumeExpansionAdapter = BlockVolumeExpansionAdapter
type OciBlockVolumeObservation = VolumeObservation
type OciBlockVolumeReadRequest = VolumeReadRequest
type OciBlockVolumeUpdateRequest = VolumeUpdateRequest
type OciBlockVolumeExpansionResult = VolumeExpansionResult
type OciBlockVolumeExpansionOutcome = VolumeExpansionOutcome

const OciBlockVolumeConverged = VolumeConverged
const OciBlockVolumeOutcomeUnknown = VolumeOutcomeUnknown

type VolumeExpansionOutcome int

const (
	VolumeConverged VolumeExpansionOutcome = iota + 1
	VolumeOutcomeUnknown
)

type VolumeExpansionResult struct {
	Outcome        VolumeExpansionOutcome
	IdempotencyKey ProviderIdempotencyKey
	ObservedSize   ProviderByteCount
	ObservedETag   string
	CleanupNone    bool
}
type BlockVolumeExpansionAdapter struct {
	CellId        ProviderCellId
	CompartmentId ProviderCompartmentId
	Transport     VolumeTransport
}

func (s BlockVolumeExpansionAdapter) Expand(ctx context.Context, intent ProviderIntent) (VolumeExpansionResult, error) {
	if ctx == nil {
		return VolumeExpansionResult{}, &errs.Argument{Param: "ctx", Message: "provider context is required"}
	}
	if err := ctx.Err(); err != nil {
		return VolumeExpansionResult{}, err
	}
	x, ok := intent.(ExpandVolumeProviderIntent)
	if !ok {
		return VolumeExpansionResult{}, &InvalidOperationError{Message: "only an ExpandVolumeProviderIntent is accepted"}
	}
	c := x.Context
	if c.ResourceKind != ResourceVolume || c.Action != ActionExpandVolume || c.DesiredTerminalState != TerminalExpanded || c.ExpectedObservedState != ObservedPresent || len(c.PermittedCompensations) != 0 || c.CellId != s.CellId || c.CompartmentId != s.CompartmentId {
		return VolumeExpansionResult{}, &InvalidOperationError{Message: "volume expansion intent is not exact"}
	}
	t, ok := c.Target.(ExistingProviderResource)
	if !ok || !isOCID(t.Id.Value, "volume") || !isOCID(c.CompartmentId.Value, "compartment") || s.Transport == nil {
		return VolumeExpansionResult{}, &InvalidOperationError{Message: "volume expansion target or scope is invalid"}
	}
	req := VolumeReadRequest{t.Id, c.CompartmentId}
	obs, err := s.Transport.GetVolume(ctx, req)
	if err != nil {
		return VolumeExpansionResult{}, err
	}
	if obs == nil {
		return VolumeExpansionResult{Outcome: VolumeOutcomeUnknown, IdempotencyKey: c.IdempotencyKey, CleanupNone: true}, nil
	}
	if obs.VolumeId != t.Id || obs.CompartmentId != c.CompartmentId || obs.Size.Value == 0 || obs.ETag == "" {
		return VolumeExpansionResult{Outcome: VolumeOutcomeUnknown, IdempotencyKey: c.IdempotencyKey, ObservedSize: obs.Size, ObservedETag: obs.ETag, CleanupNone: true}, nil
	}
	target := x.Parameters.NewSize
	if obs.Size.Value == target.Value {
		return converged(c.IdempotencyKey, *obs), nil
	}
	if obs.Size.Value > target.Value {
		return VolumeExpansionResult{}, &InvalidOperationError{Message: "OCI Block Volume shrink requests are not permitted"}
	}
	if err := ctx.Err(); err != nil {
		return VolumeExpansionResult{}, err
	}
	updated, err := s.Transport.UpdateVolume(ctx, VolumeUpdateRequest{t.Id, c.CompartmentId, target, obs.ETag})
	if err == nil && updated != nil && updated.VolumeId == t.Id && updated.CompartmentId == c.CompartmentId && updated.Size.Value >= target.Value && updated.ETag != "" {
		return converged(c.IdempotencyKey, *updated), nil
	}
	if err != nil && !indeterminate(err) {
		return VolumeExpansionResult{Outcome: VolumeOutcomeUnknown, IdempotencyKey: c.IdempotencyKey, ObservedSize: obs.Size, ObservedETag: obs.ETag, CleanupNone: true}, nil
	}
	if err := ctx.Err(); err != nil {
		return VolumeExpansionResult{}, err
	}
	read, readErr := s.Transport.GetVolume(ctx, req)
	if readErr == nil && read != nil && read.VolumeId == t.Id && read.CompartmentId == c.CompartmentId && read.Size.Value >= target.Value && read.ETag != "" {
		return converged(c.IdempotencyKey, *read), nil
	}
	if readErr != nil && ctx.Err() != nil {
		return VolumeExpansionResult{}, ctx.Err()
	}
	if read != nil && read.VolumeId == t.Id && read.CompartmentId == c.CompartmentId {
		return VolumeExpansionResult{Outcome: VolumeOutcomeUnknown, IdempotencyKey: c.IdempotencyKey, ObservedSize: read.Size, ObservedETag: read.ETag, CleanupNone: true}, nil
	}
	return VolumeExpansionResult{Outcome: VolumeOutcomeUnknown, IdempotencyKey: c.IdempotencyKey, ObservedSize: obs.Size, ObservedETag: obs.ETag, CleanupNone: true}, nil
}
func converged(k ProviderIdempotencyKey, o VolumeObservation) VolumeExpansionResult {
	return VolumeExpansionResult{VolumeConverged, k, o.Size, o.ETag, true}
}

var _ BlockVolumeExpansionProvider = BlockVolumeExpansionAdapter{}

func isOCID(v, kind string) bool {
	if len(v) < 12 || len(v) > 255 || !strings.HasPrefix(v, "ocid1."+kind+".") || strings.Count(v, ".") < 3 {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) < 5 || parts[len(parts)-1] == "" || parts[0] != "ocid1" || parts[1] != kind || len(parts[2]) < 3 || !strings.HasPrefix(parts[2], "oc") {
		return false
	}
	for _, r := range parts[2][2:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	regionless := regionlessOCIDKind(kind)
	if (regionless && parts[3] != "") || (!regionless && parts[3] == "") {
		return false
	}
	for index, part := range parts[3:] {
		if part == "" {
			// Only global IAM resources may omit the region. Accepting the
			// regionless form for regional resources weakens service and scope
			// validation because the resulting identifier cannot name a real
			// instance, volume, network, Vault, or key.
			if index != 0 || len(parts) < 5 || !regionlessOCIDKind(kind) {
				return false
			}
			continue
		}
		if !ocidSegmentPattern.MatchString(part) {
			return false
		}
	}
	for _, r := range v {
		if r < 0x21 || r == 0x7f || r == '/' || r == '\\' || r == '?' || r == '#' || r == '%' {
			return false
		}
	}
	return true
}

func regionlessOCIDKind(kind string) bool {
	switch kind {
	case "tenancy", "compartment", "policy", "dynamicgroup":
		return true
	default:
		return false
	}
}
func indeterminate(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, new(*http.ProtocolError)) || errors.As(err, new(*url.Error)) || errors.As(err, new(*ProviderOutcomeUnknownError))
}

var regionPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var ocidSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]*$`)

type OCITransportConfig struct {
	Service      OCIService
	Region       string
	Endpoint     *url.URL
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxRetries   int
}

// OCIService identifies the small set of OCI HTTP authorities used by the
// orchestrator. Keeping it explicit prevents a caller from redirecting signed
// requests to an arbitrary host.
type OCIService string

const (
	OCIServiceCore            OCIService = "core"
	OCIServiceIdentity        OCIService = "identity"
	OCIServiceObjectStorage   OCIService = "object-storage"
	OCIServiceRegistry        OCIService = "registry"
	OCIServiceVault           OCIService = "vault"
	OCIServiceVaultManagement OCIService = "vault-management"
)

func ociServiceHost(service OCIService, region string) (string, bool) {
	switch service {
	case "", OCIServiceCore:
		return "iaas." + region + ".oraclecloud.com", true
	case OCIServiceIdentity:
		return "identity." + region + ".oci.oraclecloud.com", true
	case OCIServiceObjectStorage:
		return "objectstorage." + region + ".oraclecloud.com", true
	case OCIServiceRegistry:
		key, ok := ociRegistryRegionKey(region)
		if !ok {
			return "", false
		}
		return key + ".ocir.io", true
	case OCIServiceVault:
		return "vaults." + region + ".oci.oraclecloud.com", true
	case OCIServiceVaultManagement:
		return "", true
	default:
		return "", false
	}
}

func ociRegistryRegionKey(region string) (string, bool) {
	switch region {
	case "sa-saopaulo-1":
		return "gru", true
	case "us-sanjose-1":
		return "sjc", true
	case "eu-frankfurt-1":
		return "fra", true
	default:
		return "", false
	}
}

func validOCIServiceHost(service OCIService, region, host string) bool {
	expected, ok := ociServiceHost(service, region)
	if !ok {
		return false
	}
	if service != OCIServiceVaultManagement {
		return host == expected
	}
	// OCI Vault management endpoints use the Vault OCID as the first DNS
	// label, followed by the management KMS suffix. Keep the OCID check here
	// so a caller cannot redirect this authority to another arbitrary host.
	suffix := ".management.kms." + region + ".oci.oraclecloud.com"
	prefix := strings.TrimSuffix(host, suffix)
	if prefix == "" || !strings.HasSuffix(host, suffix) || len(prefix) > 128 || prefix[0] == '-' || prefix[len(prefix)-1] == '-' {
		return false
	}
	return true
}

func NewOCITransportConfig(region, endpoint string) (OCITransportConfig, error) {
	return NewOCIServiceTransportConfig(OCIServiceCore, region, endpoint)
}

func NewOCIServiceTransportConfig(service OCIService, region, endpoint string) (OCITransportConfig, error) {
	region = strings.TrimSpace(region)
	if len(region) < 1 || len(region) > 63 || !regionPattern.MatchString(region) {
		return OCITransportConfig{}, &errs.Argument{Message: "configured OCI region is not canonical"}
	}
	_, ok := ociServiceHost(service, region)
	if !ok {
		return OCITransportConfig{}, &errs.Argument{Message: "OCI service is invalid"}
	}
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Opaque != "" || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || u.Host != "iaas."+region+".oraclecloud.com" {
		return OCITransportConfig{}, &errs.Argument{Message: "OCI endpoint is invalid"}
	}
	u.Path = "/"
	if service == "" {
		service = OCIServiceCore
	}
	return OCITransportConfig{Service: service, Region: region, Endpoint: u, Timeout: 30 * time.Second, MaxBodyBytes: 1 << 20, MaxRetries: 2}, nil
}

type RequestSigner interface{ Sign(*http.Request) error }
type OCIHTTPTransport struct {
	Config     OCITransportConfig
	Client     *http.Client
	Signer     RequestSigner
	retryDelay func(context.Context, int) error
}

func NewOCIHTTPTransport(config OCITransportConfig, client *http.Client, signer RequestSigner) (*OCIHTTPTransport, error) {
	_, serviceOK := ociServiceHost(config.Service, config.Region)
	if len(config.Region) < 1 || len(config.Region) > 63 || !regionPattern.MatchString(config.Region) ||
		config.Endpoint == nil || config.Endpoint.Scheme != "https" || config.Endpoint.User != nil ||
		config.Endpoint.RawQuery != "" || config.Endpoint.Fragment != "" ||
		config.Endpoint.Opaque != "" || config.Endpoint.RawPath != "" ||
		(config.Endpoint.Path != "" && config.Endpoint.Path != "/") ||
		config.Endpoint.Host != "iaas."+config.Region+".oraclecloud.com" {
		return nil, &errs.Argument{Message: "OCI endpoint is invalid"}
	}
	if config.Service == "" {
		config.Service = OCIServiceCore
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxBodyBytes <= 0 || config.MaxBodyBytes > 16<<20 {
		return nil, &errs.ArgumentOutOfRangeError{Param: "maxBodyBytes"}
	}
	if config.MaxRetries < 0 || config.MaxRetries > 5 {
		return nil, &errs.ArgumentOutOfRangeError{Param: "maxRetries"}
	}
	if client == nil {
		client = &http.Client{Timeout: config.Timeout}
	}
	clientClone := *client
	// OCI service authorities are allowlisted by the transport config. Never
	// let net/http replay a signed request body to a redirect target that did
	// not pass that validation.
	clientClone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &clientClone
	// Keep the endpoint immutable from callers that reuse their config value.
	endpoint := *config.Endpoint
	config.Endpoint = &endpoint
	return &OCIHTTPTransport{Config: config, Client: client, Signer: signer, retryDelay: boundedOCIRetryDelay}, nil
}

// NewOCIInstancePrincipalTransport composes a transport with an already
// resolved credential. Production estate verification uses the federated
// constructor below so no long-lived key is read from disk.
func NewOCIInstancePrincipalTransport(config OCITransportConfig, client *http.Client, keyID string, key *rsa.PrivateKey) (*OCIHTTPTransport, error) {
	signer, err := NewInstancePrincipalSigner(keyID, key)
	if err != nil {
		return nil, err
	}
	return NewOCIHTTPTransport(config, client, signer)
}

func (t *OCIHTTPTransport) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	return t.DoWithHeaders(ctx, method, path, body, nil)
}

// DoWithHeaders is Do with a small caller-supplied set of validated headers.
// Header names/values are rejected if they contain controls.
func (t *OCIHTTPTransport) DoWithHeaders(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (*http.Response, error) {
	if t == nil || t.Client == nil || t.Config.Endpoint == nil {
		return nil, &InvalidOperationError{Message: "OCI transport is unavailable"}
	}
	if ctx == nil {
		return nil, &errs.Argument{Message: "OCI context is required"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, &errs.Argument{Message: "OCI path is invalid"}
	}
	if len(headers) > 16 {
		return nil, &errs.Argument{Message: "OCI request headers exceed limit"}
	}
	callerHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		if k == "" || strings.TrimSpace(k) != k || strings.ContainsAny(k+v, "\r\n") || strings.ContainsAny(k, ": \t") || len(v) > 4096 {
			return nil, &errs.Argument{Message: "OCI request header is invalid"}
		}
		canonical := http.CanonicalHeaderKey(k)
		if _, duplicate := callerHeaders[canonical]; duplicate {
			return nil, &errs.Argument{Message: "OCI request header is duplicated"}
		}
		callerHeaders[canonical] = v
	}
	var data []byte
	hasBody := body != nil
	if body != nil {
		var err error
		data, err = io.ReadAll(io.LimitReader(body, t.Config.MaxBodyBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > t.Config.MaxBodyBytes {
			return nil, &InvalidDataError{Message: "OCI request body exceeds limit"}
		}
	}
	readOnly := method == http.MethodGet || method == http.MethodHead
	mutation := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
	replayFenced := mutation && ociMutationReplayFenced(callerHeaders)
	attempts := 1
	if readOnly || mutation {
		attempts += t.Config.MaxRetries
	}
	for n := 0; n < attempts; n++ {
		var requestBody io.Reader
		if hasBody {
			requestBody = bytes.NewReader(data)
		}
		req, err := http.NewRequestWithContext(ctx, method, t.Config.Endpoint.String()+strings.TrimPrefix(path, "/"), requestBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		for k, v := range callerHeaders {
			req.Header.Set(k, v)
		}
		if hasBody && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if t.Signer != nil {
			if err := t.Signer.Sign(req); err != nil {
				return nil, redactOCIError(err, "OCI request signing failed")
			}
		}
		resp, err := t.Client.Do(req)
		if err == nil {
			if readOnly && (resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented)) && n+1 < attempts {
				_, _ = ReadBoundedBody(resp, t.Config.MaxBodyBytes)
				if t.retryDelay == nil {
					return nil, &InvalidOperationError{Message: "OCI retry policy is unavailable"}
				}
				if err := t.retryDelay(ctx, n+1); err != nil {
					return nil, err
				}
				continue
			}
			if mutation && resp.StatusCode == http.StatusConflict {
				retryable, parseErr := retryableOCIConflictResponse(resp, t.Config.MaxBodyBytes)
				if parseErr != nil {
					return nil, &ProviderOutcomeUnknownError{Message: "OCI mutation conflict could not be classified"}
				}
				if retryable {
					if !replayFenced {
						return resp, nil
					}
					if n+1 == attempts {
						return nil, newOCIResponseRetriesExhausted("OCI mutation remained in a retryable conflict state")
					}
					if t.retryDelay == nil {
						return nil, &InvalidOperationError{Message: "OCI retry policy is unavailable"}
					}
					if err := t.retryDelay(ctx, n+1); err != nil {
						return nil, err
					}
					continue
				}
			}
			if replayFenced && (resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode != http.StatusNotImplemented)) {
				raw, readErr := ReadBoundedBody(resp, t.Config.MaxBodyBytes)
				if readErr != nil {
					return nil, &ProviderOutcomeUnknownError{Message: "OCI retryable mutation response could not be consumed"}
				}
				if resp.StatusCode >= 500 {
					code, valid := decodeOCIErrorCode(raw)
					if valid && capacityCode(code) {
						resp.Body = io.NopCloser(bytes.NewReader(raw))
						return resp, nil
					}
				}
				if n+1 == attempts {
					return nil, newOCIResponseRetriesExhausted("OCI mutation remained in a retryable provider state")
				}
				if t.retryDelay == nil {
					return nil, &InvalidOperationError{Message: "OCI retry policy is unavailable"}
				}
				if err := t.retryDelay(ctx, n+1); err != nil {
					return nil, err
				}
				continue
			}
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A mutation transport error can arrive after OCI accepted the request.
		// Never repost it automatically; the durable intent must reconcile.
		if mutation || n+1 == attempts {
			return nil, redactOCIError(err, "OCI request transport failed")
		}
		if t.retryDelay == nil {
			return nil, &InvalidOperationError{Message: "OCI retry policy is unavailable"}
		}
		if err := t.retryDelay(ctx, n+1); err != nil {
			return nil, err
		}
	}
	return nil, context.DeadlineExceeded
}

type ociResponseRetriesExhaustedError struct {
	unknown *ProviderOutcomeUnknownError
}

func newOCIResponseRetriesExhausted(message string) error {
	return &ociResponseRetriesExhaustedError{unknown: &ProviderOutcomeUnknownError{Message: message}}
}

func (e *ociResponseRetriesExhaustedError) Error() string { return e.unknown.Error() }
func (e *ociResponseRetriesExhaustedError) Unwrap() error { return e.unknown }

func ociMutationReplayFenced(headers map[string]string) bool {
	return headers["Opc-Retry-Token"] != "" || headers["If-Match"] != "" || headers["If-None-Match"] != ""
}

func retryableOCIConflictResponse(resp *http.Response, max int64) (bool, error) {
	raw, err := ReadBoundedBody(resp, max)
	if err != nil {
		return false, err
	}
	// Nonretryable conflicts still belong to the adapter's terminal failure
	// classifier, so restore the bounded body for its one remaining read.
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	code, valid := decodeOCIErrorCode(raw)
	if !valid {
		return false, &InvalidDataError{Message: "OCI mutation conflict response is invalid"}
	}
	return code == "IncorrectState" || code == "LockConflict", nil
}

func redactOCIError(err error, fallback string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &ProviderOutcomeUnknownError{Message: fallback}
}

func ReadBoundedBody(resp *http.Response, max int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, &InvalidDataError{Message: "OCI response body is empty"}
	}
	defer resp.Body.Close()
	if max <= 0 {
		max = 1 << 20
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, &InvalidDataError{Message: "OCI response body exceeds limit"}
	}
	return b, nil
}

type ociVolumeResponse struct {
	Id            string `json:"id"`
	CompartmentId string `json:"compartmentId"`
	SizeInGBs     int64  `json:"sizeInGBs"`
}

func DecodeVolumeResponse(resp *http.Response) (*VolumeObservation, error) {
	body, err := ReadBoundedBody(resp, 1<<20)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &InvalidDataError{Message: "OCI volume request failed"}
	}
	var v ociVolumeResponse
	if json.Unmarshal(body, &v) != nil || !isOCID(v.Id, "volume") || !isOCID(v.CompartmentId, "compartment") || v.SizeInGBs <= 0 || uint64(v.SizeInGBs) > math.MaxUint64/BytesPerGiB || !isSafeETag(resp.Header.Get("ETag")) {
		return nil, nil
	}
	return &VolumeObservation{ProviderResourceId{v.Id}, ProviderCompartmentId{v.CompartmentId}, ProviderByteCount{uint64(v.SizeInGBs) * BytesPerGiB}, resp.Header.Get("ETag")}, nil
}
func isSafeETag(v string) bool {
	return len(v) > 0 && len(v) <= 256 && !strings.ContainsAny(v, "\r\n") && strings.TrimSpace(v) != ""
}
