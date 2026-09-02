package provider

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func validObjectPart(value string, max int, slash bool) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	return slash || !strings.Contains(value, "/")
}

// OCIEstateSpec is the reviewed, one-time OCI estate consumed by regional
// controllers. Startup reads every identity and refuses malformed scope or
// lifecycle bindings. The orchestrator never creates these resources.
type OCIEstateSpec struct {
	Region                  string            `json:"region"`
	TenancyID               string            `json:"tenancyId"`
	ControlCompartmentID    string            `json:"controlCompartmentId"`
	NetworkCompartmentID    string            `json:"networkCompartmentId"`
	WorkloadCompartmentID   string            `json:"workloadCompartmentId"`
	VCNID                   string            `json:"vcnId"`
	SubnetIDs               []string          `json:"subnetIds"`
	NetworkSecurityGroupIDs []string          `json:"networkSecurityGroupIds"`
	IAMPolicyCompartmentID  string            `json:"iamPolicyCompartmentId"`
	IAMPolicies             []OCIEstatePolicy `json:"iamPolicies"`
	VaultID                 string            `json:"vaultId"`
	KeyID                   string            `json:"keyId"`
	KeyManagementEndpoint   string            `json:"keyManagementEndpoint"`
	ObjectNamespace         string            `json:"objectNamespace"`
	LedgerBucket            string            `json:"ledgerBucket"`
	BackupBucket            string            `json:"backupBucket"`
}

type OCIEstatePolicy struct {
	ID         string   `json:"id"`
	Statements []string `json:"statements"`
}

func LoadOCIEstateSpec(path string) (OCIEstateSpec, error) {
	if !filepath.IsAbs(path) {
		return OCIEstateSpec{}, &errs.Argument{Message: "OCI estate file path must be absolute"}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is unavailable"}
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is invalid"}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var spec OCIEstateSpec
	if decoder.Decode(&spec) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateOCIEstateSpec(spec) != nil {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is invalid"}
	}
	return spec, nil
}

func validateOCIEstateSpec(spec OCIEstateSpec) error {
	if len(spec.Region) < 1 || len(spec.Region) > 63 || !regionPattern.MatchString(spec.Region) ||
		!isOCID(spec.TenancyID, "tenancy") || !isOCID(spec.ControlCompartmentID, "compartment") ||
		!isOCID(spec.NetworkCompartmentID, "compartment") || !isOCID(spec.WorkloadCompartmentID, "compartment") ||
		!isOCID(spec.VCNID, "vcn") || !isOCID(spec.IAMPolicyCompartmentID, "compartment") ||
		!isOCID(spec.VaultID, "vault") || !isOCID(spec.KeyID, "key") ||
		!validObjectPart(spec.ObjectNamespace, 128, false) || !validObjectPart(spec.LedgerBucket, 256, false) ||
		!validObjectPart(spec.BackupBucket, 256, false) || spec.LedgerBucket == spec.BackupBucket ||
		len(spec.SubnetIDs) < 1 || len(spec.SubnetIDs) > 16 || len(spec.NetworkSecurityGroupIDs) < 1 || len(spec.NetworkSecurityGroupIDs) > 16 ||
		len(spec.IAMPolicies) == 0 || len(spec.IAMPolicies) > 16 {
		return &errs.Argument{Message: "OCI estate specification is incomplete"}
	}
	keyEndpoint, err := NewOCIServiceTransportConfig(OCIServiceVaultManagement, spec.Region, spec.KeyManagementEndpoint)
	if err != nil || keyEndpoint.Endpoint == nil {
		return &errs.Argument{Message: "OCI estate key management endpoint is invalid"}
	}
	policyIDs := make([]string, 0, len(spec.IAMPolicies))
	for _, policy := range spec.IAMPolicies {
		if len(policy.Statements) == 0 || len(policy.Statements) > 32 {
			return &errs.Argument{Message: "OCI estate IAM policy is incomplete"}
		}
		seenStatements := map[string]bool{}
		for _, statement := range policy.Statements {
			if len(statement) < 1 || len(statement) > 1024 || strings.ContainsAny(statement, "\r\n") || seenStatements[statement] {
				return &errs.Argument{Message: "OCI estate IAM policy statement is invalid"}
			}
			seenStatements[statement] = true
		}
		policyIDs = append(policyIDs, policy.ID)
	}
	return validateEstateIDs(spec.SubnetIDs, "subnet", spec.NetworkSecurityGroupIDs, "networksecuritygroup", policyIDs, "policy")
}

func validateEstateIDs(groups ...any) error {
	for index := 0; index < len(groups); index += 2 {
		ids := groups[index].([]string)
		kind := groups[index+1].(string)
		seen := map[string]bool{}
		for _, id := range ids {
			if !isOCID(id, kind) || seen[id] {
				return &errs.Argument{Message: "OCI estate specification contains invalid resource identities"}
			}
			seen[id] = true
		}
	}
	return nil
}

// OCIEstateReader is the provider-neutral, read-only verification seam used
// by startup and fake malformed-estate tests.
type OCIEstateReader interface {
	Read(context.Context, OCIService, string) ([]byte, int, error)
}

type OCIEstateHTTPReader struct {
	Transports map[OCIService]*OCIHTTPTransport
}

func (r *OCIEstateHTTPReader) Read(ctx context.Context, service OCIService, path string) ([]byte, int, error) {
	if r == nil {
		return nil, 0, &InvalidOperationError{Message: "OCI estate reader is unavailable"}
	}
	transport := r.Transports[service]
	if transport == nil {
		return nil, 0, &InvalidOperationError{Message: "OCI estate reader is unavailable"}
	}
	resp, err := transport.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, 0, err
	}
	status := resp.StatusCode
	body, err := ReadBoundedBody(resp, transport.Config.MaxBodyBytes)
	return body, status, err
}

func NewOCIEstateHTTPReader(spec OCIEstateSpec, keyID, keyPath string) (*OCIEstateHTTPReader, error) {
	if validateOCIEstateSpec(spec) != nil || keyID == "" || !filepath.IsAbs(keyPath) {
		return nil, &errs.Argument{Message: "OCI estate verification credentials are invalid"}
	}
	key, err := readRSAPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	transports := make(map[OCIService]*OCIHTTPTransport, 5)
	for _, service := range []OCIService{OCIServiceCore, OCIServiceIdentity, OCIServiceObjectStorage, OCIServiceVault} {
		host, _ := ociServiceHost(service, spec.Region)
		config, configErr := NewOCIServiceTransportConfig(service, spec.Region, "https://"+host)
		if configErr != nil {
			return nil, configErr
		}
		transport, transportErr := NewOCIInstancePrincipalTransport(config, nil, keyID, key)
		if transportErr != nil {
			return nil, transportErr
		}
		transports[service] = transport
	}
	keyConfig, err := NewOCIServiceTransportConfig(OCIServiceVaultManagement, spec.Region, spec.KeyManagementEndpoint)
	if err != nil {
		return nil, err
	}
	keyTransport, err := NewOCIInstancePrincipalTransport(keyConfig, nil, keyID, key)
	if err != nil {
		return nil, err
	}
	transports[OCIServiceVaultManagement] = keyTransport
	return &OCIEstateHTTPReader{Transports: transports}, nil
}

func readRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, &InvalidDataError{Message: "OCI signing key file is unavailable or has unsafe permissions"}
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return nil, &InvalidDataError{Message: "OCI signing key file is invalid"}
	}
	block, rest := pem.Decode(body)
	if block == nil || len(rest) != 0 {
		return nil, &InvalidDataError{Message: "OCI signing key file is invalid"}
	}
	if key, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, &InvalidDataError{Message: "OCI signing key file is invalid"}
	}
	return key, nil
}

func VerifyOCIEstate(ctx context.Context, spec OCIEstateSpec, reader OCIEstateReader) error {
	if ctx == nil || reader == nil || validateOCIEstateSpec(spec) != nil {
		return &errs.Argument{Message: "OCI estate verification request is invalid"}
	}
	for _, compartment := range []string{spec.ControlCompartmentID, spec.NetworkCompartmentID, spec.WorkloadCompartmentID} {
		if err := verifyEstateResource(ctx, reader, OCIServiceIdentity, "/20160918/compartments/"+url.PathEscape(compartment), compartment, spec.TenancyID, "", false); err != nil {
			return err
		}
	}
	if err := verifyEstateResource(ctx, reader, OCIServiceCore, "/20160918/vcns/"+url.PathEscape(spec.VCNID), spec.VCNID, spec.NetworkCompartmentID, "", false); err != nil {
		return err
	}
	for _, subnet := range spec.SubnetIDs {
		if err := verifyEstateResource(ctx, reader, OCIServiceCore, "/20160918/subnets/"+url.PathEscape(subnet), subnet, spec.NetworkCompartmentID, spec.VCNID, true); err != nil {
			return err
		}
	}
	for _, nsg := range spec.NetworkSecurityGroupIDs {
		if err := verifyEstateResource(ctx, reader, OCIServiceCore, "/20160918/networkSecurityGroups/"+url.PathEscape(nsg), nsg, spec.NetworkCompartmentID, spec.VCNID, false); err != nil {
			return err
		}
	}
	for _, policy := range spec.IAMPolicies {
		if err := verifyEstatePolicy(ctx, reader, spec.IAMPolicyCompartmentID, policy); err != nil {
			return err
		}
	}
	if err := verifyEstateResource(ctx, reader, OCIServiceVault, "/20180608/vaults/"+url.PathEscape(spec.VaultID), spec.VaultID, spec.ControlCompartmentID, "", false); err != nil {
		return err
	}
	if err := verifyEstateResource(ctx, reader, OCIServiceVaultManagement, "/20180608/keys/"+url.PathEscape(spec.KeyID), spec.KeyID, spec.ControlCompartmentID, "", false); err != nil {
		return err
	}
	for _, bucket := range []string{spec.LedgerBucket, spec.BackupBucket} {
		path := "/n/" + url.PathEscape(spec.ObjectNamespace) + "/b/" + url.PathEscape(bucket)
		body, status, err := reader.Read(ctx, OCIServiceObjectStorage, path)
		var document struct {
			Name          string `json:"name"`
			CompartmentID string `json:"compartmentId"`
		}
		if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.Name != bucket || document.CompartmentID != spec.ControlCompartmentID {
			return &InvalidDataError{Message: "OCI estate verification rejected a bucket"}
		}
	}
	return nil
}

// VerifyOCIEstateAndBind returns a launch allowlist only after every
// read-only estate check has succeeded. Callers cannot construct the binding
// directly because its fields and constructor are private.
func VerifyOCIEstateAndBind(ctx context.Context, spec OCIEstateSpec, reader OCIEstateReader) (*OCINodeEstateBinding, error) {
	if err := VerifyOCIEstate(ctx, spec, reader); err != nil {
		return nil, err
	}
	binding := &OCINodeEstateBinding{
		vcnID: spec.VCNID,
		subnets: make(map[string]struct{}, len(spec.SubnetIDs)),
		networkSecurityGroups: make(map[string]struct{}, len(spec.NetworkSecurityGroupIDs)),
		digest: fingerprintJSON("oci-estate-binding", spec),
	}
	for _, id := range spec.SubnetIDs {
		binding.subnets[id] = struct{}{}
	}
	for _, id := range spec.NetworkSecurityGroupIDs {
		binding.networkSecurityGroups[id] = struct{}{}
	}
	return binding, nil
}

func verifyEstatePolicy(ctx context.Context, reader OCIEstateReader, compartment string, expected OCIEstatePolicy) error {
	body, status, err := reader.Read(ctx, OCIServiceIdentity, "/20160918/policies/"+url.PathEscape(expected.ID))
	var document struct {
		ID, CompartmentID, LifecycleState string
		Statements                        []string
	}
	if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.ID != expected.ID ||
		document.CompartmentID != compartment || document.LifecycleState != "ACTIVE" || !sameStringSet(document.Statements, expected.Statements) {
		return &InvalidDataError{Message: "OCI estate verification rejected a required IAM policy"}
	}
	return nil
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, item := range left {
		counts[item]++
	}
	for _, item := range right {
		counts[item]--
		if counts[item] < 0 {
			return false
		}
	}
	return true
}

func verifyEstateResource(ctx context.Context, reader OCIEstateReader, service OCIService, path, id, compartment, vcn string, requirePrivate bool) error {
	body, status, err := reader.Read(ctx, service, path)
	var document struct {
		ID                     string `json:"id"`
		CompartmentID          string `json:"compartmentId"`
		VCNID                  string `json:"vcnId"`
		LifecycleState         string `json:"lifecycleState"`
		ProhibitPublicIPOnVNIC bool   `json:"prohibitPublicIpOnVnic"`
	}
	decodeErr := json.Unmarshal(body, &document)
	ready := document.LifecycleState == "ACTIVE" || document.LifecycleState == "AVAILABLE" || (isOCID(id, "key") && document.LifecycleState == "ENABLED")
	if err != nil || status < 200 || status >= 300 || decodeErr != nil || document.ID != id ||
		(compartment != "" && document.CompartmentID != compartment) || (vcn != "" && document.VCNID != vcn) ||
		!ready || (requirePrivate && !document.ProhibitPublicIPOnVNIC) {
		return &InvalidDataError{Message: "OCI estate verification rejected a required resource"}
	}
	return nil
}

var _ OCIEstateReader = (*OCIEstateHTTPReader)(nil)
