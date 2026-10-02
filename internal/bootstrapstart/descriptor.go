package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	imdsAddress                        = "169.254.169.254:80"
	imdsBaseURL                        = "http://169.254.169.254/opc/v2/instance/"
	descriptorEndpoint                 = imdsBaseURL + "metadata/terrascale-bootstrap"
	controllerManifestEndpoint         = imdsBaseURL + "metadata/terrascale-controller-manifest-v1"
	identityMetadataEndpoint           = imdsBaseURL + "metadata/" + IdentityMetadataKey
	anchorMetadataEndpoint             = imdsBaseURL + "metadata/" + AnchorMetadataKey
	hostEnrollmentMetadataEndpoint     = imdsBaseURL + "metadata/" + hostboot.EnrollmentMetadataKey
	operatorSSHKeyMetadataEndpoint     = imdsBaseURL + "metadata/" + OperatorSSHKeyMetadataKey
	identityEndpoint                   = imdsBaseURL + "id"
	availabilityDomainEndpoint         = imdsBaseURL + "availabilityDomain"
	faultDomainEndpoint                = imdsBaseURL + "faultDomain"
	maxDescriptorBytes                 = 4096
	MaxControllerManifestMetadataBytes = 30 << 10
	imdsTimeout                        = 3 * time.Second
)

var (
	ErrInvalidDescriptor = errors.New("OCI bootstrap descriptor is invalid")
	// ErrNotController reports an instance launched without controller launch
	// metadata, such as a managed host sharing the qualified image.
	ErrNotController  = errors.New("instance has no controller launch metadata")
	errMetadataAbsent = fmt.Errorf("%w: metadata key is absent", ErrInvalidDescriptor)
	descriptorSlotRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	instanceIDRE      = regexp.MustCompile(`^ocid1\.instance\.oc1\.[a-z0-9-]*\.[a-z0-9-]+$`)
)

// Descriptor is an untrusted IMDS transport hint. Its slot identifies the
// signed ledger key to read; it supplies no trust root, storage scope, image,
// or deployment expectation.
type Descriptor struct {
	SchemaVersion int    `json:"schemaVersion"`
	Slot          string `json:"slot"`
}

func ParseDescriptor(data []byte) (Descriptor, error) {
	var descriptor Descriptor
	if len(data) == 0 || len(data) > maxDescriptorBytes ||
		protocol.DecodeStrict(data, &descriptor, maxDescriptorBytes) != nil ||
		descriptor.SchemaVersion != 1 || !descriptorSlotRE.MatchString(descriptor.Slot) {
		return Descriptor{}, ErrInvalidDescriptor
	}
	return descriptor, nil
}

// IMDSClient is pinned to the OCI v2 link-local endpoint. The transport never
// honors proxy variables, DNS, redirects, or a caller-supplied target URL.
type IMDSClient struct{ client *http.Client }

func NewIMDSClient() IMDSClient {
	dialer := &net.Dialer{Timeout: imdsTimeout}
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: imdsTimeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != imdsAddress {
				return nil, ErrInvalidDescriptor
			}
			return dialer.DialContext(ctx, network, imdsAddress)
		},
	}
	return IMDSClient{client: &http.Client{
		Timeout: imdsTimeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidDescriptor },
	}}
}

func (imds IMDSClient) FetchDescriptor(ctx context.Context) (Descriptor, error) {
	data, err := imds.fetch(ctx, descriptorEndpoint, maxDescriptorBytes)
	if err != nil {
		return Descriptor{}, err
	}
	return ParseDescriptor(data)
}

// FetchInstanceID identifies the local VM from the fixed OCI IMDS endpoint.
// A caller must still compare it with authenticated OCI GetInstance/VNIC facts.
func (imds IMDSClient) FetchInstanceID(ctx context.Context) (string, error) {
	data, err := imds.fetch(ctx, identityEndpoint, 255)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !instanceIDRE.MatchString(id) || !bytes.Equal(bytes.TrimSpace(data), []byte(id)) {
		return "", ErrInvalidDescriptor
	}
	return id, nil
}

// FetchPlacement reads the local VM's availability and fault domain. It is
// used only to refuse co-locating founder peers with the seed; it grants no
// authority and a failure only defers peer launch.
func (imds IMDSClient) FetchPlacement(ctx context.Context) (bootstrap.ControllerPlacement, error) {
	var values [2]string
	for index, endpoint := range []string{availabilityDomainEndpoint, faultDomainEndpoint} {
		data, err := imds.fetch(ctx, endpoint, 255)
		if err != nil {
			return bootstrap.ControllerPlacement{}, err
		}
		values[index] = strings.TrimSpace(string(data))
		if values[index] == "" || strings.ContainsAny(values[index], " \t\r\n") {
			return bootstrap.ControllerPlacement{}, ErrInvalidDescriptor
		}
	}
	return bootstrap.ControllerPlacement{AvailabilityDomain: values[0], FaultDomain: values[1]}, nil
}

// FetchControllerManifest reads only the fixed public transport field. The
// caller must verify the signed envelope against baked roots and observed OCI
// identity before using its configuration.
func (imds IMDSClient) FetchControllerManifest(ctx context.Context) ([]byte, error) {
	return imds.fetch(ctx, controllerManifestEndpoint, MaxControllerManifestMetadataBytes)
}

// FetchLaunchMaterial reads the deployment identity, signed anchor, host
// enrollment bundle and operator SSH key delivered in launch metadata. The
// caller verifies the anchor against the image's trust roots before installing
// any of them.
func (imds IMDSClient) FetchLaunchMaterial(ctx context.Context) (LaunchMaterial, error) {
	identity, err := imds.fetch(ctx, identityMetadataEndpoint, maxIdentity)
	if errors.Is(err, errMetadataAbsent) {
		return LaunchMaterial{}, ErrNotController
	}
	if err != nil {
		return LaunchMaterial{}, fmt.Errorf("read launch identity metadata: %w", err)
	}
	anchor, err := imds.fetch(ctx, anchorMetadataEndpoint, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return LaunchMaterial{}, fmt.Errorf("read launch anchor metadata: %w", err)
	}
	enrollment, err := imds.fetch(ctx, hostEnrollmentMetadataEndpoint, hostenroll.MaxPublicBundleBytes)
	if err != nil {
		return LaunchMaterial{}, fmt.Errorf("read launch host enrollment metadata: %w", err)
	}
	operatorSSHKey, err := imds.fetch(ctx, operatorSSHKeyMetadataEndpoint, maxOperatorSSHKey)
	if err != nil {
		return LaunchMaterial{}, fmt.Errorf("read launch operator SSH key metadata: %w", err)
	}
	return LaunchMaterial{Identity: identity, Anchor: anchor, HostEnrollment: enrollment,
		OperatorSSHKey: operatorSSHKey}, nil
}

func (imds IMDSClient) fetch(ctx context.Context, endpoint string, maximum int64) ([]byte, error) {
	if imds.client == nil || endpoint != descriptorEndpoint && endpoint != identityEndpoint &&
		endpoint != controllerManifestEndpoint && endpoint != identityMetadataEndpoint &&
		endpoint != anchorMetadataEndpoint && endpoint != hostEnrollmentMetadataEndpoint &&
		endpoint != operatorSSHKeyMetadataEndpoint && endpoint != availabilityDomainEndpoint &&
		endpoint != faultDomainEndpoint {
		return nil, ErrInvalidDescriptor
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := imds.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("read fixed OCI IMDS endpoint: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, errMetadataAbsent
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > maximum {
		return nil, ErrInvalidDescriptor
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maximum {
		return nil, ErrInvalidDescriptor
	}
	return data, nil
}
