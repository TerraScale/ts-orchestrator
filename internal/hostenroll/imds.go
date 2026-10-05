package hostenroll

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	imdsInstanceURL   = "http://169.254.169.254/opc/v2/instance/id"
	imdsDescriptorURL = "http://169.254.169.254/opc/v2/instance/metadata/" + hostboot.MetadataKey
	imdsEnrollmentURL = "http://169.254.169.254/opc/v2/instance/metadata/" + hostboot.EnrollmentMetadataKey
	// imdsBootstrapURL is the controller launch hint naming its signed slot.
	imdsBootstrapURL = "http://169.254.169.254/opc/v2/instance/metadata/terrascale-bootstrap"
	maxIMDSIDBytes   = 255
)

// ErrNotManagedHost reports an instance launched without a host descriptor,
// such as a controller sharing the qualified image. An operator-launched C#
// TerraBase host carries a static descriptor (hostboot.Static) instead.
var ErrNotManagedHost = errors.New("instance has no managed host descriptor")

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func NewIMDSClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// InstanceMetadata is the untrusted instance identity hint returned by OCI
// IMDSv2. The controller must independently observe the instance and peer IP.
type InstanceMetadata struct {
	InstanceID string
	Descriptor hostboot.Descriptor
	Wire       []byte
}

func ReadInstanceMetadata(ctx context.Context, client HTTPDoer) (InstanceMetadata, error) {
	instanceID, err := readInstanceID(ctx, client)
	if err != nil {
		return InstanceMetadata{}, err
	}
	encoded, err := readIMDS(ctx, client, imdsDescriptorURL, hostboot.MaxDescriptorBytes)
	if errors.Is(err, errIMDSKeyAbsent) {
		return InstanceMetadata{}, ErrNotManagedHost
	}
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("read OCI IMDSv2 host descriptor: %w", err)
	}
	descriptor, err := hostboot.ParseHost(encoded)
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("parse OCI IMDSv2 host descriptor: %w", err)
	}
	return InstanceMetadata{InstanceID: instanceID, Descriptor: descriptor, Wire: encoded}, nil
}

func readInstanceID(ctx context.Context, client HTTPDoer) (string, error) {
	if client == nil {
		return "", errors.New("IMDS client is required")
	}
	idWire, err := readIMDS(ctx, client, imdsInstanceURL, maxIMDSIDBytes)
	if err != nil {
		return "", fmt.Errorf("read OCI IMDSv2 instance ID: %w", err)
	}
	instanceID := strings.TrimSpace(string(idWire))
	if !strings.HasPrefix(instanceID, "ocid1.instance.") || len(instanceID) > maxIMDSIDBytes ||
		strings.ContainsAny(instanceID, " \t\r\n\f\v") {
		return "", errors.New("OCI IMDSv2 instance ID is invalid")
	}
	return instanceID, nil
}

// ReadControllerHostMetadata returns the static descriptor of the host agent
// on a controller VM: the server name of the controller's launch slot in
// cell and region. An instance without a controller slot is not a host.
func ReadControllerHostMetadata(ctx context.Context, client HTTPDoer, cell, region string) (InstanceMetadata, error) {
	instanceID, err := readInstanceID(ctx, client)
	if err != nil {
		return InstanceMetadata{}, err
	}
	wire, err := readIMDS(ctx, client, imdsBootstrapURL, 256)
	if errors.Is(err, errIMDSKeyAbsent) {
		return InstanceMetadata{}, ErrNotManagedHost
	}
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("read OCI IMDSv2 controller slot: %w", err)
	}
	var bootstrap struct {
		SchemaVersion int    `json:"schemaVersion"`
		Slot          string `json:"slot"`
	}
	if err := protocol.DecodeStrict(wire, &bootstrap, 256); err != nil || bootstrap.SchemaVersion != 1 {
		return InstanceMetadata{}, errors.New("OCI IMDSv2 controller slot is invalid")
	}
	node, err := naming.RegionCell(region).ControllerSlot(bootstrap.Slot)
	if err != nil {
		return InstanceMetadata{}, err
	}
	descriptor := hostboot.Static(cell, region, node)
	encoded, err := descriptor.CanonicalBytes()
	if err != nil {
		return InstanceMetadata{}, err
	}
	return InstanceMetadata{InstanceID: instanceID, Descriptor: descriptor, Wire: encoded}, nil
}

// ReadEnrollmentMetadata reads the exact public enrollment bundle delivered
// by the controller that launched this host.
func ReadEnrollmentMetadata(ctx context.Context, client HTTPDoer) ([]byte, error) {
	if client == nil {
		return nil, errors.New("IMDS client is required")
	}
	wire, err := readIMDS(ctx, client, imdsEnrollmentURL, MaxPublicBundleBytes)
	if err != nil {
		return nil, fmt.Errorf("read OCI IMDSv2 host enrollment bundle: %w", err)
	}
	return wire, nil
}

var errIMDSKeyAbsent = errors.New("OCI IMDSv2 metadata key is absent")

func readIMDS(ctx context.Context, client HTTPDoer, endpoint string, maximum int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, errors.New("OCI IMDSv2 response is missing")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, errIMDSKeyAbsent
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > maximum {
		return nil, errors.New("OCI IMDSv2 response is invalid or too large")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(wire) == 0 || int64(len(wire)) > maximum {
		return nil, errors.New("OCI IMDSv2 body is missing or too large")
	}
	return wire, nil
}
