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
)

const (
	imdsInstanceURL   = "http://169.254.169.254/opc/v2/instance/id"
	imdsDescriptorURL = "http://169.254.169.254/opc/v2/instance/metadata/" + hostboot.MetadataKey
	maxIMDSIDBytes    = 255
)

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
	if client == nil {
		return InstanceMetadata{}, errors.New("IMDS client is required")
	}
	idWire, err := readIMDS(ctx, client, imdsInstanceURL, maxIMDSIDBytes)
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("read OCI IMDSv2 instance ID: %w", err)
	}
	instanceID := strings.TrimSpace(string(idWire))
	if !strings.HasPrefix(instanceID, "ocid1.instance.") || len(instanceID) > maxIMDSIDBytes ||
		strings.ContainsAny(instanceID, " \t\r\n\f\v") {
		return InstanceMetadata{}, errors.New("OCI IMDSv2 instance ID is invalid")
	}
	encoded, err := readIMDS(ctx, client, imdsDescriptorURL, hostboot.MaxDescriptorBytes)
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("read OCI IMDSv2 host descriptor: %w", err)
	}
	descriptor, err := hostboot.Parse(encoded)
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("parse OCI IMDSv2 host descriptor: %w", err)
	}
	return InstanceMetadata{InstanceID: instanceID, Descriptor: descriptor, Wire: encoded}, nil
}

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
	if response.StatusCode != http.StatusOK || response.ContentLength > maximum {
		return nil, errors.New("OCI IMDSv2 response is invalid or too large")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || len(wire) == 0 || int64(len(wire)) > maximum {
		return nil, errors.New("OCI IMDSv2 body is missing or too large")
	}
	return wire, nil
}
