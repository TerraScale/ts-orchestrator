package hostenroll

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
)

const (
	imdsURL      = "http://169.254.169.254/opc/v2/instance/"
	maxIMDSBytes = 16 << 10
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
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsURL, nil)
	if err != nil {
		return InstanceMetadata{}, err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := client.Do(request)
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("read OCI IMDSv2 instance: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxIMDSBytes {
		return InstanceMetadata{}, errors.New("OCI IMDSv2 instance response is invalid or too large")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxIMDSBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maxIMDSBytes {
		return InstanceMetadata{}, errors.New("OCI IMDSv2 instance body is missing or too large")
	}
	var instance struct {
		ID       string            `json:"id"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(wire, &instance); err != nil {
		return InstanceMetadata{}, fmt.Errorf("decode OCI IMDSv2 instance: %w", err)
	}
	if !strings.HasPrefix(instance.ID, "ocid1.instance.") || len(instance.ID) > 255 ||
		strings.ContainsAny(instance.ID, " \t\r\n\f\v") {
		return InstanceMetadata{}, errors.New("OCI IMDSv2 instance ID is invalid")
	}
	encoded := []byte(instance.Metadata[hostboot.MetadataKey])
	descriptor, err := hostboot.Parse(encoded)
	if err != nil {
		return InstanceMetadata{}, fmt.Errorf("parse OCI IMDSv2 host descriptor: %w", err)
	}
	return InstanceMetadata{InstanceID: instance.ID, Descriptor: descriptor, Wire: encoded}, nil
}
