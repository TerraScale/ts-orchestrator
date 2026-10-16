package hostenroll

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
)

type imdsDoFunc func(*http.Request) (*http.Response, error)

func (fn imdsDoFunc) Do(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func imdsDescriptorFixture(t *testing.T) []byte {
	t.Helper()
	wire, err := (hostboot.Descriptor{
		SchemaVersion: hostboot.SchemaVersion,
		Cell:          "gru", Region: "GRU", Node: "host-0123456789abcdef01234567", Owner: "terrascale",
		FleetGeneration: 7, CreateKey: "0000000000AVXGCP7NEZ0TK93A",
		ImageID: "ocid1.image.oc1.sa-saopaulo-1.image-a", DatabaseID: "0000000000WVSMBJNMAWCDJBSK",
		PartitionID: "0000000000Z3WK359G2W66CVT8", SeatID: "000000000082AXF7GZQT1D126Y", HostAttempt: 2, IntentGeneration: 9,
		IntentPayloadDigest: strings.Repeat("a", 64), CanonicalRosterDigest: strings.Repeat("b", 64),
		ManagedHostProfileDigest: strings.Repeat("c", 64), RuntimeManifestDigest: strings.Repeat("d", 64),
	}).CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func imdsResponse(status int, body []byte, contentLength int64) *http.Response {
	return &http.Response{StatusCode: status, ContentLength: contentLength,
		Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}
}

func TestReadInstanceMetadataUsesOnlyBoundedFixedEndpoints(t *testing.T) {
	ctx := t.Context()
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.example"
	descriptorWire := imdsDescriptorFixture(t)
	rootWire := []byte(`{"id":"` + instanceID + `","metadata":{"user_data":"` + strings.Repeat("x", 27636) + `"}}`)
	if len(rootWire) <= 16<<10 {
		t.Fatal("fixture root response is not larger than the old limit")
	}
	var endpoints []string
	client := imdsDoFunc(func(request *http.Request) (*http.Response, error) {
		if request.Context() != ctx || request.Method != http.MethodGet ||
			request.Header.Get("Authorization") != "Bearer Oracle" {
			t.Fatalf("IMDS request lost caller context, method, or authorization: %+v", request)
		}
		endpoints = append(endpoints, request.URL.String())
		switch request.URL.String() {
		case imdsInstanceURL:
			return imdsResponse(http.StatusOK, []byte(instanceID+"\n"), -1), nil
		case imdsDescriptorURL:
			return imdsResponse(http.StatusOK, descriptorWire, int64(len(descriptorWire))), nil
		case "http://169.254.169.254/opc/v2/instance/":
			return imdsResponse(http.StatusOK, rootWire, int64(len(rootWire))), nil
		default:
			t.Fatalf("unexpected IMDS endpoint %s", request.URL)
			return nil, nil
		}
	})
	metadata, err := ReadInstanceMetadata(ctx, client)
	if err != nil || metadata.InstanceID != instanceID ||
		!bytes.Equal(metadata.Wire, descriptorWire) || metadata.Descriptor.SeatID != "000000000082AXF7GZQT1D126Y" ||
		!slices.Equal(endpoints, []string{
			"http://169.254.169.254/opc/v2/instance/id",
			"http://169.254.169.254/opc/v2/instance/metadata/terrascale_hostboot_v1",
		}) {
		t.Fatalf("fixed endpoint metadata = %+v, %v; requests=%v", metadata, err, endpoints)
	}
}

func TestReadInstanceMetadataRejectsInvalidFixedEndpointResponses(t *testing.T) {
	validID := []byte("ocid1.instance.oc1.sa-saopaulo-1.example")
	validDescriptor := imdsDescriptorFixture(t)
	tests := []struct {
		name              string
		idStatus          int
		idBody            []byte
		idContentLength   int64
		descStatus        int
		descBody          []byte
		descContentLength int64
	}{
		{name: "missing ID", idStatus: http.StatusNotFound, idBody: validID,
			idContentLength: int64(len(validID)), descStatus: http.StatusOK, descBody: validDescriptor},
		{name: "oversized ID length", idStatus: http.StatusOK, idBody: validID,
			idContentLength: maxIMDSIDBytes + 1, descStatus: http.StatusOK, descBody: validDescriptor},
		{name: "oversized ID stream", idStatus: http.StatusOK, idBody: bytes.Repeat([]byte{'x'}, maxIMDSIDBytes+1),
			idContentLength: -1, descStatus: http.StatusOK, descBody: validDescriptor},
		{name: "wrong identity", idStatus: http.StatusOK, idBody: []byte("ocid1.volume.oc1.sa-saopaulo-1.example"),
			idContentLength: -1, descStatus: http.StatusOK, descBody: validDescriptor},
		{name: "identity whitespace", idStatus: http.StatusOK, idBody: []byte("ocid1.instance.oc1.abc def"),
			idContentLength: -1, descStatus: http.StatusOK, descBody: validDescriptor},
		{name: "missing descriptor", idStatus: http.StatusOK, idBody: validID,
			idContentLength: -1, descStatus: http.StatusNotFound, descBody: validDescriptor},
		{name: "oversized descriptor length", idStatus: http.StatusOK, idBody: validID,
			idContentLength: -1, descStatus: http.StatusOK, descBody: validDescriptor,
			descContentLength: hostboot.MaxDescriptorBytes + 1},
		{name: "oversized descriptor stream", idStatus: http.StatusOK, idBody: validID,
			idContentLength: -1, descStatus: http.StatusOK, descBody: bytes.Repeat([]byte{'x'}, hostboot.MaxDescriptorBytes+1),
			descContentLength: -1},
		{name: "invalid descriptor", idStatus: http.StatusOK, idBody: validID,
			idContentLength: -1, descStatus: http.StatusOK, descBody: []byte(`{}`), descContentLength: -1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := imdsDoFunc(func(request *http.Request) (*http.Response, error) {
				switch request.URL.String() {
				case imdsInstanceURL:
					return imdsResponse(test.idStatus, test.idBody, test.idContentLength), nil
				case imdsDescriptorURL:
					return imdsResponse(test.descStatus, test.descBody, test.descContentLength), nil
				default:
					t.Fatalf("unexpected IMDS endpoint %s", request.URL)
					return nil, nil
				}
			})
			if _, err := ReadInstanceMetadata(t.Context(), client); err == nil {
				t.Fatal("invalid IMDS identity or descriptor was accepted")
			}
		})
	}
}

func TestNewIMDSClientRetainsBoundedTransport(t *testing.T) {
	client := NewIMDSClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || client.Timeout != 5*time.Second ||
		client.CheckRedirect == nil {
		t.Fatal("IMDS transport lost its proxy, timeout, or redirect boundary")
	}
	if err := client.CheckRedirect(new(http.Request), nil); err != http.ErrUseLastResponse {
		t.Fatalf("IMDS redirects were enabled: %v", err)
	}
	if _, err := ReadInstanceMetadata(context.Background(), nil); err == nil {
		t.Fatal("nil IMDS client was accepted")
	}
}

// A controller VM's host descriptor names the server of its launch slot; an
// instance without a slot is not a host, and a malformed slot is refused.
func TestReadControllerHostMetadataNamesTheControllerSlot(t *testing.T) {
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.ctl2"
	slot := []byte(`{"schemaVersion":1,"slot":"controller-b"}`)
	name := []byte("gru-1-ctl-2")
	client := imdsDoFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case imdsInstanceURL:
			return imdsResponse(http.StatusOK, []byte(instanceID), -1), nil
		case imdsNameURL:
			if name == nil {
				return imdsResponse(http.StatusInternalServerError, nil, 0), nil
			}
			return imdsResponse(http.StatusOK, name, int64(len(name))), nil
		case imdsBootstrapURL:
			if slot == nil {
				return imdsResponse(http.StatusNotFound, nil, 0), nil
			}
			return imdsResponse(http.StatusOK, slot, int64(len(slot))), nil
		default:
			t.Fatalf("unexpected IMDS endpoint %s", request.URL)
			return nil, nil
		}
	})
	metadata, err := ReadControllerHostMetadata(t.Context(), client, "gru", "GRU")
	if err != nil || metadata.InstanceID != instanceID || metadata.Descriptor != hostboot.Static("gru", "GRU", "gru-1-ctl-2") ||
		!metadata.Descriptor.IsController() ||
		string(metadata.Wire) != `{"schema_version":2,"cell":"gru","region":"GRU","node":"gru-1-ctl-2"}` {
		t.Fatalf("controller host metadata = %+v, %v", metadata, err)
	}
	// A node the rename named keeps its name; another region's does not.
	for display, want := range map[string]string{"ts-gru-2": "ts-gru-2", "ts-sfo-2": "gru-1-ctl-2", "gru-1-ctl-9": "gru-1-ctl-2"} {
		name = []byte(display)
		if metadata, err := ReadControllerHostMetadata(t.Context(), client, "gru", "GRU"); err != nil ||
			metadata.Descriptor != hostboot.Static("gru", "GRU", want) || !metadata.Descriptor.IsController() {
			t.Errorf("display name %s: metadata = %+v, %v, want node %s", display, metadata.Descriptor, err, want)
		}
	}
	name = nil
	if _, err := ReadControllerHostMetadata(t.Context(), client, "gru", "GRU"); err == nil {
		t.Fatal("an unreadable display name fell back to the slot's name")
	}
	name = []byte("gru-1-ctl-2")
	for _, invalid := range [][]byte{[]byte(`{"schemaVersion":1,"slot":"0000000000WM3QQGQPMW5X58P9"}`),
		[]byte(`{"schemaVersion":2,"slot":"controller-a"}`), []byte(`{"slot":"controller-a","extra":1}`)} {
		slot = invalid
		if _, err := ReadControllerHostMetadata(t.Context(), client, "gru", "GRU"); err == nil {
			t.Errorf("accepted controller slot %s", invalid)
		}
	}
	slot = nil
	if _, err := ReadControllerHostMetadata(t.Context(), client, "gru", "GRU"); !errors.Is(err, ErrNotManagedHost) {
		t.Fatalf("an instance without a controller slot: %v", err)
	}
}

func TestReadPoolNodeMetadataWaitsForTheLeaderToName(t *testing.T) {
	instanceID := "ocid1.instance.oc1.sa-saopaulo-1.pool4"
	marker := []byte(`{"schemaVersion":1}`)
	name := []byte("inst-abc")
	client := imdsDoFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.String() {
		case imdsInstanceURL:
			return imdsResponse(http.StatusOK, []byte(instanceID), -1), nil
		case imdsNameURL:
			return imdsResponse(http.StatusOK, name, int64(len(name))), nil
		case imdsNodePoolURL:
			if marker == nil {
				return imdsResponse(http.StatusNotFound, nil, 0), nil
			}
			return imdsResponse(http.StatusOK, marker, int64(len(marker))), nil
		default:
			t.Fatalf("unexpected IMDS endpoint %s", request.URL)
			return nil, nil
		}
	})
	if _, err := ReadPoolNodeMetadata(t.Context(), client, "gru", "GRU"); !errors.Is(err, ErrNodeNotNamed) {
		t.Fatalf("an unnamed pool instance: %v", err)
	}
	name = []byte("ts-sfo-4")
	if _, err := ReadPoolNodeMetadata(t.Context(), client, "gru", "GRU"); !errors.Is(err, ErrNodeNotNamed) {
		t.Fatalf("another region's name: %v", err)
	}
	name = []byte("ts-gru-4")
	metadata, err := ReadPoolNodeMetadata(t.Context(), client, "gru", "GRU")
	if err != nil || metadata.InstanceID != instanceID || metadata.Descriptor != hostboot.Static("gru", "GRU", "ts-gru-4") ||
		string(metadata.Wire) != `{"schema_version":2,"cell":"gru","region":"GRU","node":"ts-gru-4"}` {
		t.Fatalf("pool node metadata = %+v, %v", metadata, err)
	}
	for _, invalid := range [][]byte{[]byte(`{"schemaVersion":2}`), []byte(`{"schemaVersion":"1"}`),
		[]byte(`{"schemaVersion":1,"extra":1}`)} {
		marker = invalid
		if _, err := ReadPoolNodeMetadata(t.Context(), client, "gru", "GRU"); err == nil ||
			errors.Is(err, ErrNotManagedHost) || errors.Is(err, ErrNodeNotNamed) {
			t.Errorf("accepted pool marker %s: %v", invalid, err)
		}
	}
	marker = nil
	if _, err := ReadPoolNodeMetadata(t.Context(), client, "gru", "GRU"); !errors.Is(err, ErrNotManagedHost) {
		t.Fatalf("an instance without the pool marker: %v", err)
	}
}
