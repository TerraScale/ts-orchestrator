package hostenroll

import (
	"bytes"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

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
