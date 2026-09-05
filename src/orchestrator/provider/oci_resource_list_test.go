package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestOCIResourceListsConsumeCanonicalArraysAndAllPages(t *testing.T) {
	for _, kind := range []string{"vcn", "volume", "attachment", "instance", "key"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			roundTrip := func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != http.MethodGet || request.URL.Query().Get("compartmentId") != "ocid1.compartment.oc1.x" {
					t.Fatal("list lost signed request scope")
				}
				page := request.URL.Query().Get("page")
				if calls == 1 && page != "" || calls == 2 && page != "opaque+next/=" || calls > 2 {
					t.Fatalf("unexpected page request: %s", request.URL)
				}
				headers := http.Header{}
				if calls == 1 {
					headers.Set("opc-next-page", "opaque+next/=")
				}
				var item string
				switch kind {
				case "vcn":
					item = fmt.Sprintf(`{"id":"ocid1.vcn.oc1.x.%d","cidrBlocks":["10.0.0.0/16"]}`, calls)
				case "volume":
					item = fmt.Sprintf(`{"id":"ocid1.volume.oc1.x.%d","sizeInGBs":50,"vpusPerGB":10}`, calls)
				case "attachment":
					item = fmt.Sprintf(`{"id":"ocid1.volumeattachment.oc1.x.%d","instanceId":"ocid1.instance.oc1.x","volumeId":"ocid1.volume.oc1.x"}`, calls)
				case "instance":
					item = fmt.Sprintf(`{"id":"ocid1.instance.oc1.x.%d"}`, calls)
				case "key":
					item = fmt.Sprintf(`{"id":"ocid1.key.oc1.x.%d","displayName":"kek","lifecycleState":"ENABLED","keyShape":{"algorithm":"AES","length":256,"protectionMode":"SOFTWARE"}}`, calls)
				}
				return testHTTPResponse(http.StatusOK, "["+item+"]", headers), nil
			}
			core := testOCITransport(t, OCIServiceCore, roundTrip)
			count := 0
			var err error
			switch kind {
			case "vcn":
				values, e := (&OCINetworkGateway{Core: core, CompartmentID: "ocid1.compartment.oc1.x"}).ListVCNs(context.Background(), "target")
				count, err = len(values), e
			case "volume":
				values, e := (&OCIBlockStorageGateway{Core: core, CompartmentID: "ocid1.compartment.oc1.x"}).ListVolumes(context.Background())
				count, err = len(values), e
			case "attachment":
				values, e := (&OCIBlockStorageGateway{Core: core, CompartmentID: "ocid1.compartment.oc1.x"}).ListAttachments(context.Background())
				count, err = len(values), e
			case "instance":
				values, e := (&OCIComputeNodeClient{OCI: core}).listNodeInstances(context.Background(), "ocid1.compartment.oc1.x")
				count, err = len(values), e
			case "key":
				values, e := vaultTestGateway(t, roundTrip).ListKeys(context.Background(), vaultTestVault())
				count, err = len(values), e
			}
			if err != nil || count != 2 || calls != 2 {
				t.Fatalf("all-page %s list = %d, calls=%d, err=%v", kind, count, calls, err)
			}
		})
	}
}

func TestOCIResourcePaginationRejectsWrappedCyclesDuplicatesAndPartialLists(t *testing.T) {
	for _, failure := range []string{"wrapper", "cycle", "duplicate", "late-error"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			core := testOCITransport(t, OCIServiceCore, func(request *http.Request) (*http.Response, error) {
				calls++
				item := fmt.Sprintf(`{"id":"ocid1.vcn.oc1.x.%d","cidrBlocks":["10.0.0.0/16"]}`, calls)
				headers := http.Header{}
				if calls == 1 || failure == "cycle" {
					headers.Set("opc-next-page", "same-page")
				}
				if failure == "wrapper" {
					return testHTTPResponse(200, `{"items":[`+item+`]}`, nil), nil
				}
				if failure == "duplicate" {
					item = strings.ReplaceAll(item, fmt.Sprintf("x.%d", calls), "x.1")
				}
				if failure == "late-error" && calls == 2 {
					return testHTTPResponse(403, `{}`, nil), nil
				}
				return testHTTPResponse(200, "["+item+"]", headers), nil
			})
			values, err := (&OCINetworkGateway{Core: core, CompartmentID: "ocid1.compartment.oc1.x"}).ListVCNs(context.Background(), "target")
			if err == nil || values != nil || calls > 2 {
				t.Fatalf("unsafe %s list accepted: %#v, %v, calls=%d", failure, values, err, calls)
			}
		})
	}
}

func TestOCICertificateCollectionRetainsWrapperAndPaginates(t *testing.T) {
	for _, failure := range []string{"", "bare-array", "duplicate", "over-bound", "cycle"} {
		t.Run(failure, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceCertificates, func(request *http.Request) (*http.Response, error) {
				calls++
				if calls > 2 {
					t.Fatal("certificate page bound lost")
				}
				index := calls
				if failure == "duplicate" {
					index = 1
				}
				item := fmt.Sprintf(`{"id":"ocid1.certificate.oc1.x.%d","name":"member-control"}`, index)
				body := `{"items":[` + item + `]}`
				if failure == "bare-array" {
					body = "[" + item + "]"
				}
				header := http.Header{}
				if calls == 1 || failure == "cycle" {
					header.Set("opc-next-page", "next")
				}
				if calls == 2 && request.URL.Query().Get("page") != "next" {
					t.Fatal("certificate continuation missing")
				}
				return testHTTPResponse(200, body, header), nil
			})
			gateway := &OCICertificatesGateway{Certs: transport, CompartmentID: "ocid1.compartment.oc1.x", MaxListed: 2}
			if failure == "over-bound" {
				gateway.MaxListed = 1
			}
			result, err := gateway.listCertificateSummaries(context.Background())
			if failure == "" {
				if err != nil || len(result) != 2 {
					t.Fatalf("certificate pages = %v, %v", result, err)
				}
			} else if err == nil || result != nil {
				t.Fatalf("invalid %s accepted", failure)
			}
		})
	}
}
