package region

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// Actual OCI signing, compute/network SDK decoding and TLS carry every endpoint
// substitution. This boundary never constructs source or mutation authority.
func TestNetBirdUnderlaySDKPinsOriginalCurrentVNIC(t *testing.T) {
	_, objects, _ := foundationProtocolStore(t)
	provider := objects.ConfigurationProvider()
	if provider == nil {
		t.Fatal("protocol fixture has no authenticated SDK provider")
	}
	factory, err := ociclient.New(*provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	const instance = "ocid1.instance.oc1.sa-saopaulo-1.original"
	const vnic = "ocid1.vnic.oc1.sa-saopaulo-1.original"
	const subnet = "ocid1.subnet.oc1.sa-saopaulo-1.original"
	const nsg = "ocid1.networksecuritygroup.oc1.sa-saopaulo-1.original"
	const compartment, address = "ocid1.compartment.oc1..control", "10.251.0.10"
	var mode atomic.Value
	mode.Store("valid")
	var calls, writes atomic.Int32
	var cancelRead atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet {
			writes.Add(1)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") == "" || !strings.Contains(r.Host, foundationHomeRegion) {
			t.Error("native endpoint observation lost the authenticated signed GRU SDK request")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		current := mode.Load().(string)
		switch r.URL.Path {
		case "/20160918/instances/" + instance:
			id := instance
			if current == "instance" {
				id += "other"
			}
			json.MarshalWrite(w, map[string]any{"id": id, "compartmentId": compartment, "lifecycleState": "RUNNING"})
		case "/20160918/vnicAttachments":
			if r.URL.Query().Get("instanceId") != instance || r.URL.Query().Get("compartmentId") != compartment {
				t.Error("SDK attachment query lost the exact original instance and compartment")
			}
			row := map[string]any{"id": "ocid1.vnicattachment.oc1.sa-saopaulo-1.original", "instanceId": instance, "compartmentId": compartment, "subnetId": subnet, "vnicId": vnic, "lifecycleState": "ATTACHED"}
			if current == "attachment" {
				row["instanceId"] = instance + "other"
			}
			rows := []map[string]any{row}
			if current == "duplicate" {
				rows = append(rows, row)
			}
			if current == "pagination" {
				w.Header().Set("opc-next-page", "other")
			}
			json.MarshalWrite(w, rows)
		case "/20160918/vnics/" + vnic:
			if current == "canceled" {
				cancelRead.Load().(context.CancelCauseFunc)(errors.New("original native observation canceled"))
				<-r.Context().Done()
				return
			}
			row := map[string]any{"id": vnic, "compartmentId": compartment, "subnetId": subnet, "nsgIds": []string{nsg}, "privateIp": address, "isPrimary": true, "skipSourceDestCheck": false, "lifecycleState": "AVAILABLE"}
			switch current {
			case "vnic":
				row["id"] = vnic + "other"
			case "subnet":
				row["subnetId"] = subnet + "other"
			case "nsg":
				row["nsgIds"] = []string{nsg + "other"}
			case "address":
				row["privateIp"] = "10.251.0.11"
			case "secondary":
				row["isPrimary"] = false
			case "forwarding":
				row["skipSourceDestCheck"] = true
			case "public writer":
				row["publicIp"] = "203.0.113.10"
			case "ipv6":
				row["ipv6Addresses"] = []string{"fd00::1"}
			}
			json.MarshalWrite(w, row)
		default:
			t.Errorf("unexpected OCI operation: %s", r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	originalTransport := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = originalTransport; transport.CloseIdleConnections() })
	for _, name := range []string{"valid", "instance", "attachment", "duplicate", "pagination", "vnic", "subnet", "nsg", "address", "secondary", "forwarding", "public writer", "ipv6", "canceled"} {
		t.Run(name, func(t *testing.T) {
			mode.Store(name)
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cancelRead.Store(cancel)
			observed, err := observeNetBirdUnderlayEndpoint(ctx, factory, instance, compartment, subnet, address, []string{nsg}, true)
			if name == "valid" {
				if err != nil || observed != vnic {
					t.Fatalf("original native endpoint was not admitted: %s %v", observed, err)
				}
			} else if err == nil || observed != "" {
				t.Fatalf("substituted or canceled native endpoint was admitted: %s %v", observed, err)
			}
		})
	}
	if calls.Load() == 0 || writes.Load() != 0 {
		t.Fatalf("read-only native SDK boundary observed %d calls and %d writes", calls.Load(), writes.Load())
	}
}
