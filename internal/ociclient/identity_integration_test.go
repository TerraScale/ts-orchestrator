package ociclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestAuthorityFencesSDKMutationRetries(t *testing.T) {
	var calls atomic.Int32
	var lost atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "" || r.Header.Get("opc-retry-token") != "durable-operation-vcn" {
			t.Error("SDK write omitted authentication or operation token")
		}
		lost.Store(true)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"code":"InternalError","message":"lost response"}`)
	}))
	defer server.Close()
	factory, err := New(testProvider(t), Options{Region: "sa-saopaulo-1", Retry: RetryOptions{BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	home, err := factory.ForRegion("eu-frankfurt-1")
	if err != nil {
		t.Fatal(err)
	}
	if home.Provider() != factory.Provider() {
		t.Fatal("home region changed authenticated identity")
	}
	network, err := home.Network()
	if err != nil {
		t.Fatal(err)
	}
	PinHost(&network.BaseClient, server.URL)
	network.HTTPClient = server.Client()
	ctx := WithAuthority(t.Context(), func(context.Context) error {
		if lost.Load() {
			return errors.New("authority transferred")
		}
		return nil
	})
	_, err = network.CreateVcn(ctx, core.CreateVcnRequest{OpcRetryToken: new("durable-operation-vcn"), CreateVcnDetails: core.CreateVcnDetails{CompartmentId: new("ocid1.compartment.oc1..owned"), CidrBlock: new("10.1.0.0/16")}})
	if err == nil || !strings.Contains(err.Error(), "authority transferred") || calls.Load() != 1 {
		t.Fatalf("stale SDK retry reached provider: calls=%d err=%v", calls.Load(), err)
	}
}
