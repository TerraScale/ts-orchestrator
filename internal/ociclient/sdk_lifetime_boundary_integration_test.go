package ociclient_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestRegionalIdentityAndMutationAuthorityFenceOverVerifiedTLS(t *testing.T) {
	provider, key := sdkLifetimeProvider(t)
	t.Run("fenced_mutation_then_read", func(t *testing.T) {
		const vcnID = "ocid1.vcn.oc1.eu-frankfurt-1.lifetime"
		var writes atomic.Int32
		var reads atomic.Int32
		var lost atomic.Bool
		server := sdkLifetimeServer(t, key, func(w http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet && request.URL.Path == "/20160918/vcns/"+vcnID {
				reads.Add(1)
				sdkLifetimeJSON(t, w, http.StatusOK, map[string]string{"id": vcnID, "cidrBlock": "10.1.0.0/16"})
				return
			}
			writes.Add(1)
			if request.Method != http.MethodPost || request.URL.Path != "/20160918/vcns" || request.Header.Get("opc-retry-token") != "durable-operation-vcn" {
				t.Errorf("unexpected authenticated mutation: %s %s token=%s", request.Method, request.URL.Path, request.Header.Get("opc-retry-token"))
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			var details core.CreateVcnDetails
			if err := json.UnmarshalRead(request.Body, &details); err != nil || details.CompartmentId == nil || *details.CompartmentId != "ocid1.compartment.oc1..owned" || details.CidrBlock == nil || *details.CidrBlock != "10.1.0.0/16" {
				t.Errorf("VCN mutation details=%+v err=%v", details, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			lost.Store(true)
			sdkLifetimeJSON(t, w, http.StatusServiceUnavailable, map[string]string{"code": "InternalError", "message": "lost response"})
		})
		factory := sdkLifetimeFactory(t, provider, ociclient.Options{Region: "sa-saopaulo-1",
			Retry: ociclient.RetryOptions{BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}})
		home, err := factory.ForRegion("eu-frankfurt-1")
		if err != nil {
			t.Fatal(err)
		}
		if home.Provider() != factory.Provider() {
			t.Fatal("home region changed authenticated identity")
		}
		cached, err := factory.ForRegion("eu-frankfurt-1")
		if err != nil || cached != home || cached.Limiter(ociclient.ServiceNetwork) != home.Limiter(ociclient.ServiceNetwork) {
			t.Fatal("home-region clients do not share their factory and service limiter")
		}
		client, err := home.Network()
		if err != nil {
			t.Fatal(err)
		}
		ociclient.PinHost(&client.BaseClient, server.URL)
		transferred := errors.New("authority transferred")
		ctx := ociclient.WithAuthority(sdkLifetimeContext(t), func(context.Context) error {
			if lost.Load() {
				return transferred
			}
			return nil
		})
		_, err = client.CreateVcn(ociclient.RequestContext(ctx), core.CreateVcnRequest{
			OpcRetryToken:    new("durable-operation-vcn"),
			CreateVcnDetails: core.CreateVcnDetails{CompartmentId: new("ocid1.compartment.oc1..owned"), CidrBlock: new("10.1.0.0/16")},
		})
		if !errors.Is(err, transferred) || !strings.Contains(err.Error(), "authority transferred") || writes.Load() != 1 {
			t.Fatalf("stale SDK retry reached provider: writes=%d err=%v", writes.Load(), err)
		}
		response, err := client.GetVcn(ociclient.RequestContext(ctx), core.GetVcnRequest{VcnId: new(vcnID)})
		if err != nil || response.Id == nil || *response.Id != vcnID || reads.Load() != 1 || writes.Load() != 1 {
			t.Fatalf("read after authority transfer: reads=%d writes=%d response=%+v err=%v", reads.Load(), writes.Load(), response, err)
		}
	})
}

func sdkLifetimeProvider(t *testing.T) (common.ConfigurationProvider, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return common.NewRawConfigurationProvider("ocid1.tenancy.oc1..lifetime", "ocid1.user.oc1..lifetime", "sa-saopaulo-1", "lifetime-fingerprint", string(privateKey), nil), key
}

func sdkLifetimeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func sdkLifetimeServer(t *testing.T, key *rsa.PrivateKey, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.TLS == nil {
			t.Error("SDK provider request did not cross TLS")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := sdkLifetimeVerify(request, &key.PublicKey); err != nil {
			t.Errorf("SDK request signature: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler(w, request)
	}))
	server.StartTLS()
	server.Config.SetKeepAlivesEnabled(false)
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	bundle := filepath.Join(t.TempDir(), "sdk-fixture-ca.pem")
	if err := os.WriteFile(bundle, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	// The SDK's test-only CA bundle preserves the factory's real dispatcher chain.
	t.Setenv("OCI_DEFAULT_CERTS_PATH", bundle)
	return server
}

func sdkLifetimeVerify(request *http.Request, key *rsa.PublicKey) error {
	authorization, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Signature ")
	if !ok {
		return errors.New("missing OCI Signature authorization")
	}
	fields := make(map[string]string)
	for field := range strings.SplitSeq(authorization, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			return errors.New("malformed OCI Signature authorization")
		}
		fields[name] = value[1 : len(value)-1]
	}
	if fields["algorithm"] != "rsa-sha256" || fields["keyId"] != "ocid1.tenancy.oc1..lifetime/ocid1.user.oc1..lifetime/lifetime-fingerprint" {
		return errors.New("unexpected OCI signing identity or algorithm")
	}
	headers := strings.Fields(fields["headers"])
	for _, required := range []string{"(request-target)", "host", "date"} {
		if !slices.Contains(headers, required) {
			return fmt.Errorf("unsigned required header %s", required)
		}
	}
	parts := make([]string, 0, len(headers))
	for _, header := range headers {
		value := request.Header.Get(header)
		switch header {
		case "(request-target)":
			value = strings.ToLower(request.Method) + " " + request.URL.RequestURI()
		case "host":
			value = request.Host
		case "content-length":
			value = fmt.Sprint(request.ContentLength)
		}
		if value == "" {
			return fmt.Errorf("signed header %s is absent", header)
		}
		parts = append(parts, header+": "+value)
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}

func sdkLifetimeFactory(t *testing.T, provider common.ConfigurationProvider, options ociclient.Options) *ociclient.Factory {
	t.Helper()
	factory, err := ociclient.New(provider, options)
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func sdkLifetimeJSON(t *testing.T, writer http.ResponseWriter, status int, value any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.MarshalWrite(writer, value); err != nil {
		t.Error(err)
	}
}
