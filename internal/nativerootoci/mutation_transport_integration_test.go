package nativerootoci

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type nativeWireConnectionKey struct{}

type nativeWireRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip nativeWireRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

// A TLS fixture can prove request/transport behavior, not OCI mutation finality.
func TestNativeRootSDKWireKeepsUnacknowledgedPutUncertain(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range []int{1, 2} {
		for _, failure := range []string{"lost-ack", "service-unavailable", "unauthorized"} {
			t.Run(fmt.Sprintf("HTTP%d/%s", protocol, failure), func(t *testing.T) {
				target := testTarget(t)
				root := []byte("root-after-conditional-put")
				var mu sync.Mutex
				var puts, gets int
				var warmConnection net.Conn
				committed := false
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
					body, err := io.ReadAll(io.LimitReader(request.Body, MaxRootBytes+1))
					if err != nil {
						t.Errorf("read complete wire body: %v", err)
						return
					}
					if request.TLS == nil || request.ProtoMajor != protocol ||
						request.URL.Path != "/n/"+target.Namespace+"/b/"+target.Bucket+"/o/"+target.rootKey() {
						t.Errorf("unexpected signed target or protocol: %s %s", request.Proto, request.URL.Path)
					}
					verifyNativeWireSignature(t, request, key.PublicKey)
					connection, ok := request.Context().Value(nativeWireConnectionKey{}).(net.Conn)
					if !ok {
						t.Error("missing actual server connection")
						return
					}
					mu.Lock()
					defer mu.Unlock()
					switch request.Method {
					case http.MethodGet:
						gets++
						if gets == 1 {
							warmConnection = connection
						}
						w.Header().Set("ETag", "original-etag")
						if committed {
							w.Header().Set("ETag", "committed-etag")
							_, _ = w.Write(root)
						} else {
							_, _ = w.Write([]byte("original-root"))
						}
					case http.MethodPut:
						puts++
						checksum := sha256.Sum256(root)
						if !bytes.Equal(body, root) || request.ContentLength != int64(len(root)) ||
							request.Header.Get("If-Match") != "original-etag" || request.Header.Get("If-None-Match") != "" ||
							request.Header.Get("opc-content-sha256") != base64.StdEncoding.EncodeToString(checksum[:]) {
							t.Error("conditional PUT body, length or checksum changed on the wire")
						}
						if puts == 1 && connection != warmConnection {
							t.Error("first PUT did not exercise the previously used connection")
						}
						if puts > 1 {
							writeNativeWireError(w, http.StatusPreconditionFailed, "PreconditionFailed")
							return
						}
						switch failure {
						case "lost-ack":
							committed = true
							// Close the actual HTTP/1 or HTTP/2 TLS connection after consuming the PUT.
							_ = connection.Close()
						case "service-unavailable":
							writeNativeWireError(w, http.StatusServiceUnavailable, "ServiceUnavailable")
						case "unauthorized":
							writeNativeWireError(w, http.StatusUnauthorized, "NotAuthenticated")
						}
					default:
						t.Errorf("unexpected wire method %s", request.Method)
					}
				}))
				server.EnableHTTP2 = protocol == 2
				server.Config.ConnContext = func(ctx context.Context, connection net.Conn) context.Context {
					return context.WithValue(ctx, nativeWireConnectionKey{}, connection)
				}
				server.StartTLS()
				t.Cleanup(server.Close)
				client := nativeWireSDKClient(t, server, key)
				service, err := NewService(target, client)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				authorize := func(context.Context) error { return nil }
				warm := service.Execute(ctx, testRequest(target, "get", nil, ""), authorize)
				if warm.Status != "found" || warm.ETag != "original-etag" ||
					warm.RootBase64 != base64.StdEncoding.EncodeToString([]byte("original-root")) {
					t.Fatalf("warm GET did not preserve reader behavior: %+v", warm)
				}
				first := service.Execute(ctx, testRequest(target, "update", root, "original-etag"), authorize)
				mu.Lock()
				firstPuts := puts
				mu.Unlock()
				if first.Status != "uncertain" || first.ETag != "" || firstPuts != 1 {
					t.Fatalf("unacknowledged PUT replayed or lost uncertainty: response=%+v, physical requests=%d", first, firstPuts)
				}
				later := service.Execute(ctx, testRequest(target, "update", root, "original-etag"), authorize)
				if later.Status != "precondition" || later.ETag != "" {
					t.Fatalf("explicit later request did not retain exact 412: %+v", later)
				}
				readback := service.Execute(ctx, testRequest(target, "get", nil, ""), authorize)
				wantBody, wantETag := []byte("original-root"), "original-etag"
				if failure == "lost-ack" {
					wantBody, wantETag = root, "committed-etag"
				}
				if readback.Status != "found" || readback.ETag != wantETag ||
					readback.RootBase64 != base64.StdEncoding.EncodeToString(wantBody) {
					t.Fatalf("readback changed: %+v", readback)
				}
				mu.Lock()
				defer mu.Unlock()
				if puts != 2 || gets != 2 {
					t.Fatalf("server observed unexpected wire attempts: PUT=%d GET=%d", puts, gets)
				}
			})
		}
	}
}

func nativeWireSDKClient(t *testing.T, server *httptest.Server, key *rsa.PrivateKey) *objectstorage.ObjectStorageClient {
	t.Helper()
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..wire", "ocid1.user.oc1..wire",
		"sa-saopaulo-1", "wire-fingerprint", string(privateKey), nil)
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	client.SetRegion("sa-saopaulo-1")
	bounded, err := bootstrap.NewInstancePrincipalSDKHTTPClient()
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := bounded.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || bounded.CheckRedirect == nil {
		t.Fatal("production SDK HTTP client lost its concrete proxy/redirect boundary")
	}
	fixtureURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = fixtureURL.Hostname()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	bounded.Transport = nativeWireRoundTripper(func(request *http.Request) (*http.Response, error) {
		_, idempotencyKey := request.Header["Idempotency-Key"]
		_, alternateKey := request.Header["X-Idempotency-Key"]
		if request.Method == http.MethodPut && (request.GetBody != nil || request.Body == nil ||
			request.ContentLength <= 0 || idempotencyKey || alternateKey) {
			t.Error("SDK made the nonempty conditional PUT replayable")
		}
		return transport.RoundTrip(request)
	})
	client.HTTPClient = bounded
	policy := common.NoRetryPolicy()
	client.Configuration.RetryPolicy = &policy
	return &client
}

func writeNativeWireError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"code":%q,"message":"native wire fixture"}`, code)
}

func verifyNativeWireSignature(t *testing.T, request *http.Request, key rsa.PublicKey) {
	t.Helper()
	authorization, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Signature ")
	if !ok {
		t.Error("wire request has no OCI signature")
		return
	}
	fields := make(map[string]string)
	for field := range strings.SplitSeq(authorization, ",") {
		name, value, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found {
			t.Error("malformed OCI authorization field")
			return
		}
		decoded, err := strconv.Unquote(value)
		if err != nil {
			t.Error("malformed quoted OCI authorization field")
			return
		}
		fields[name] = decoded
	}
	if fields["algorithm"] != "rsa-sha256" || fields["headers"] == "" {
		t.Error("wire request lost OCI signing algorithm or headers")
		return
	}
	var signed []string
	for header := range strings.FieldsSeq(fields["headers"]) {
		value := request.Header.Get(header)
		switch header {
		case "(request-target)":
			value = strings.ToLower(request.Method) + " " + request.URL.RequestURI()
		case "host":
			value = request.Host
		case "content-length":
			value = strconv.FormatInt(request.ContentLength, 10)
		}
		signed = append(signed, header+": "+value)
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	if err != nil {
		t.Error("wire request has an invalid OCI signature encoding")
		return
	}
	hash := sha256.Sum256([]byte(strings.Join(signed, "\n")))
	if err := rsa.VerifyPKCS1v15(&key, crypto.SHA256, hash[:], signature); err != nil {
		t.Errorf("OCI signature failed across SDK/TLS/server boundary: %v", err)
	}
}
