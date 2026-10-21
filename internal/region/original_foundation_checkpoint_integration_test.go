package region

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestOriginalProviderCheckpointSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22 (Q-MAIN-GREEN), owner ts-orch consolidation thread: flaky on main and M1 PRs since the 2026-10-21 integration-line merge")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", foundationHomeRegion, "fixture",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	rootRevoked := errors.New("original root session revoked")
	for _, test := range []struct {
		name                                           string
		publication, admission                         bool
		cancelOperation, cancelLease, deadline, revoke bool
		wantGuards, wantRoots, wantGets, wantPuts      int64
	}{
		{name: "publication child deadline", publication: true, wantGuards: 2, wantRoots: 3, wantGets: 2, wantPuts: 1},
		{name: "admission checkpoint", admission: true, wantGuards: 3, wantRoots: 4, wantGets: 3, wantPuts: 1},
		{name: "operation cancellation", cancelOperation: true, wantGuards: 1, wantRoots: 1, wantGets: 1},
		{name: "operation deadline", deadline: true, wantGuards: 1, wantRoots: 1, wantGets: 1},
		{name: "owning context cancellation", cancelLease: true, wantGuards: 1, wantRoots: 1, wantGets: 1},
		{name: "original root guard revoked", revoke: true, wantGuards: 1, wantRoots: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(common.UsingExpectHeaderEnvVar, "false")
			checkpoint := []byte("original acknowledged checkpoint")
			dir := t.TempDir()
			checkpointPath, effectPath := filepath.Join(dir, "checkpoint"), filepath.Join(dir, "effect")
			if err := os.WriteFile(checkpointPath, checkpoint, 0600); err != nil {
				t.Fatal(err)
			}
			lifetime, cancelLease := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancelLease()
			var guards, roots, gets, puts atomic.Int64
			entered, canceled := make(chan struct{}, 1), make(chan struct{}, 1)
			serverErrors := make(chan error, 8)
			report := func(err error) {
				select {
				case serverErrors <- err:
				default:
				}
			}
			blocked := test.cancelOperation || test.cancelLease || test.deadline
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS == nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
					report(errors.New("checkpoint fixture requires signed SDK TLS requests"))
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch {
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/o/checkpoint"):
					gets.Add(1)
					if blocked {
						entered <- struct{}{}
						<-r.Context().Done()
						canceled <- struct{}{}
						return
					}
					wire, err := os.ReadFile(checkpointPath)
					if err != nil {
						report(err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.Header().Set("ETag", "checkpoint-etag")
					_, _ = w.Write(wire)
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/effect"):
					puts.Add(1)
					wire, err := io.ReadAll(r.Body)
					if err == nil {
						err = os.WriteFile(effectPath, wire, 0600)
					}
					if err != nil {
						report(err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.Header().Set("ETag", "effect-etag")
				default:
					report(fmt.Errorf("unexpected SDK request %s %s", r.Method, r.URL.Path))
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			defer func() { cancelLease(); server.Close() }()
			listener, ok := server.Listener.Addr().(*net.TCPAddr)
			if !ok || !listener.IP.IsLoopback() {
				t.Fatal("checkpoint fixture requires literal loopback TLS")
			}
			previous := http.DefaultTransport
			transport := previous.(*http.Transport).Clone()
			transport.Proxy = nil
			transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("checkpoint fixture refuses plaintext and proxies")
			}
			transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" && network != "tcp6" {
					return nil, fmt.Errorf("checkpoint fixture refuses network %q", network)
				}
				return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
			}
			http.DefaultTransport = transport
			defer func() { http.DefaultTransport = previous; transport.CloseIdleConnections() }()
			factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
			if err != nil {
				t.Fatal(err)
			}
			objects, err := factory.ObjectStorage()
			if err != nil {
				t.Fatal(err)
			}
			ociclient.PinHost(&objects.BaseClient, server.URL)
			type leaseValueKey struct{}
			lease := context.WithValue(lifetime, leaseValueKey{}, "owning lease value")
			lease = ociclient.WithRequestGuard(lease, func(context.Context) error {
				roots.Add(1)
				if test.revoke {
					return rootRevoked
				}
				return nil
			})
			operation, cancelOperation := context.WithCancel(lease)
			defer cancelOperation()
			if test.deadline {
				operation, cancelOperation = context.WithTimeout(lease, 2*time.Second)
				defer cancelOperation()
			}
			guard := func(dispatch context.Context) error {
				if guards.Add(1) > test.wantGuards {
					return errors.New("provider guard reentered its own prerequisite reads")
				}
				ctx := originalProviderCheckpointContext(dispatch, lease)
				deadline, hasDeadline := dispatch.Deadline()
				got, hasGot := ctx.Deadline()
				if !hasDeadline || !hasGot || !got.Equal(deadline) || ctx.Value(leaseValueKey{}) != "owning lease value" {
					return errors.New("checkpoint lost dispatch deadline or owning lease values")
				}
				operationDeadline, _ := operation.Deadline()
				if test.publication && !deadline.Before(operationDeadline) {
					return errors.New("publication checkpoint did not receive the tighter write deadline")
				}
				response, err := objects.GetObject(ociclient.ReadContext(ctx), objectstorage.GetObjectRequest{
					NamespaceName: new("ns"), BucketName: new(foundationDiscoveryBucket), ObjectName: new("checkpoint")})
				if err != nil {
					return err
				}
				if response.Content == nil {
					return errors.New("SDK checkpoint omitted body")
				}
				defer response.Content.Close()
				wire, err := io.ReadAll(response.Content)
				if err != nil || !bytes.Equal(wire, checkpoint) {
					return errors.Join(errors.New("SDK checkpoint changed"), err)
				}
				return nil
			}
			ctx := ociclient.WithRequestGuard(ociclient.WithAuthority(operation, guard), guard)
			if test.admission {
				ctx = ociclient.WithAdmission(ctx, func(dispatch context.Context) (func(), error) {
					if err := guard(dispatch); err != nil {
						return nil, err
					}
					return func() {}, nil
				})
			}
			done := make(chan error, 1)
			go func() {
				if test.publication {
					done <- publishFoundationObject(ctx, &objects, "ns", "effect", []byte("effect"))
					return
				}
				_, err := objects.PutObject(ociclient.RequestContext(ctx), objectstorage.PutObjectRequest{
					NamespaceName: new("ns"), BucketName: new(foundationDiscoveryBucket), ObjectName: new("effect"),
					PutObjectBody: io.NopCloser(strings.NewReader("effect")), ContentLength: new(int64(len("effect")))})
				done <- err
			}()
			if blocked {
				select {
				case <-entered:
					if test.cancelOperation {
						cancelOperation()
					} else if test.cancelLease {
						cancelLease()
					}
				case err := <-done:
					t.Fatalf("SDK returned before checkpoint HTTP read: %v", err)
				case <-lifetime.Done():
					t.Fatal("checkpoint HTTP read never entered")
				}
			}
			select {
			case err = <-done:
			case <-lifetime.Done():
				// Join the SDK operation even on a faulty cancellation path.
				cancelLease()
				err = <-done
			}
			wantErr := error(nil)
			if test.deadline {
				wantErr = context.DeadlineExceeded
			} else if test.cancelOperation || test.cancelLease {
				wantErr = context.Canceled
			} else if test.revoke {
				wantErr = rootRevoked
			}
			if (wantErr == nil && err != nil) || (wantErr != nil && !errors.Is(err, wantErr)) {
				t.Fatalf("SDK operation error = %v, want %v", err, wantErr)
			}
			if !test.cancelLease && lifetime.Err() != nil {
				t.Fatal("operation cancellation waited for or canceled the owning context")
			}
			if blocked {
				select {
				case <-canceled:
				case <-time.After(2 * time.Second):
					t.Fatal("checkpoint HTTP request did not observe cancellation")
				}
			}
			if guards.Load() != test.wantGuards || roots.Load() != test.wantRoots || gets.Load() != test.wantGets || puts.Load() != test.wantPuts {
				t.Fatalf("guard/root/GET/PUT = %d/%d/%d/%d, want %d/%d/%d/%d", guards.Load(), roots.Load(), gets.Load(), puts.Load(), test.wantGuards, test.wantRoots, test.wantGets, test.wantPuts)
			}
			if wire, err := os.ReadFile(checkpointPath); err != nil || !bytes.Equal(wire, checkpoint) {
				t.Fatal("checkpoint fixture changed", err)
			}
			wire, effectErr := os.ReadFile(effectPath)
			if test.wantPuts == 0 {
				if !errors.Is(effectErr, os.ErrNotExist) {
					t.Fatal("denied SDK operation left an effect file", effectErr)
				}
			} else if effectErr != nil || string(wire) != "effect" {
				t.Fatal("successful SDK operation omitted exact effect file", effectErr)
			}
			select {
			case err := <-serverErrors:
				t.Fatal(err)
			default:
			}
		})
	}
}
