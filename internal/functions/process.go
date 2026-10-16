package functions

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"golang.org/x/net/netutil"
	"golang.org/x/sync/errgroup"
)

const processMaterialDirectory = "/run/ts-orch/function"

// ProcessDeployment is delivered by admitted task/Vault reconciliation. It is
// trusted placement metadata, never a user-supplied worker configuration.
type ProcessDeployment struct {
	Environment     string `json:"environment"`
	Cell            string `json:"cell"`
	TenantID        string `json:"tenant_id"`
	FunctionID      string `json:"function_id"`
	Revision        string `json:"revision"`
	Digest          string `json:"digest"`
	MinimumSequence uint64 `json:"minimum_sequence"`
	BrokerURL       string `json:"broker_url"`
}

// Run serves a single admitted tenant revision in its own long-lived process.
// Task admission mounts the fixed material directory automatically; there are no flags.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("function-worker accepts no arguments")
	}
	return runProcess(ctx, processMaterialDirectory, ":8080", output)
}

func runProcess(ctx context.Context, directory, address string, output io.Writer) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("function material directory: %w", err)
	}
	defer root.Close()
	read := func(name string, limit int64, secret bool) ([]byte, error) {
		file, err := root.Open(name)
		if err != nil {
			return nil, fmt.Errorf("read function material %s: %w", name, err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > limit || (secret && info.Mode().Perm()&0077 != 0) {
			return nil, fmt.Errorf("invalid function material %s size or permissions", name)
		}
		value, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || int64(len(value)) > limit {
			return nil, fmt.Errorf("read function material %s exceeded bound", name)
		}
		return value, nil
	}
	deploymentWire, err := read("deployment.json", 16<<10, false)
	if err != nil {
		return err
	}
	var deployment ProcessDeployment
	if err := json.Unmarshal(deploymentWire, &deployment, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("function deployment: %w", err)
	}
	brokerURL, err := url.Parse(deployment.BrokerURL)
	if err != nil || brokerURL.Scheme != "tls" || brokerURL.Host == "" || brokerURL.User != nil || brokerURL.Path != "" || brokerURL.RawQuery != "" || brokerURL.Fragment != "" {
		return errors.New("function broker requires one verified TLS endpoint")
	}
	rootPublic, err := read("root.pub", ed25519.PublicKeySize, false)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(ed25519.PublicKey(rootPublic))
	if err != nil {
		return err
	}
	receipt, err := read("receipt.json", 64<<10, false)
	if err != nil {
		return err
	}
	delegation, err := read("delegation.json", 64<<10, false)
	if err != nil {
		return err
	}
	module, err := read("module.wasm", MaxModuleBytes, false)
	if err != nil {
		return err
	}
	proof, err := release.VerifyFunctionCurrent(receipt, delegation, module, roots, release.FunctionExpectation{
		Environment: deployment.Environment, Cell: deployment.Cell, TenantID: deployment.TenantID,
		FunctionID: deployment.FunctionID, Revision: deployment.Revision, Digest: deployment.Digest, MinimumSequence: deployment.MinimumSequence,
	}, time.Now())
	if err != nil {
		return fmt.Errorf("admit function worker: %w", err)
	}
	ctx, cancel := context.WithDeadline(ctx, proof.ExpiresAt())
	defer cancel()
	worker, err := NewWorker(ctx, proof)
	if err != nil {
		return err
	}
	defer worker.Close(context.Background())
	certificateWire, err := read("ingress-cert.pem", 64<<10, false)
	if err != nil {
		return err
	}
	keyWire, err := read("ingress-key.pem", 64<<10, true)
	if err != nil {
		return err
	}
	defer clear(keyWire)
	certificate, err := tls.X509KeyPair(certificateWire, keyWire)
	if err != nil {
		return fmt.Errorf("function ingress certificate: %w", err)
	}
	ingressCA, err := read("ingress-ca.pem", 64<<10, false)
	if err != nil {
		return err
	}
	ingressRoots := x509.NewCertPool()
	if !ingressRoots.AppendCertsFromPEM(ingressCA) {
		return errors.New("invalid function ingress CA")
	}
	brokerCA, err := read("broker-ca.pem", 64<<10, false)
	if err != nil {
		return err
	}
	brokerRoots := x509.NewCertPool()
	if !brokerRoots.AppendCertsFromPEM(brokerCA) {
		return errors.New("invalid function broker CA")
	}
	credentials, err := read("broker.creds", 64<<10, true)
	if err != nil {
		return err
	}
	defer clear(credentials)
	credentialJWT, err := jwt.ParseDecoratedJWT(credentials)
	if err != nil {
		return fmt.Errorf("function broker credential format: %w", err)
	}
	credentialClaim, err := jwt.DecodeUserClaims(credentialJWT)
	if err != nil {
		return fmt.Errorf("function broker credential claim: %w", err)
	}
	inbox, err := WorkerInboxPrefix(credentialClaim.Subject)
	if err != nil {
		return err
	}
	nc, err := nats.Connect(deployment.BrokerURL, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: brokerRoots}), nats.UserCredentialBytes(credentials), nats.CustomInboxPrefix(inbox), nats.Timeout(2*time.Second), nats.MaxReconnects(-1))
	if err != nil {
		return fmt.Errorf("function broker connection: %w", err)
	}
	defer nc.Close()
	queue, err := NewQueueWorker(ctx, nc, worker)
	if err != nil {
		return err
	}
	expectedURI := "spiffe://terrascale.tech/tenants/" + deployment.TenantID + "/functions/" + deployment.FunctionID
	authorize := func(r *http.Request) (string, error) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			return "", ErrScope
		}
		for _, uri := range r.TLS.PeerCertificates[0].URIs {
			if uri.String() == expectedURI {
				return deployment.TenantID, nil
			}
		}
		return "", ErrScope
	}
	handler, err := NewHTTPHandler(worker, authorize)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.Handle("POST /", handler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := authorize(r); err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !nc.IsConnected() || worker.ctx.Err() != nil {
			http.Error(w, "function worker unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"state":"ready"}`)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 4 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: ingressRoots, ClientAuth: tls.RequireAndVerifyClientCert},
	}
	group, groupCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		err := server.Serve(tls.NewListener(netutil.LimitListener(listener, 64), server.TLSConfig))
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	})
	group.Go(func() error { return queue.Run(groupCtx) })
	group.Go(func() error {
		<-groupCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		return server.Shutdown(shutdownCtx)
	})
	ready, err := json.Marshal(struct{ State, Address, TenantID, FunctionID, Revision, Digest string }{"ready", listener.Addr().String(), deployment.TenantID, deployment.FunctionID, deployment.Revision, deployment.Digest})
	if err == nil {
		_, err = fmt.Fprintln(output, string(ready))
	}
	if err != nil {
		cancel()
	}
	return errors.Join(err, group.Wait())
}
