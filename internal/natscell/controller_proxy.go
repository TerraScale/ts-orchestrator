package natscell

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ControllerProxy belongs to one root-admitted controller process. The root
// listener retains its original process/source guards for every Unix stream.
type ControllerProxy struct {
	runtime  *Runtime
	config   *tls.Config
	address  string
	deadline time.Time
	initial  atomic.Bool
}

// NewControllerProxy snapshots the running root broker's retained material;
// neither the ordinary controller nor its reconnects read private TLS files.
func NewControllerProxy(runtime *Runtime) (*ControllerProxy, error) {
	if runtime == nil || runtime.server == nil || !runtime.server.Running() || runtime.bridge == nil || runtime.brokerTLS == nil || runtime.controllerJWT == "" {
		return nil, errors.New("controller proxy requires the original root broker")
	}
	runtime.brokerTLS.mu.Lock()
	material := runtime.brokerTLS.current
	certificate := tls.Certificate{}
	if material.certificate != nil {
		for _, der := range material.certificate.Certificate {
			certificate.Certificate = append(certificate.Certificate, bytes.Clone(der))
		}
	}
	if len(certificate.Certificate) == 0 || material.roots == nil {
		runtime.brokerTLS.mu.Unlock()
		return nil, errors.New("controller proxy root TLS material is unavailable")
	}
	roots := material.roots.Clone()
	keyDER, err := x509.MarshalPKCS8PrivateKey(material.certificate.PrivateKey)
	runtime.brokerTLS.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer clear(keyDER)
	certificate.PrivateKey, err = x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("controller proxy root TLS key cannot sign")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, certificate.Leaf.RawSubjectPublicKeyInfo) {
		return nil, errors.New("controller proxy root TLS key does not match its certificate")
	}
	intermediates := x509.NewCertPool()
	for _, der := range certificate.Certificate[1:] {
		intermediate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		intermediates.AddCert(intermediate)
	}
	chains, err := certificate.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, err
	}
	deadline := certificate.Leaf.NotAfter
	for _, certificate := range chains[0] {
		if certificate.NotAfter.Before(deadline) {
			deadline = certificate.NotAfter
		}
	}
	address := runtime.bridge.Addr().String()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return &ControllerProxy{runtime: runtime, address: address, deadline: deadline,
		config: &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
			Certificates: []tls.Certificate{certificate}, RootCAs: roots, ServerName: host}}, nil
}

// ServeInitial consumes this process's allowance before validation or TLS.
// Only the root listener's original MainPID/source admission may call it.
func (proxy *ControllerProxy) ServeInitial(ctx context.Context, ordinary net.Conn, originalDeadline time.Time) error {
	if ordinary != nil {
		defer ordinary.Close()
	}
	if proxy == nil || !proxy.initial.CompareAndSwap(false, true) {
		return errors.New("controller private startup was already consumed")
	}
	if ordinary == nil || ctx == nil || ctx.Err() != nil || !time.Now().Before(originalDeadline) {
		return errors.New("controller private startup source is unavailable")
	}
	ctx, cancel := context.WithDeadline(ctx, originalDeadline)
	defer cancel()
	ctx, stop := context.WithDeadline(ctx, proxy.deadline)
	defer stop()
	admitted, initial := net.Pipe()
	serverContext, stopServer := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- proxy.runtime.ServeStartupController(serverContext, admitted, originalDeadline) }()
	closeInternal := func() {
		stopServer()
		_ = initial.Close()
		<-done
	}
	return proxy.serve(ctx, ordinary, initial, closeInternal)
}

// ServeReconnect always traverses the real production TCP gate. Startup
// admission is never consulted or reused as reconnect permission.
func (proxy *ControllerProxy) ServeReconnect(ctx context.Context, ordinary net.Conn) error {
	if ordinary != nil {
		defer ordinary.Close()
	}
	if proxy == nil || ordinary == nil || ctx == nil || ctx.Err() != nil {
		return errors.New("controller reconnect source is unavailable")
	}
	if _, finite := ctx.Deadline(); !finite {
		return errors.New("controller reconnect requires its original finite source")
	}
	ctx, cancel := context.WithDeadline(ctx, proxy.deadline)
	defer cancel()
	raw, err := (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, "tcp", proxy.address)
	if err != nil {
		return err
	}
	return proxy.serve(ctx, ordinary, raw, func() { _ = raw.Close() })
}

func (proxy *ControllerProxy) serve(ctx context.Context, ordinary, raw net.Conn, closeInternal func()) error {
	closePair := sync.OnceFunc(func() {
		closeInternal()
		_ = ordinary.Close()
	})
	stop := context.AfterFunc(ctx, closePair)
	defer stop()
	defer closePair()
	secured := tls.Client(raw, proxy.config)
	handshake, cancel := context.WithTimeout(ctx, 12*time.Second)
	err := secured.HandshakeContext(handshake)
	cancel()
	if err != nil {
		return err
	}
	done := make(chan error, 2)
	go func() { _, err := io.Copy(secured, ordinary); done <- err }()
	go func() { _, err := io.Copy(ordinary, secured); done <- err }()
	first := <-done
	closePair()
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return first
}
