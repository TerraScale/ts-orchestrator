package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type pushPlan struct {
	Hold float64 `json:"hold"`
	Hang bool    `json:"hang"`
}

func servePush(ctx context.Context, address, certificate string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP(address)}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	var mu sync.Mutex
	var plans []pushPlan
	control := http.NewServeMux()
	control.HandleFunc("POST /plan", func(w http.ResponseWriter, r *http.Request) {
		var plan pushPlan
		if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		plans = append(plans, plan)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
	push := http.NewServeMux()
	push.HandleFunc("POST /push/{topic}", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		mu.Lock()
		var plan pushPlan
		if len(plans) > 0 {
			plan, plans = plans[0], plans[1:]
		}
		mu.Unlock()
		fmt.Printf("push received proto=%s body=%s\n", r.Proto, strconv.Quote(string(body)))
		if plan.Hang {
			<-r.Context().Done()
			return
		}
		select {
		case <-time.After(time.Duration(plan.Hold * float64(time.Second))):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": rand.Text()[:12], "event": "message", "topic": r.PathValue("topic")})
	})
	servers := []*http.Server{
		{Addr: net.JoinHostPort(address, "8026"), Handler: push, ReadHeaderTimeout: time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}},
		{Addr: net.JoinHostPort(address, "8027"), Handler: control, ReadHeaderTimeout: time.Second},
	}
	listeners := make([]net.Listener, len(servers))
	for i, server := range servers {
		if listeners[i], err = net.Listen("tcp", server.Addr); err != nil {
			return err
		}
		stop := context.AfterFunc(ctx, func() { _ = server.Close() })
		defer stop()
	}
	failed := make(chan error, 2)
	go func() { failed <- servers[0].ServeTLS(listeners[0], "", "") }()
	go func() { failed <- servers[1].Serve(listeners[1]) }()
	fmt.Println("push provider ready")
	err = <-failed
	if ctx.Err() != nil {
		return nil
	}
	return err
}
