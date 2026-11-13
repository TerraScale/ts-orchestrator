package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeAuthority struct {
	mu      sync.Mutex
	base    string
	key     *ecdsa.PrivateKey
	root    *x509.Certificate
	orders  map[string]string
	issuers map[string]string
	count   map[string]int
	chain   map[string][]byte
	proceed chan struct{}
	once    sync.Once
}

func authorityToken(name string) string {
	digest := sha256.Sum256([]byte(name))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (a *fakeAuthority) challenge(name string) (string, error) {
	var answer string
	a.mu.Lock()
	nodes := []string{a.issuers[name]}
	a.mu.Unlock()
	if name == "shared.e2e.test" {
		nodes = []string{"10.77.0.2", "10.77.0.3"}
	}

	if strings.HasPrefix(name, "gru.") {
		nodes = []string{"10.77.0.2"}
	}
	if strings.HasPrefix(name, "sjc.") {
		nodes = []string{"10.77.0.3"}
	}
	for _, node := range nodes {
		request, err := http.NewRequest(http.MethodGet, "http://"+node+"/.well-known/acme-challenge/"+authorityToken(name), nil)
		if err != nil {
			return "", err
		}
		request.Host = name
		response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
		if err != nil {
			return "", err
		}
		data, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || len(data) == 0 {
			return "", fmt.Errorf("challenge on %s: HTTP %d, %v", node, response.StatusCode, err)
		}
		if answer != "" && answer != string(data) {
			return "", fmt.Errorf("challenge responses differ")
		}
		answer = string(data)
	}
	return answer, nil
}

func authorityMain(ctx context.Context, cfg configuration) error {
	rootPEM, err := os.ReadFile(cfg.Work + "/ca.pem")
	if err != nil {
		return err
	}
	rootBlock, _ := pem.Decode(rootPEM)
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return err
	}
	private, err := os.ReadFile(cfg.Work + "/ca.key")
	if err != nil {
		return err
	}
	keyBlock, _ := pem.Decode(private)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	a := &fakeAuthority{base: "https://acme-v02.api.letsencrypt.org", key: key, root: root, orders: map[string]string{}, issuers: map[string]string{}, count: map[string]int{}, chain: map[string][]byte{}, proceed: make(chan struct{})}
	control, err := net.Listen("tcp", "10.77.0.1:8088")
	if err != nil {
		return err
	}
	defer control.Close()
	public, err := net.Listen("tcp", "10.77.0.1:443")
	if err != nil {
		return err
	}
	defer public.Close()
	metadata, err := net.Listen("tcp", "169.254.169.254:80")
	if err != nil {
		return err
	}
	defer metadata.Close()
	api, err := net.Listen("tcp", "10.77.0.1:9443")
	if err != nil {
		return err
	}
	defer api.Close()
	proxy, err := net.Listen("tcp", "10.77.0.1:8089")
	if err != nil {
		return err
	}
	defer proxy.Close()
	pair, err := tls.LoadX509KeyPair(cfg.Work+"/identity.pem", cfg.Work+"/identity.key")
	if err != nil {
		return err
	}
	tlsAPI := tls.NewListener(api, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}})
	defer tlsAPI.Close()
	var databaseReads int
	servers := []*http.Server{
		{Handler: http.HandlerFunc(a.serve)},
		{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/instance/id"):
				_, _ = io.WriteString(w, "ocid1.instance.oc1..journey")
			case strings.HasSuffix(r.URL.Path, "/vnics/"):
				address := "10.77.0.2"
				if strings.HasPrefix(r.RemoteAddr, "10.77.0.3:") {
					address = "10.77.0.3"
				}
				_ = json.NewEncoder(w).Encode([]map[string]string{{"privateIp": address}})
			case strings.HasSuffix(r.URL.Path, "/canonicalRegionName"):
				region := "sa-saopaulo-1"
				if strings.HasPrefix(r.RemoteAddr, "10.77.0.3:") {
					region = "us-sanjose-1"
				}
				_, _ = io.WriteString(w, region)
			case strings.HasSuffix(r.URL.Path, "/region"):
				_, _ = io.WriteString(w, "sa-saopaulo-1")
			case strings.HasSuffix(r.URL.Path, "/identity/key.pem"):
				http.ServeFile(w, r, cfg.Work+"/identity.key")
			case strings.HasSuffix(r.URL.Path, "/identity/cert.pem"), strings.HasSuffix(r.URL.Path, "/identity/intermediate.pem"):
				http.ServeFile(w, r, cfg.Work+"/identity.pem")
			default:
				http.NotFound(w, r)
			}
		})},
		{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(r.URL.Path, "x509"):
				claims, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "opc-tenant": "ocid1.tenancy.oc1..journey"})
				token := base64.RawURLEncoding.EncodeToString([]byte("{}")) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
				_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
			case strings.Contains(r.URL.Path, "secretbundles"):
				value, ok := map[string]string{"ts-orch-mesh-key": cfg.MeshSeed, "gru-1-terrabase-nats-token": cfg.DatabaseToken}[r.URL.Query().Get("secretName")]
				if r.URL.Query().Get("secretName") == "gru-1-terrabase-nats-token" {
					a.mu.Lock()
					databaseReads++
					digest := sha256.Sum256([]byte(cfg.DatabaseToken + strconv.Itoa(databaseReads)))
					value = hex.EncodeToString(digest[:])
					a.mu.Unlock()
				}
				if !ok {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(value))}, "versionNumber": 1})
			default:
				http.NotFound(w, r)
			}
		})},
		{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect || r.Host != "auth.sa-saopaulo-1.oraclecloud.com:443" && r.Host != "secrets.vaults.sa-saopaulo-1.oci.oraclecloud.com:443" {
				http.Error(w, "unexpected upstream", 403)
				return
			}
			upstream, err := net.DialTimeout("tcp", "10.77.0.1:9443", 3*time.Second)
			if err != nil {
				http.Error(w, "upstream unavailable", 502)
				return
			}
			defer upstream.Close()
			downstream, stream, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer downstream.Close()
			_, _ = stream.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = stream.Flush()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(upstream, stream); _ = upstream.Close(); close(done) }()
			_, _ = io.Copy(downstream, upstream)
			_ = downstream.Close()
			<-done
		})},
	}
	publicTLS := tls.NewListener(public, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}})
	servers = append(servers, &http.Server{Handler: http.HandlerFunc(a.serve)})
	listeners := []net.Listener{publicTLS, metadata, tlsAPI, proxy, control}
	var running sync.WaitGroup
	for i, server := range servers {
		running.Go(func() { _ = server.Serve(listeners[i]) })
	}
	fmt.Println("READY authority")
	<-ctx.Done()
	for _, server := range servers {
		_ = server.Close()
	}
	running.Wait()
	return nil
}

func (a *fakeAuthority) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	base := a.base
	w.Header().Set("Replay-Nonce", base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 10))))
	w.Header().Set("Content-Type", "application/json")
	var envelope struct {
		Payload string `json:"payload"`
	}
	var payload struct {
		Identifiers        []acme.AuthzID `json:"identifiers"`
		CSR                string         `json:"csr"`
		OnlyReturnExisting bool           `json:"onlyReturnExisting"`
	}
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			http.Error(w, "JWS", 400)
			return
		}
		body, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if err != nil {
			http.Error(w, "payload", 400)
			return
		}
		if len(body) > 0 && json.Unmarshal(body, &payload) != nil {
			http.Error(w, "JSON", 400)
			return
		}
	}
	id := r.URL.Query().Get("id")
	switch r.URL.Path {
	case "/counts":
		_ = json.NewEncoder(w).Encode(a.count)
	case "/release":
		a.once.Do(func() { close(a.proceed) })
		w.WriteHeader(204)
	case "/directory":
		_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order"})
	case "/nonce":
		w.WriteHeader(http.StatusNoContent)
	case "/account":
		w.Header().Set("Location", base+"/account/1")
		if payload.OnlyReturnExisting {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		_, _ = io.WriteString(w, `{"status":"valid"}`)
	case "/new-order":
		if len(payload.Identifiers) != 1 {
			http.Error(w, "identifiers", 400)
			return
		}
		id = payload.Identifiers[0].Value
		a.count[id]++
		a.issuers[id], _, _ = net.SplitHostPort(r.RemoteAddr)
		if strings.HasPrefix(id, "fail-") {
			w.Header().Set("Content-Type", "application/problem+json")
			if id == "fail-long.e2e.test" {
				w.Header().Set("Retry-After", "172800")
			}
			w.WriteHeader(429)
			_ = json.NewEncoder(w).Encode(map[string]string{"type": "urn:ietf:params:acme:error:rateLimited", "detail": "lane rejection"})
			fmt.Println("rejected", id)
			return
		}

		a.orders[id] = "pending"
		a.mu.Unlock()
		fmt.Println("order", id)
		if id == "shared.e2e.test" {
			select {
			case <-a.proceed:
			case <-r.Context().Done():
			}
		}
		a.mu.Lock()
		if r.Context().Err() != nil {
			return
		}
		w.Header().Set("Location", base+"/order?id="+id)
		w.WriteHeader(http.StatusCreated)
		a.writeOrder(w, id)
	case "/order":
		a.writeOrder(w, id)
	case "/authorization":
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[bool]string{true: "valid", false: "pending"}[a.orders[id] != "pending"], "identifier": acme.AuthzID{Type: "dns", Value: id}, "challenges": []map[string]string{{"type": "http-01", "url": base + "/challenge?id=" + id, "token": authorityToken(id), "status": "pending"}}})
	case "/challenge":
		a.mu.Unlock()
		value, err := a.challenge(id)
		a.mu.Lock()
		if err != nil || value == "" {
			fmt.Println("challenge failed", id, err)
			http.Error(w, "challenge unavailable", 400)
			return
		}
		a.orders[id] = "ready"
		_ = json.NewEncoder(w).Encode(map[string]string{"type": "http-01", "url": base + "/challenge?id=" + id, "token": authorityToken(id), "status": "valid"})
	case "/finalize":
		csrDER, err := base64.RawURLEncoding.DecodeString(payload.CSR)
		if err != nil {
			http.Error(w, "CSR", 400)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "CSR signature", 400)
			return
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(len(a.chain) + 1)), DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, a.root, csr.PublicKey, a.key)
		if err != nil {
			http.Error(w, "sign", 500)
			return
		}
		fmt.Printf("issued %s %T\n", id, csr.PublicKey)

		a.chain[id] = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		a.orders[id] = "valid"
		a.writeOrder(w, id)
	case "/certificate":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(a.chain[id])
	default:
		http.NotFound(w, r)
	}
}

func (a *fakeAuthority) writeOrder(w http.ResponseWriter, id string) {
	_ = json.NewEncoder(w).Encode(map[string]any{"status": a.orders[id], "identifiers": []acme.AuthzID{{Type: "dns", Value: id}}, "authorizations": []string{a.base + "/authorization?id=" + id}, "finalize": a.base + "/finalize?id=" + id, "certificate": a.base + "/certificate?id=" + id})
}
