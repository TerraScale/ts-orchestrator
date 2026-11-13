package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"golang.org/x/sys/unix"
)

func challengeSyntax(ctx context.Context, cfg configuration, client *http.Client) error {
	for _, token := range []string{strings.Repeat("a", 20) + "-_", strings.Repeat("Z", 126) + "-_", strings.Repeat("a", 21), strings.Repeat("a", 129), strings.Repeat("a", 21) + "!"} {
		if err := tokenLookup(ctx, cfg, client, token); err != nil {
			return err
		}
	}
	ca, err := mesh.DeriveCA([]byte(strings.Repeat("certificate-journey", 2)))
	if err != nil {
		return err
	}
	config := ca.TLS("journey." + mesh.Domain).Clone()
	config.ServerName = "replay." + mesh.Domain
	transport := &http.Transport{TLSClientConfig: config}
	defer transport.CloseIdleConnections()
	peer := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	for _, pair := range []struct{ source, target, address string }{{"previous", "b", "10.77.0.2"}, {"b", "previous", "10.77.0.3"}} {
		token := authorityToken(pair.source + "-to-" + pair.target)
		body := token + ".journey"
		path := cfg.Work + "/" + pair.target + "/edge-certs/" + token + "+http-01"
		if err = os.WriteFile(path, []byte(body), 0600); err != nil {
			return err
		}
		status, data, err := request(ctx, client, pair.address, "/.well-known/acme-challenge/"+token)
		if err != nil || status != 200 || string(data) != body {
			return fmt.Errorf("%s to %s peer token: status=%d body=%s error=%v", pair.source, pair.target, status, data, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+pair.address+"/.well-known/acme-challenge/"+token, nil)
		if err != nil {
			return err
		}
		req.Host = "shared.e2e.test"
		response, err := peer.Do(req)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			return fmt.Errorf("%s peer request forwarded beyond local storage: %d", pair.source, response.StatusCode)
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	fmt.Println("PASS token boundaries: 22/128 reach lookup; 21/129/non-base64url return 404 with zero storage lookups; old/new peer lookup both directions and peer requests local-only")
	return nil
}

func tokenLookup(ctx context.Context, cfg configuration, client *http.Client, token string) error {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	body := token + ".journey"
	for _, node := range []string{"previous", "b", "c"} {
		directory := cfg.Work + "/" + node + "/edge-certs"
		if err = os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		path := directory + "/" + token + "+http-01"
		if err = os.WriteFile(path, []byte(body), 0600); err != nil {
			return err
		}
		defer os.Remove(path)
		if _, err = unix.InotifyAddWatch(fd, path, unix.IN_OPEN); err != nil {
			return err
		}
	}
	valid := token == strings.Repeat("a", 20)+"-_" || token == strings.Repeat("Z", 126)+"-_"
	want := 404
	if valid {
		want = 200
	}
	status, data, err := request(ctx, client, "10.77.0.3", "/.well-known/acme-challenge/"+token)
	if err != nil || status != want || valid && string(data) != body {
		return fmt.Errorf("token length=%d: status=%d want=%d error=%v", len(token), status, want, err)
	}
	events := make([]byte, 4096)
	n, readErr := unix.Read(fd, events)
	if valid && (readErr != nil || n == 0) {
		return fmt.Errorf("valid token length=%d did not reach storage: %v", len(token), readErr)
	}
	if !valid && (n > 0 || !errors.Is(readErr, unix.EAGAIN)) {
		return fmt.Errorf("malformed token length=%d caused storage lookup: bytes=%d error=%v", len(token), n, readErr)
	}
	return nil
}

type storedFile struct {
	Digest [32]byte
	Size   int64
	Mode   fs.FileMode
}

func storageSnapshot(directory string) (map[string]storedFile, error) {
	files := map[string]storedFile{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected certificate storage entry %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		files[name] = storedFile{sha256.Sum256(data), info.Size(), info.Mode()}
		return nil
	})
	return files, err
}

func authorityCounts(ctx context.Context, cfg configuration) (map[string]int, error) {
	data, err := os.ReadFile(cfg.Work + "/ca.pem")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid authority root")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "acme-v02.api.letsencrypt.org", MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://10.77.0.1/counts", nil)
	if err != nil {
		return nil, err
	}
	response, err := (&http.Client{Transport: tr, Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("authority counts status=%d", response.StatusCode)
	}
	counts := map[string]int{}
	err = json.NewDecoder(response.Body).Decode(&counts)
	return counts, err
}

func selectedCertificate(address, name string, rsaOnly bool) ([]byte, error) {
	config := &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
	if rsaOnly {
		config.MaxVersion = tls.VersionTLS12
		config.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 20 * time.Second}, "tcp", address+":443", config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	leaf := conn.ConnectionState().PeerCertificates[0]
	if rsaOnly && leaf.PublicKeyAlgorithm != x509.RSA {
		return nil, errors.New("RSA client received another key type")
	}
	return leaf.Raw, nil
}

func rsaServing(address string, certificate []byte) error {
	block, _ := pem.Decode(certificate)
	if block == nil {
		return errors.New("missing RSA certificate")
	}
	served, err := selectedCertificate(address, "shared.e2e.test", true)
	if err != nil {
		return fmt.Errorf("RSA-only name TLS failed while not ready: %w", err)
	}
	if sha256.Sum256(served) != sha256.Sum256(block.Bytes) {
		return errors.New("RSA-only name served another certificate")
	}
	return nil
}

func warmCache(ctx context.Context, cfg configuration, client *http.Client, nodes map[string]*process, env []string, ecdsaFingerprint string) error {
	rsaDER, err := selectedCertificate("10.77.0.2", "shared.e2e.test", true)
	if err != nil {
		return fmt.Errorf("previous build RSA issuance: %w", err)
	}
	nodes["previous"].stop()
	directory := cfg.Work + "/previous/edge-certs"
	before, err := storageSnapshot(directory)
	if err != nil {
		return err
	}
	for _, key := range []string{"shared.e2e.test", "shared.e2e.test+rsa", "acme_account+key"} {
		if _, ok := before[key]; !ok {
			return fmt.Errorf("warm storage missing %s", key)
		}
	}
	counts, err := authorityCounts(ctx, cfg)
	if err != nil {
		return err
	}
	if counts["shared.e2e.test"] != 2 {
		return fmt.Errorf("previous build orders=%v, want ECDSA and RSA", counts)
	}
	for _, build := range []string{"previous", "current", "rollback"} {
		args := []string{"ip", "netns", "exec", "cert-previous", cfg.Work + "/previous-edge", cfg.Work + "/lane.json"}
		if build == "current" {
			args = []string{"ip", "netns", "exec", "cert-previous", cfg.Work + "/certificates", "node", cfg.Work + "/lane.json", "previous", "gru"}
		}
		p, err := launch(ctx, cfg.Work+"/warm-"+build, env, args...)
		if err != nil {
			return err
		}
		nodes["previous"] = p
		if err = p.wait(ctx, "READY ", 1); err != nil {
			return err
		}
		if build == "current" {
			if err = checkReady(ctx, client, "10.77.0.2", 200); err != nil {
				return err
			}
			if err = cli(cfg, "previous", true); err != nil {
				return err
			}
		}
		for file := range before {
			data, err := os.ReadFile(filepath.Join(directory, file))
			if err != nil {
				return err
			}
			for len(data) > 0 {
				block, rest := pem.Decode(data)
				if block == nil {
					break
				}
				data = rest
				if block.Type != "CERTIFICATE" {
					continue
				}
				leaf, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return err
				}
				for _, name := range leaf.DNSNames {
					served, err := selectedCertificate("10.77.0.2", name, leaf.PublicKeyAlgorithm == x509.RSA)
					if err != nil {
						return fmt.Errorf("%s warm TLS %s/%s: %w", build, name, leaf.PublicKeyAlgorithm, err)
					}
					if sha256.Sum256(served) != sha256.Sum256(leaf.Raw) {
						return fmt.Errorf("%s changed TLS certificate for %s/%s", build, name, leaf.PublicKeyAlgorithm)
					}
				}
			}
		}
		fingerprint, err := handshake("10.77.0.2")
		if err != nil || fingerprint != ecdsaFingerprint {
			return fmt.Errorf("%s changed ECDSA certificate: %v", build, err)
		}
		servedRSA, err := selectedCertificate("10.77.0.2", "shared.e2e.test", true)
		if err != nil || sha256.Sum256(servedRSA) != sha256.Sum256(rsaDER) {
			return fmt.Errorf("%s changed RSA certificate: %v", build, err)
		}
		current, err := storageSnapshot(directory)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, current) {
			return fmt.Errorf("%s changed certificate storage digests, sizes or modes", build)
		}
		afterCounts, err := authorityCounts(ctx, cfg)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(counts, afterCounts) {
			return fmt.Errorf("%s placed new orders: %v -> %v", build, counts, afterCounts)
		}
		if build != "rollback" {
			p.stop()
			stopped, err := storageSnapshot(directory)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(before, stopped) {
				return fmt.Errorf("%s shutdown changed certificate storage", build)
			}
		}
		fmt.Println("PASS warm", build, "all file digests/sizes/modes identical, zero new orders, every stored name and both key types serve identical TLS certificates")
	}
	return nil
}
