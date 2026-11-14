package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func regressionFixtures(cfg configuration, root *x509.Certificate, signer *ecdsa.PrivateKey) error {
	directory := cfg.Work + "/regressions"
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "journey intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(180 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, root, intermediateKey.Public(), signer)
	if err != nil {
		return err
	}
	intermediate, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	untrustedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	untrustedPEM, _, err := fixtureCertificate("journey CA", untrustedKey, nil, nil, time.Now().Add(365*24*time.Hour))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(untrustedPEM)
	untrusted, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	for _, item := range []struct {
		name, path string
		issuer     *x509.Certificate
		key        *ecdsa.PrivateKey
		chain      bool
	}{
		{"*.wild.e2e.test", cfg.Work + "/a/edge-certs/one.wild.e2e.test", root, signer, false},
		{"durability.e2e.test", directory + "/durability.e2e.test", root, signer, false},
		{"untrusted.chain.e2e.test", directory + "/untrusted.chain.e2e.test", untrusted, untrustedKey, false},
		{"incomplete.chain.e2e.test", directory + "/incomplete.chain.e2e.test", intermediate, intermediateKey, false},
		{"complete.chain.e2e.test", directory + "/complete.chain.e2e.test", intermediate, intermediateKey, true},
	} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		cert, private, err := fixtureCertificate(item.name, key, item.issuer, item.key, time.Now().Add(90*24*time.Hour))
		if err != nil {
			return err
		}
		data := append(private, cert...)
		if item.chain {
			data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Raw})...)
		}
		if err := os.WriteFile(item.path, data, 0600); err != nil {
			return err
		}
	}

	for _, name := range []string{"two.wild.e2e.test", "durability.e2e.test", "untrusted.chain.e2e.test", "incomplete.chain.e2e.test", "complete.chain.e2e.test"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		cert, private, err := fixtureCertificate("gru."+name, key, root, signer, time.Now().Add(90*24*time.Hour))
		if err != nil {
			return err
		}
		if err := os.WriteFile(cfg.Work+"/a/edge-certs/gru."+name, append(private, cert...), 0600); err != nil {
			return err
		}
	}
	return nil
}

func regressionWatch(ctx context.Context, conn *nats.Conn, key string) (jetstream.KeyWatcher, error) {
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	bucket, err := js.KeyValue(ctx, "edge-certs")
	if err != nil {
		return nil, err
	}
	return bucket.Watch(ctx, key)
}

func committedValue(ctx context.Context, watch jetstream.KeyWatcher, check func([]byte) bool) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, open := <-watch.Updates():
			if !open {
				return errors.New("certificate watch closed")
			}
			if entry != nil && check(entry.Value()) {
				return nil
			}
		}
	}
}

func regressionPair(ctx context.Context, cfg configuration, conn *nats.Conn, name string) error {
	data, err := os.ReadFile(cfg.Work + "/regressions/" + name)
	if err != nil {
		return err
	}
	seal, keyID, err := fixtureSeal(cfg)
	if err != nil {
		return err
	}
	value := laneEnvelope{Version: "v1", KeyID: keyID, Data: seal.Seal(nil, nil, data, []byte(name))}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	js, err := conn.JetStream()
	if err != nil {
		return err
	}
	_, err = js.Publish("$KV.edge-certs."+hex.EncodeToString([]byte(name)), encoded, nats.Context(ctx))
	return err
}

func regressionJourney(ctx context.Context, cfg configuration, current **process, store *process, startNode func(string, string, string, string) (*process, error), scenario string) error {
	conn, err := nats.Connect("nats://10.77.0.1:4223", nats.UserInfo("orch", "journey"))
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, step := range []struct {
		name string
		run  func(context.Context) error
	}{
		{"selection", func(ctx context.Context) error { return selectionJourney(ctx, cfg, conn, *current) }},
		{"chains", func(ctx context.Context) error { return chainsJourney(ctx, cfg, conn, *current) }},
		{"retirement", func(ctx context.Context) error { return retirementJourney(ctx, cfg, conn, *current) }},
		{"adoption", func(ctx context.Context) error { return adoptionJourney(ctx, cfg, conn, *current) }},
		{"durability", func(ctx context.Context) error { return durabilityJourney(ctx, cfg, conn, current, store, startNode) }},
	} {
		if scenario != "journey" && scenario != step.name {
			continue
		}
		bounded, cancel := context.WithTimeout(ctx, time.Minute)
		err := step.run(bounded)
		cancel()
		if err != nil {
			return fmt.Errorf("%s regression: %w", step.name, err)
		}
	}
	return nil
}

func selectionJourney(ctx context.Context, cfg configuration, conn *nats.Conn, current *process) error {
	name := "two.wild.e2e.test"
	_, keyID, err := fixtureSeal(cfg)
	if err != nil {
		return err
	}
	value := laneEnvelope{Version: "v1", KeyID: keyID, Retry: laneRetry{Next: time.Now().Add(48 * time.Hour), Updated: time.Now()}}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	js, err := conn.JetStream()
	if err != nil {
		return err
	}
	if _, err := js.Publish("$KV.edge-certs."+hex.EncodeToString([]byte(name)), data, nats.Context(ctx)); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "selection", []string{name}); err != nil {
		return err
	}
	if err := current.wait(ctx, "edge certificate renewal deferred name="+name+" ", 1); err != nil {
		return err
	}
	served, err := fingerprint(cfg, "10.77.0.2", name, false)
	if err != nil {
		return err
	}
	wildcard, err := fileFingerprint(cfg.Work + "/a/edge-certs/one.wild.e2e.test")
	if err != nil || served != wildcard {
		return errors.New("handshake did not select the wildcard certificate")
	}
	if err := ready("10.77.0.2"); err != nil {
		return fmt.Errorf("wildcard handshake succeeds but readiness fails: %w", err)
	}
	if err := removeRoute(ctx, cfg, "a", "selection"); err != nil {
		return err
	}
	fmt.Println("PASS readiness counts the wildcard certificate selected by a real HTTPS handshake for a different cache key")
	return nil
}

func chainsJourney(ctx context.Context, cfg configuration, conn *nats.Conn, current *process) error {
	for _, label := range []string{"untrusted", "incomplete", "complete"} {
		name := label + ".chain.e2e.test"
		if err := regressionPair(ctx, cfg, conn, name); err != nil {
			return err
		}
		if err := route(ctx, cfg, "a", label, []string{name}); err != nil {
			return err
		}
		if err := current.wait(ctx, "edge certificate installed name="+name+" ", 1); err != nil {
			return err
		}
		_, handshakeErr := fingerprint(cfg, "10.77.0.2", name, false)
		if label == "complete" {
			if handshakeErr != nil {
				return handshakeErr
			}
			if err := ready("10.77.0.2"); err != nil {
				return err
			}
		} else {
			var unknown x509.UnknownAuthorityError
			if !errors.As(handshakeErr, &unknown) {
				return fmt.Errorf("%s handshake did not reject its chain: %v", label, handshakeErr)
			}
			if err := pendingReadiness("10.77.0.2", name); err != nil {
				return err
			}
		}
		if err := removeRoute(ctx, cfg, "a", label); err != nil {
			return err
		}
	}
	fmt.Println("PASS readiness agrees with HTTPS clients: untrusted and incomplete chains rejected, complete intermediate chain accepted")
	return nil
}

type regressionHoldings struct {
	Version      string
	Registered   []string
	Certificates map[string]json.RawMessage
}

func retirementJourney(ctx context.Context, cfg configuration, conn *nats.Conn, current *process) error {
	js, err := conn.JetStream()
	if err != nil {
		return err
	}
	key := "holdings." + hex.EncodeToString([]byte("ts-gru-1"))
	initial, err := regressionWatch(ctx, conn, key)
	if err != nil {
		return err
	}
	defer initial.Stop()
	if err := committedValue(ctx, initial, func(data []byte) bool {
		var holdings regressionHoldings
		return json.Unmarshal(data, &holdings) == nil && holdings.Version == "v1"
	}); err != nil {
		return err
	}
	entry, err := js.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+key, nats.Context(ctx))
	if err != nil {
		return err
	}
	var holdings regressionHoldings
	if err := json.Unmarshal(entry.Data, &holdings); err != nil {
		return err
	}
	holdings.Registered = append(holdings.Registered, "retired.e2e.test")
	data, err := json.Marshal(holdings)
	if err != nil {
		return err
	}
	if _, err := js.Publish("$KV.edge-certs."+key, data, nats.ExpectLastSequencePerSubject(entry.Sequence), nats.Context(ctx)); err != nil {
		return err
	}
	watch, err := regressionWatch(ctx, conn, key)
	if err != nil {
		return err
	}
	defer watch.Stop()
	name := "after-retirement.e2e.test"
	if err := route(ctx, cfg, "a", "retirement", []string{name}); err != nil {
		return err
	}
	if err := committedValue(ctx, watch, func(data []byte) bool {
		return json.Unmarshal(data, &holdings) == nil && !slices.Contains(holdings.Registered, "retired.e2e.test")
	}); err != nil {
		return fmt.Errorf("retired member retained in published roster: %w", err)
	}
	if err := current.wait(ctx, "edge certificate installed name="+name+" ", 1); err != nil {
		return err
	}
	if _, err := fingerprint(cfg, "10.77.0.2", name, false); err != nil {
		return err
	}
	counts, err := fetchCounts()
	if err != nil {
		return err
	}
	if counts[name] != 1 {
		return fmt.Errorf("new name after retirement: %d orders", counts[name])
	}
	if err := removeRoute(ctx, cfg, "a", "retirement"); err != nil {
		return err
	}
	fmt.Println("PASS persisted inventory drops a retired member absent from the live roster; a new hostname obtains one certificate and serves HTTPS")
	return nil
}

func adoptionJourney(ctx context.Context, cfg configuration, conn *nats.Conn, current *process) error {
	name := "adoption.e2e.test"
	pidData, err := os.ReadFile(cfg.Work + "/a.pid")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		return err
	}
	watch, err := regressionWatch(ctx, conn, hex.EncodeToString([]byte(name)))
	if err != nil {
		return err
	}
	defer watch.Stop()
	debugger, err := launch(ctx, cfg.Work+"/adoption-debugger", nil, "gdb", "--nx", "--quiet", "--batch",
		"-ex", "handle SIGPIPE nostop noprint pass", "-ex", "handle SIGURG nostop noprint pass", "-ex", "set pagination off", "-ex", "set confirm off", "-ex", "set auto-load off", "-ex", "set print frame-arguments none", "-ex", "set print thread-events off",
		"-ex", fmt.Sprintf("attach %d", pid), "-ex", "break 'github.com/TerraScale/ts-orchestrator/internal/edge.(*certificateCache).lease'",
		"-ex", "echo READY adoption debugger\\n", "-ex", "continue", "-ex", "delete", "-ex", "break 'github.com/TerraScale/ts-orchestrator/internal/edge.(*certificateCache).write'", "-ex", "continue",
		"-ex", "shell ip netns exec cert-a iptables -I OUTPUT -p tcp --sport 4223 -s 127.0.0.1 -m string --string '\"stream\":\"KV_edge-certs\"' --algo bm -j DROP", "-ex", "echo ACK WITHHELD\\n", "-ex", "detach")
	if err != nil {
		return err
	}
	defer debugger.stop()
	rule := []string{"ip", "netns", "exec", "cert-a", "iptables", "-D", "OUTPUT", "-p", "tcp", "--sport", "4223", "-s", "127.0.0.1", "-m", "string", "--string", "\"stream\":\"KV_edge-certs\"", "--algo", "bm", "-j", "DROP"}
	defer func() { _ = command(rule...) }()
	defer syscall.Kill(pid, syscall.SIGCONT)
	if err := debugger.wait(ctx, "READY adoption debugger", 1); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "adoption", []string{name}); err != nil {
		return err
	}
	if err := debugger.wait(ctx, "ACK WITHHELD", 1); err != nil {
		return err
	}
	if err := current.wait(ctx, "edge certificate unavailable name="+name+" ", 1); err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return err
	}
	if err := command(rule...); err != nil {
		return err
	}
	var reserved laneEnvelope
	if err := committedValue(ctx, watch, func(data []byte) bool {
		return json.Unmarshal(data, &reserved) == nil && reserved.Lease.Generation != ""
	}); err != nil {
		return err
	}
	reserved.Retry = laneRetry{Attempt: reserved.Retry.Attempt, Next: time.Now().Add(48 * time.Hour), Updated: time.Now()}
	data, err := json.Marshal(reserved)
	if err != nil {
		return err
	}
	js, err := conn.JetStream()
	if err != nil {
		return err
	}
	_, revision, err := readEnvelope(ctx, js, name)
	if err != nil {
		return err
	}
	if _, err := js.Publish("$KV.edge-certs."+hex.EncodeToString([]byte(name)), data, nats.ExpectLastSequencePerSubject(revision), nats.Context(ctx)); err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return err
	}
	if err := removeRoute(ctx, cfg, "a", "adoption"); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "adoption", []string{name}); err != nil {
		return err
	}
	if err := current.wait(ctx, "reason=\"retry deadline extended past unacknowledged reservation\"", 1); err != nil {
		after, _, readErr := readEnvelope(ctx, js, name)
		return fmt.Errorf("adoption ignored the longer authority deadline: wanted=%s actual=%s generation_changed=%t read=%v: %w", reserved.Retry.Next.Format(time.RFC3339Nano), after.Retry.Next.Format(time.RFC3339Nano), after.Lease.Generation != reserved.Lease.Generation, readErr, err)
	}
	after, _, err := readEnvelope(ctx, js, name)
	if err != nil {
		return err
	}
	if after.Retry.Next.Before(reserved.Retry.Next) || after.Lease.Generation != reserved.Lease.Generation {
		return errors.New("adoption shortened deadline or replaced the held lease")
	}
	counts, err := fetchCounts()
	if err != nil {
		return err
	}
	if counts[name] != 0 {
		return errors.New("adoption made an order before the authority deadline")
	}
	if err := removeRoute(ctx, cfg, "a", "adoption"); err != nil {
		return err
	}
	fmt.Println("PASS unacknowledged lease adoption preserves a peer-published 48h authority deadline and generation; zero authority orders")
	return nil
}

func durabilityJourney(ctx context.Context, cfg configuration, conn *nats.Conn, current **process, store *process, startNode func(string, string, string, string) (*process, error)) error {
	name := "durability.e2e.test"
	path := filepath.Join(cfg.Work, "a", "edge-certs", name)
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	if err := regressionPair(ctx, cfg, conn, name); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "durability", []string{name}); err != nil {
		return err
	}
	if err := (*current).wait(ctx, "edge certificate unavailable name="+name+" ", 1); err != nil {
		return err
	}
	served, err := fingerprint(cfg, "10.77.0.2", name, false)
	if err != nil {
		return fmt.Errorf("certificate not served during disk failure: %w", err)
	}
	if metric, err := observationMetric("10.77.0.2", "ts_orch_edge_certificate_not_durable"); err != nil || metric != 1 {
		return fmt.Errorf("disk failure metric: %g %v", metric, err)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	key := "holdings." + hex.EncodeToString([]byte("ts-gru-1"))
	watch, err := regressionWatch(ctx, conn, key)
	if err != nil {
		return err
	}
	defer watch.Stop()
	if err := route(ctx, cfg, "a", "durability-recovered", []string{name}); err != nil {
		return err
	}
	if err := committedValue(ctx, watch, func(data []byte) bool {
		var holdings regressionHoldings
		return json.Unmarshal(data, &holdings) == nil && holdings.Certificates[name] != nil
	}); err != nil {
		return err
	}
	disk, err := fileFingerprint(path)
	if err != nil || disk != served {
		return fmt.Errorf("served certificate not durable after disk recovery: fingerprint=%s error=%v", disk, err)
	}
	if metric, err := observationMetric("10.77.0.2", "ts_orch_edge_certificate_not_durable"); err != nil || metric != 0 {
		return fmt.Errorf("recovered disk metric: %g %v", metric, err)
	}
	(*current).stop()
	if err := store.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		return err
	}
	defer store.cmd.Process.Signal(syscall.SIGCONT)
	restarted, err := startNode("a", cfg.Binary, "durability-restart", "oracle")
	if err != nil {
		return err
	}
	*current = restarted
	if err := restarted.wait(ctx, "edge certificate installed name="+name+" ", 1); err != nil {
		return err
	}
	if err := restarted.wait(ctx, "edge readiness changed ready=true", 1); err != nil {
		return err
	}
	recovered, err := fingerprint(cfg, "10.77.0.2", name, false)
	if err != nil || recovered != served {
		return fmt.Errorf("restart with unavailable store lost certificate: fingerprint=%s error=%v", recovered, err)
	}
	if err := store.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		return err
	}
	fmt.Println("PASS certificate serves during disk failure, becomes durable after recovery (metric 1 -> 0), survives process restart with the store unavailable")
	return nil
}
