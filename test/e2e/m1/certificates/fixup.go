package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

type laneRetry struct {
	Attempt int
	Next    time.Time
	Updated time.Time
}

type laneEnvelope struct {
	Version string
	KeyID   string
	Data    []byte
	Lease   struct {
		Generation string
		Until      time.Time
	}
	Retry laneRetry
}

func readEnvelope(ctx context.Context, js nats.JetStreamContext, name string) (laneEnvelope, uint64, error) {
	entry, err := js.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+hex.EncodeToString([]byte(name)), nats.Context(ctx))
	if err != nil {
		return laneEnvelope{}, 0, err
	}
	var value laneEnvelope
	err = json.Unmarshal(entry.Data, &value)
	return value, entry.Sequence, err
}

func fixtureSeal(cfg configuration) (cipher.AEAD, string, error) {
	secret, err := hex.DecodeString(cfg.MeshSeed)
	if err != nil {
		return nil, "", err
	}
	defer clear(secret)
	seed, err := hkdf.Key(sha256.New, secret, nil, "ts-orch mesh ca v1", 32)
	if err != nil {
		return nil, "", err
	}
	defer clear(seed)
	key, err := hkdf.Key(sha256.New, seed, nil, "ts-orch edge certificates v1", 32)
	if err != nil {
		return nil, "", err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", err
	}
	seal, err := cipher.NewGCMWithRandomNonce(block)
	digest := sha256.Sum256(key)
	return seal, "mesh-v1:" + hex.EncodeToString(digest[:8]), err
}

func fileFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return "", errors.New("invalid fixture certificate")
	}
	digest := sha256.Sum256(cert.Leaf.Raw)
	return hex.EncodeToString(digest[:]), nil
}

func fetchCounts() (map[string]int, error) {
	response, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://10.77.0.1:8088/counts")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var counts map[string]int
	err = json.NewDecoder(response.Body).Decode(&counts)
	return counts, err
}

func getText(address string) (string, error) {
	response, err := (&http.Client{Timeout: 3 * time.Second}).Get(address)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	return string(data), err
}

func waitUntil(ctx context.Context, deadline time.Time) error {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func failureDeadline(p *process, name string, attempt int, duration time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, line := range p.lines {
		if !strings.Contains(line, "edge certificate order failed name="+name+" ") || !strings.Contains(line, fmt.Sprintf("attempt=%d ", attempt)) {
			continue
		}
		values := map[string]string{}
		for _, field := range strings.Fields(line) {
			if key, value, ok := strings.Cut(field, "="); ok {
				values[key] = value
			}
		}
		failed, err := time.Parse(time.RFC3339Nano, values["failed_at"])
		if err != nil {
			return err
		}
		next, err := time.Parse(time.RFC3339Nano, values["next_attempt"])
		if err != nil {
			return err
		}
		if next.Sub(failed) != duration {
			return fmt.Errorf("%s attempt %d cooldown %s, want %s", name, attempt, next.Sub(failed), duration)
		}
		return nil
	}
	return fmt.Errorf("missing failure warning %s attempt %d", name, attempt)
}

func fixupJourney(ctx context.Context, cfg configuration, conn *nats.Conn, authority, current, second, store *process) error {
	js, err := conn.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return err
	}
	unknownEntries := map[string]*nats.RawStreamMsg{}
	for _, name := range []string{"unknown.e2e.test", "unknown-local.e2e.test"} {
		entry, err := js.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+hex.EncodeToString([]byte(name)), nats.Context(ctx))
		if err != nil {
			return err
		}
		unknownEntries[name] = entry
	}
	seal, keyID, err := fixtureSeal(cfg)
	if err != nil {
		return err
	}
	pidData, err := os.ReadFile(cfg.Work + "/a.pid")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		return err
	}
	stageCtx, stopStage := context.WithTimeout(ctx, time.Minute)
	defer stopStage()
	debugger, err := launch(ctx, cfg.Work+"/debugger", nil, "gdb", "--nx", "--quiet", "--batch",
		"-ex", "handle SIGPIPE nostop noprint pass", "-ex", "handle SIGURG nostop noprint pass", "-ex", "set pagination off", "-ex", "set confirm off", "-ex", "set auto-load off", "-ex", "set print frame-arguments none", "-ex", "set print thread-events off",
		"-ex", fmt.Sprintf("attach %d", pid), "-ex", "break 'github.com/TerraScale/ts-orchestrator/internal/edge.(*issuanceLease).finish'",
		"-ex", "echo READY debugger\\n", "-ex", "continue",
		"-ex", fmt.Sprintf("shell export PATH=\"$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH\"; kill -STOP %d", pid), "-ex", "detach")
	if err != nil {
		return err
	}
	defer debugger.stop()
	if err := debugger.wait(stageCtx, "Breakpoint 1 at", 1); err != nil {
		return err
	}
	if err := debugger.wait(stageCtx, "READY debugger", 1); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "fenced", []string{"fenced.e2e.test"}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-debugger.done:
	case <-stageCtx.Done():
		return stageCtx.Err()
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return err
	}
	if !bytes.Contains(status, []byte("State:\tT")) {
		return errors.New("issuer not SIGSTOPed after issuance")
	}
	paused, err := fileFingerprint(cfg.Work + "/a/edge-certs/fenced.e2e.test")
	if err != nil {
		return err
	}
	fenced, _, err := readEnvelope(ctx, js, "fenced.e2e.test")
	if err != nil {
		return err
	}
	if len(fenced.Data) != 0 || fenced.Lease.Generation == "" {
		return errors.New("paused issuer published before fence check")
	}

	fmt.Println("PASS issuer SIGSTOPed after local installation, before publication; waiting for real ten-minute lease expiry")
	for _, name := range []string{"fail-second.e2e.test"} {
		value := laneEnvelope{Version: "v1", KeyID: keyID, Retry: laneRetry{Attempt: 1, Next: time.Now().Add(-time.Minute), Updated: time.Now().Add(-time.Hour)}}
		data, _ := json.Marshal(value)
		if _, err := js.Publish("$KV.edge-certs."+hex.EncodeToString([]byte(name)), data, nats.Context(ctx)); err != nil {
			return err
		}
	}
	beforeEqual := []string{}
	for _, node := range []string{"a", "b"} {
		fp, err := fileFingerprint(cfg.Work + "/" + node + "/edge-certs/equal.e2e.test")
		if err != nil {
			return err
		}
		beforeEqual = append(beforeEqual, fp)
	}
	for _, node := range []string{"b"} {
		if err := route(ctx, cfg, node, "fixup", []string{"unknown-local.e2e.test", "ecdsa-renew.e2e.test", "rsa-renew-rsa.e2e.test", "equal.e2e.test", "fail-first.e2e.test", "fail-second.e2e.test", "fail-long.e2e.test"}); err != nil {
			return err
		}
	}
	for _, name := range []string{"ecdsa-renew.e2e.test", "rsa-renew-rsa.e2e.test+rsa"} {
		if err := second.wait(ctx, "edge certificate installed name="+name+" ", 2); err != nil {
			return err
		}
	}
	for _, name := range []string{"fail-first.e2e.test", "fail-second.e2e.test", "fail-long.e2e.test"} {
		if err := second.wait(ctx, "edge certificate order failed name="+name+" ", 1); err != nil {
			return err
		}
	}
	if err := failureDeadline(second, "fail-first.e2e.test", 1, 30*time.Minute); err != nil {
		return err
	}
	if err := failureDeadline(second, "fail-second.e2e.test", 2, time.Hour); err != nil {
		return err
	}
	long, _, err := readEnvelope(ctx, js, "fail-long.e2e.test")
	if err != nil {
		return err
	}
	if long.Retry.Next.Sub(long.Retry.Updated) < 48*time.Hour {
		return errors.New("authority Retry-After shortened")
	}
	for _, item := range []struct {
		name     string
		attempt  int
		duration time.Duration
	}{{"fail-first.e2e.test", 1, 30 * time.Minute}, {"fail-second.e2e.test", 2, time.Hour}} {
		value, _, err := readEnvelope(ctx, js, item.name)
		if err != nil {
			return err
		}
		if value.Retry.Attempt != item.attempt || value.Retry.Next.Sub(value.Retry.Updated) != item.duration {
			return errors.New("shared retry deadline differs from warning")
		}
		data, err := os.ReadFile(cfg.Work + "/b/edge-certs/.state-" + item.name)
		if err != nil {
			return err
		}
		var state struct{ Retry laneRetry }
		if json.Unmarshal(data, &state) != nil || !state.Retry.Next.Equal(value.Retry.Next) {
			return errors.New("retry deadline not persisted on disk")
		}
	}
	metrics, err := getText("http://10.77.0.3/edge/certificates/metrics")
	if err != nil {
		return err
	}
	if !strings.Contains(metrics, `ts_orch_edge_certificate_order_failures_total{name="fail-first.e2e.test",variant="ecdsa"} 1`) || !strings.Contains(metrics, "ts_orch_edge_certificate_unsupported 1") {
		return errors.New("failure or unsupported metric missing")
	}
	readsBefore, err := getText("http://10.77.0.1:8090")
	if err != nil {
		return err
	}
	for range 32 {
		request, _ := http.NewRequest(http.MethodGet, "http://10.77.0.3/.well-known/acme-challenge/"+authorityToken("idle"), nil)
		request.Host = "existing.e2e.test"
		response, err := (&http.Client{Timeout: 2 * time.Second}).Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			return fmt.Errorf("idle challenge HTTP %d", response.StatusCode)
		}
	}
	readsAfter, err := getText("http://10.77.0.1:8090")
	if err != nil {
		return err
	}
	if readsBefore != readsAfter {
		return errors.New("idle challenge requests read shared tokens")
	}
	if readsAfter == "0" {
		return errors.New("store read instrumentation never saw live challenges")
	}
	fmt.Println("PASS challenge-shaped requests without live issuance: 32 HTTP 404 responses, zero store reads")
	if err := waitUntil(ctx, time.Now().Add(11*time.Second)); err != nil {
		return err
	}
	counts, err := fetchCounts()
	if err != nil {
		return err
	}
	for _, name := range []string{"fail-first.e2e.test", "fail-second.e2e.test", "fail-long.e2e.test"} {
		if counts[name] != 1 {
			return fmt.Errorf("cooldown %s: %d orders", name, counts[name])
		}
	}
	for _, name := range []string{"unknown.e2e.test", "unknown-local.e2e.test"} {
		value, _, err := readEnvelope(ctx, js, name)
		if err != nil {
			return err
		}
		if value.Version != "v999" || !bytes.Equal(value.Data, []byte{0}) || counts[name] != 0 {
			return errors.New("unsupported envelope overwritten or ordered")
		}
	}
	if counts["ecdsa-renew.e2e.test"] != 1 || counts["rsa-renew-rsa.e2e.test"] != 1 {
		return fmt.Errorf("variant order counts: ECDSA=%d RSA=%d", counts["ecdsa-renew.e2e.test"], counts["rsa-renew-rsa.e2e.test"])
	}
	for _, item := range []struct {
		name    string
		variant string
	}{{"ecdsa-renew.e2e.test", "*ecdsa.PublicKey"}, {"rsa-renew-rsa.e2e.test", "*rsa.PublicKey"}} {
		if err := authority.wait(ctx, "issued "+item.name+" "+item.variant, 1); err != nil {
			return err
		}
	}
	if _, err := fingerprint(cfg, "10.77.0.3", "rsa-renew-rsa.e2e.test", false); err != nil {
		return err
	}
	fmt.Println("PASS variants: ECDSA 10d/RSA 90d -> one ECDSA, zero RSA; ECDSA 90d/RSA 10d -> one RSA saved as +rsa and served to RSA-only client")
	fmt.Println("PASS unsupported v999 preserved; no orders; local copy served; unsupported count and per-variant failure counters exposed")
	fmt.Println("PASS failure deadlines exactly 30m then 60m; shared and disk copies match; 48h authority Retry-After retained; no early orders")
	if err := waitUntil(ctx, fenced.Lease.Until.Add(time.Second)); err != nil {
		return err
	}
	unchanged, revision, err := readEnvelope(ctx, js, "fenced.e2e.test")
	if err != nil {
		return err
	}
	if len(unchanged.Data) != 0 || unchanged.Lease.Generation != fenced.Lease.Generation {
		return errors.New("expired paused issuer published")
	}
	unchanged.Retry.Next = time.Now().Add(-time.Second)
	unchanged.Retry.Updated = time.Now()
	data, _ := json.Marshal(unchanged)
	if _, err := js.Publish("$KV.edge-certs."+hex.EncodeToString([]byte("fenced.e2e.test")), data, nats.ExpectLastSequencePerSubject(revision), nats.Context(ctx)); err != nil {
		return err
	}
	if err := route(ctx, cfg, "b", "fenced", []string{"fenced.e2e.test"}); err != nil {
		return err
	}
	if err := second.wait(ctx, "edge certificate installed name=fenced.e2e.test ", 1); err != nil {
		return err
	}

	replacement, err := fingerprint(cfg, "10.77.0.3", "fenced.e2e.test", false)
	if err != nil {
		return err
	}
	if replacement == paused {
		return errors.New("next holder did not replace paused issuer")
	}
	if err := current.cmd.Process.Signal(syscall.SIGCONT); err != nil {
		return err
	}
	if err := current.wait(ctx, "certificate issuance lease lost", 1); err != nil {
		return err
	}
	if _, err := fingerprint(cfg, "10.77.0.2", "fenced.e2e.test", false); err != nil {
		return err
	}
	published, _, err := readEnvelope(ctx, js, "fenced.e2e.test")
	if err != nil {
		return err
	}
	plain, err := seal.Open(nil, nil, published.Data, []byte("fenced.e2e.test"))
	if err != nil {
		return errors.New("cannot decrypt shared certificate using mesh seed")
	}
	cert, err := tls.X509KeyPair(plain, plain)
	clear(plain)
	if err != nil {
		return errors.New("shared certificate invalid")
	}
	digest := sha256.Sum256(cert.Leaf.Raw)
	if hex.EncodeToString(digest[:]) != replacement {
		return errors.New("stale issuer published over next holder")
	}
	fmt.Println("PASS issuer SIGSTOP beyond actual 10m lease: next holder publishes, resumed issuer cannot publish, resumed node serves valid TLS; reserved cooldown matured as fixture input")
	if err := route(ctx, cfg, "a", "fixup", []string{"unknown.e2e.test", "unknown-local.e2e.test", "equal.e2e.test", "fail-first.e2e.test", "fail-second.e2e.test", "fail-long.e2e.test"}); err != nil {
		return err
	}
	if err := route(ctx, cfg, "b", "unsupported-missing", []string{"unknown.e2e.test"}); err != nil {
		return err
	}
	if err := second.wait(ctx, "edge certificate envelope unsupported name=unknown.e2e.test ", 1); err != nil {
		return err
	}
	if err := current.wait(ctx, "edge certificate envelope unsupported name=unknown.e2e.test ", 1); err != nil {
		return err
	}
	if _, err := fingerprint(cfg, "10.77.0.2", "unknown-local.e2e.test", false); err != nil {
		return err
	}
	if _, err := fingerprint(cfg, "10.77.0.3", "unknown-local.e2e.test", false); err != nil {
		return err
	}
	if err := waitUntil(ctx, time.Now().Add(11*time.Second)); err != nil {
		return err
	}
	for _, address := range []string{"10.77.0.2", "10.77.0.3"} {
		metrics, err := getText("http://" + address + "/edge/certificates/metrics")
		if err != nil {
			return err
		}
		if !strings.Contains(metrics, "ts_orch_edge_certificate_unsupported 2") {
			return errors.New("unsupported count missing after both nodes reconciled")
		}
		got, err := fingerprint(cfg, address, "equal.e2e.test", false)
		if err != nil {
			return err
		}
		if got != min(beforeEqual[0], beforeEqual[1]) {
			return errors.New("equal-expiry certificates failed to converge to lower fingerprint")
		}
	}
	for _, name := range []string{"unknown.e2e.test", "unknown-local.e2e.test"} {
		value, _, err := readEnvelope(ctx, js, name)
		if err != nil {
			return err
		}
		if value.Version != "v999" || !bytes.Equal(value.Data, []byte{0}) {
			return errors.New("unknown envelope changed after both nodes reconciled")
		}
	}
	for name, original := range unknownEntries {
		entry, err := js.GetLastMsg("KV_edge-certs", "$KV.edge-certs."+hex.EncodeToString([]byte(name)), nats.Context(ctx))
		if err != nil {
			return err
		}
		if entry.Sequence != original.Sequence || !bytes.Equal(entry.Data, original.Data) {
			return errors.New("unsupported envelope bytes or revision changed")
		}
	}
	counts, err = fetchCounts()
	if err != nil {
		return err
	}
	if counts["fail-first.e2e.test"] != 1 || counts["fail-second.e2e.test"] != 1 || counts["unknown.e2e.test"] != 0 || counts["unknown-local.e2e.test"] != 0 {
		return errors.New("another node bypassed shared cooldown or unsupported envelope")
	}
	fmt.Println("PASS equal-expiry convergence to lower fingerprint; both nodes preserve unsupported envelopes and honor shared cooldown")
	return nil
}
