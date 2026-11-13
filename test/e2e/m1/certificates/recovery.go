package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func laneCommand(ctx context.Context, cfg configuration, args ...string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	args = append([]string{"ip", "netns", "exec", "cert-a", "unshare", "--uts", self, "operator", os.Args[2], cfg.Binary}, args...)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "HTTPS_PROXY=http://10.77.0.1:8089", "NO_PROXY=169.254.169.254,127.0.0.1,10.77.0.0/24", "SSL_CERT_FILE="+cfg.Work+"/ca.pem")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("operator: %w: %s", err, output)
	}
	return nil
}

func recoveryJourney(ctx context.Context, cfg configuration, conn *nats.Conn, current *process) error {
	js, err := conn.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "metadata", []string{"metadata.e2e.test"}); err != nil {
		return err
	}
	if err := current.wait(ctx, "edge certificate unavailable name=metadata.e2e.test ", 1); err != nil {
		return err
	}
	issued, err := fingerprint(cfg, "10.77.0.2", "metadata.e2e.test", false)
	if err != nil {
		return fmt.Errorf("issued result lost after metadata error: %w", err)
	}
	disk, err := fileFingerprint(cfg.Work + "/a/edge-certs/metadata.e2e.test")
	if err != nil || issued != disk {
		return errors.New("issued result not saved before metadata failure")
	}
	if err := os.Remove(cfg.Work + "/a/edge-certs/.state-metadata.e2e.test"); err != nil {
		return err
	}
	if err := waitUntil(ctx, time.Now().Add(11*time.Second)); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.Work + "/a/edge-certs/.state-metadata.e2e.test"); err != nil {
		return fmt.Errorf("metadata not reconciled: %w", err)
	}
	counts, err := fetchCounts()
	if err != nil || counts["metadata.e2e.test"] != 1 {
		return errors.New("metadata failure spent another order")
	}
	fmt.Println("PASS metadata write fails after CA success: certificate atomically saved, installed, served; metadata reconciled, one order")

	key := "repair.e2e.test"
	value, revision, err := readEnvelope(ctx, js, key)
	if err != nil {
		return err
	}
	value.Data = []byte("unreadable")
	value.Lease.Generation, value.Lease.Until = "repair-holder", time.Now().Add(5*time.Minute)
	value.Retry = laneRetry{Attempt: 4, Next: time.Now().Add(8 * time.Hour), Updated: time.Now()}
	data, _ := json.Marshal(value)
	if _, err := js.Publish("$KV.edge-certs."+hex.EncodeToString([]byte(key)), data, nats.ExpectLastSequencePerSubject(revision), nats.Context(ctx)); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "repair", []string{key}); err != nil {
		return err
	}
	if err := current.wait(ctx, "edge certificate envelope unsupported name=repair.e2e.test ", 1); err != nil {
		return err
	}
	metrics, err := getText("http://10.77.0.2/edge/certificates/metrics")
	if err != nil || !strings.Contains(metrics, "ts_orch_edge_certificate_expiry_seconds{name=\"repair.e2e.test\",variant=\"ecdsa\"}") || !strings.Contains(metrics, "ts_orch_edge_certificate_blocked_names ") {
		return errors.New("expiry or blocked-name metrics missing")
	}
	if err := laneCommand(ctx, cfg, "edge", "certificates", "repair", "--state", cfg.Work+"/a", key, "ecdsa"); err != nil {
		return err
	}
	repaired, _, err := readEnvelope(ctx, js, key)
	if err != nil || repaired.Lease.Generation != value.Lease.Generation || !repaired.Lease.Until.Equal(value.Lease.Until) || repaired.Retry.Attempt != value.Retry.Attempt || !repaired.Retry.Next.Equal(value.Retry.Next) || !repaired.Retry.Updated.Equal(value.Retry.Updated) || bytes.Equal(repaired.Data, value.Data) {
		return errors.New("repair changed lease/cooldown or retained corrupt data")
	}
	seal, _, err := fixtureSeal(cfg)
	if err != nil {
		return err
	}
	plain, err := seal.Open(nil, nil, repaired.Data, []byte(key))
	if err != nil {
		return err
	}
	localRepair, err := os.ReadFile(cfg.Work + "/a/edge-certs/" + key)
	if err != nil || !bytes.Equal(plain, localRepair) {
		return errors.New("repaired ciphertext does not contain validated local key pair")
	}
	clear(plain)
	if err := laneCommand(ctx, cfg, "edge", "certificates", "repair", "--state", cfg.Work+"/a", "unknown-local.e2e.test", "ecdsa"); err == nil || !strings.Contains(err.Error(), "unsupported envelope version") {
		return errors.New("repair overwrote newer envelope format")
	}
	fmt.Println("PASS revision-conditional local repair restores ciphertext, preserves lease and cooldown; newer format refused; expiry and blocked-name metrics exposed")

	token := authorityToken("watch-delay")
	if _, err := js.Publish("$KV.edge-cert-tokens."+hex.EncodeToString([]byte("existing.e2e.test:"+token)), []byte("watch-delay-response"), nats.Context(ctx)); err != nil {
		return err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://10.77.0.2/.well-known/acme-challenge/"+token, nil)
	request.Host = "existing.e2e.test"
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	answer, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil || string(answer) != "watch-delay-response" {
		return errors.New("fallback challenge token mismatch")
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("challenge without watch delivery: %s", response.Status)
	}
	fmt.Println("PASS served-name challenge lookup succeeds without a watch-delivered live lease")

	committed, err := jetstream.New(conn)
	if err != nil {
		return err
	}
	bucket, err := committed.KeyValue(ctx, "edge-certs")
	if err != nil {
		return err
	}
	updates, err := bucket.Watch(ctx, hex.EncodeToString([]byte("fail-upload.e2e.test")))
	if err != nil {
		return err
	}
	defer updates.Stop()
	pidData, err := os.ReadFile(cfg.Work + "/a.pid")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	debugger, err := launch(ctx, cfg.Work+"/retry-debugger", nil, "gdb", "--nx", "--quiet", "--batch",
		"-ex", "handle SIGPIPE nostop noprint pass", "-ex", "handle SIGURG nostop noprint pass",
		"-ex", "set pagination off", "-ex", "set confirm off", "-ex", "set auto-load off",
		"-ex", "set print frame-arguments none",
		"-ex", fmt.Sprintf("attach %d", pid),
		"-ex", "break 'github.com/TerraScale/ts-orchestrator/internal/edge.(*issuanceLease).finish'",
		"-ex", "echo READY retry debugger\\n", "-ex", "continue",
		"-ex", fmt.Sprintf("shell kill -STOP %d", pid), "-ex", "detach")
	if err != nil {
		return err
	}
	defer debugger.stop()
	if err := debugger.wait(bounded, "READY retry debugger", 1); err != nil {
		return err
	}
	if err := route(ctx, cfg, "a", "retry-upload", []string{"fail-upload.e2e.test"}); err != nil {
		return err
	}
	select {
	case <-debugger.done:
	case <-bounded.Done():
		return bounded.Err()
	}
	defer syscall.Kill(pid, syscall.SIGCONT)
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil || !bytes.Contains(status, []byte("State:\tT")) {
		return errors.New("retry issuer not paused before completion")
	}
	retryData, err := os.ReadFile(cfg.Work + "/a/edge-certs/.retry-fail-upload.e2e.test")
	if err != nil {
		return fmt.Errorf("authority deadline not durably journaled: %w", err)
	}
	var retry laneRetry
	if json.Unmarshal(retryData, &retry) != nil || retry.Next.Sub(retry.Updated) < 48*time.Hour {
		return errors.New("durable authority deadline shortened")
	}
	for {
		select {
		case <-bounded.Done():
			return fmt.Errorf("committed reservation: %w", bounded.Err())
		case entry, open := <-updates.Updates():
			if !open {
				return errors.New("reservation watch closed")
			}
			if entry == nil {
				continue
			}
			if err := json.Unmarshal(entry.Value(), &value); err != nil {
				return err
			}
			revision = entry.Revision()
		}
		if value.Lease.Generation != "" && value.Retry.Next.Before(retry.Next) {
			break
		}
	}
	value.Retry.Next = time.Now().Add(-time.Second)
	value.Lease.Generation, value.Lease.Until = "another-holder", time.Now().Add(5*time.Minute)
	data, _ = json.Marshal(value)
	subject := "$KV.edge-certs." + hex.EncodeToString([]byte("fail-upload.e2e.test"))
	if _, err := js.Publish(subject, data, nats.ExpectLastSequencePerSubject(revision), nats.Context(ctx)); err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		return err
	}
	if err := current.wait(bounded, "edge certificate unavailable name=fail-upload.e2e.test ", 1); err != nil {
		return err
	}
	if err := removeRoute(ctx, cfg, "a", "retry-upload"); err != nil {
		return err
	}
	observedFence := false
	for {
		var entry jetstream.KeyValueEntry
		select {
		case <-bounded.Done():
			snapshot, _, readErr := readEnvelope(ctx, js, "fail-upload.e2e.test")
			_, journalErr := os.Stat(cfg.Work + "/a/edge-certs/.retry-fail-upload.e2e.test")
			return fmt.Errorf("deadline watch: %w; shared read=%v, peer fence=%t, deadline=%s, want=%s, journal=%t", bounded.Err(), readErr, snapshot.Lease.Generation == value.Lease.Generation, snapshot.Retry.Next.Format(time.RFC3339Nano), retry.Next.Format(time.RFC3339Nano), journalErr == nil)
		case received, open := <-updates.Updates():
			if !open {
				return errors.New("committed deadline watch closed")
			}
			entry = received
		}
		if entry == nil {
			continue
		}
		var updated laneEnvelope
		if json.Unmarshal(entry.Value(), &updated) != nil {
			continue
		}
		if updated.Lease.Generation == value.Lease.Generation {
			observedFence = true
		}
		if !observedFence || !updated.Retry.Next.Equal(retry.Next) {
			continue
		}
		if updated.Lease.Generation != value.Lease.Generation || !updated.Lease.Until.Equal(value.Lease.Until) {
			return errors.New("deadline publication changed another holder fence")
		}
		break
	}
	value, revision, err = readEnvelope(ctx, js, "fail-upload.e2e.test")
	if err != nil {
		return err
	}
	value.Lease.Generation, value.Lease.Until = "", time.Time{}
	data, _ = json.Marshal(value)
	if _, err := js.Publish(subject, data, nats.ExpectLastSequencePerSubject(revision), nats.Context(ctx)); err != nil {
		return err
	}
	if err := route(ctx, cfg, "b", "retry-upload", []string{"fail-upload.e2e.test"}); err != nil {
		return err
	}
	if err := waitUntil(ctx, time.Now().Add(11*time.Second)); err != nil {
		return err
	}
	counts, err = fetchCounts()
	if err != nil || counts["fail-upload.e2e.test"] != 1 {
		return errors.New("peer bypassed recovered authority deadline")
	}
	fmt.Println("PASS CA 48h deadline survives failed publication in durable journal; reconciliation advances expired reservation monotonically, preserves another holder fence, peer makes no order")
	return removeRoute(ctx, cfg, "b", "retry-upload")
}
