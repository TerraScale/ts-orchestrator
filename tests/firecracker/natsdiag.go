//go:build ignore

// natsdiag reads only regional JetStream metadata during a Firecracker lab run.
// It never prints credentials or raw control-log payloads.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

func main() {
	seed := flag.String("seed", "", "private controller NKey seed file")
	operatorSeed := flag.String("operator-seed", "", "private operator NKey seed file")
	creds := flag.String("creds", "", "private controller JWT credentials file")
	operatorCreds := flag.String("operator-creds", "", "private operator JWT credentials file")
	sessionMode := flag.String("session-probe", "", "single pinned endpoint admission probe: once or hold")
	cell := flag.String("cell", "", "regional cell name")
	operationID := flag.String("operation-id", "", "delivery operation to inspect without payloads")
	urls := flag.String("urls", "", "comma-separated direct controller URLs")
	caFile := flag.String("ca", "", "trusted NATS CA PEM file")
	certFile := flag.String("cert", "", "NATS client certificate PEM file")
	keyFile := flag.String("key", "", "NATS client private key PEM file")
	operatorCertFile := flag.String("operator-cert", "", "operator NATS client certificate PEM file")
	operatorKeyFile := flag.String("operator-key", "", "operator NATS client private key PEM file")
	flag.Parse()
	if (*seed == "") == (*creds == "") || *cell == "" || *urls == "" {
		fmt.Fprintln(os.Stderr, "usage: natsdiag --creds FILE --cell CELL --urls URL,URL,URL")
		os.Exit(2)
	}
	if *sessionMode != "" && (*sessionMode != "once" && *sessionMode != "hold" || strings.Contains(*urls, ",")) {
		fmt.Fprintln(os.Stderr, "session probe requires once or hold and one pinned endpoint")
		os.Exit(2)
	}
	options, err := diagnosticOptions(*seed, *creds, *cell)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load controller identity:", err)
		os.Exit(1)
	}
	if (*caFile != "" || *certFile != "" || *keyFile != "") && (*caFile == "" || *certFile == "" || *keyFile == "") {
		fmt.Fprintln(os.Stderr, "--ca, --cert, and --key must be supplied together")
		os.Exit(2)
	}
	if (*operatorCertFile != "" || *operatorKeyFile != "") &&
		(*operatorCertFile == "" || *operatorKeyFile == "" || *caFile == "" || *operatorSeed == "" && *operatorCreds == "") {
		fmt.Fprintln(os.Stderr, "--operator-cert and --operator-key require TLS and --operator-seed")
		os.Exit(2)
	}
	if *caFile != "" {
		tlsOption, err := diagnosticTLS(*caFile, *certFile, *keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load diagnostic TLS:", err)
			os.Exit(1)
		}
		options = append(options, tlsOption)
	}
	if *sessionMode != "" {
		if err := sessionProbe(*urls, *sessionMode, options); err != nil {
			fmt.Fprintln(os.Stderr, "session probe:", err)
			os.Exit(1)
		}
		return
	}
	var output sync.Mutex
	var workers sync.WaitGroup
	for _, url := range strings.Split(*urls, ",") {
		workers.Go(func() { probe(url, "controller", *cell, *operationID, options, &output) })
	}
	if *operatorSeed != "" || *operatorCreds != "" {
		operatorOptions, err := diagnosticOptions(*operatorSeed, *operatorCreds, *cell)
		if err != nil {
			fmt.Fprintln(os.Stderr, "load operator identity:", err)
			os.Exit(1)
		}
		if *caFile != "" {
			operatorCert, operatorKey := *certFile, *keyFile
			if *operatorCertFile != "" {
				operatorCert, operatorKey = *operatorCertFile, *operatorKeyFile
			}
			tlsOption, err := diagnosticTLS(*caFile, operatorCert, operatorKey)
			if err != nil {
				fmt.Fprintln(os.Stderr, "load diagnostic TLS:", err)
				os.Exit(1)
			}
			operatorOptions = append(operatorOptions, tlsOption)
		}
		workers.Go(func() { probe(*urls, "operator", *cell, *operationID, operatorOptions, &output) })
	}
	workers.Wait()
}

type diagnosticTLSDialer struct {
	config *tls.Config
}

func (d *diagnosticTLSDialer) Dial(network, address string) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, network, address, d.config)
}

func (*diagnosticTLSDialer) SkipTLSHandshake() bool { return true }

func bridgeURL(raw string) string {
	parts := strings.Split(raw, ",")
	for index, part := range parts {
		part = strings.TrimSpace(part)
		if address, ok := strings.CutPrefix(part, "tls://"); ok {
			parts[index] = "nats://" + address
		} else {
			parts[index] = part
		}
	}
	return strings.Join(parts, ",")
}

func diagnosticTLS(caFile, certFile, keyFile string) (nats.Option, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("NATS CA file has no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return nats.SetCustomDialer(&diagnosticTLSDialer{config: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{certificate},
	}}), nil
}

func diagnosticOptions(seedFile, credentialsFile, cell string) ([]nats.Option, error) {
	if credentialsFile == "" {
		return identityOptions(seedFile, cell)
	}
	contents, err := os.ReadFile(credentialsFile)
	if err != nil {
		return nil, err
	}
	pair, err := nkeys.ParseDecoratedUserNKey(contents)
	clear(contents)
	if err != nil {
		return nil, err
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil {
		return nil, err
	}
	return []nats.Option{nats.CustomInboxPrefix("ts.orch.v1." + cell + ".inbox." + public),
		nats.UserCredentials(credentialsFile)}, nil
}

func identityOptions(seedFile, cell string) ([]nats.Option, error) {
	seed, err := os.ReadFile(seedFile)
	if err != nil {
		return nil, err
	}
	pair, err := nkeys.ParseDecoratedUserNKey(seed)
	clear(seed)
	if err != nil {
		return nil, err
	}
	public, err := pair.PublicKey()
	pair.Wipe()
	if err != nil {
		return nil, err
	}
	identity, err := nats.NkeyOptionFromSeed(seedFile)
	if err != nil {
		return nil, err
	}
	return []nats.Option{nats.CustomInboxPrefix("ts.orch.v1." + cell + ".inbox." + public), identity}, nil
}

// sessionProbe keeps one authenticated, non-reconnecting connection pinned to
// one bridge. A successful INFO request is required after Flush and on each
// hold poll, so an open TCP socket without a working account cannot pass.
func sessionProbe(url, mode string, identity []nats.Option) error {
	return sessionProbeReady(url, mode, identity, nil)
}

func sessionProbeReady(url, mode string, identity []nats.Option, ready chan<- struct{}) error {
	started := time.Now()
	options := append([]nats.Option{nats.Timeout(2 * time.Second), nats.NoReconnect()}, identity...)
	conn, err := nats.Connect(bridgeURL(url), options...)
	if err != nil {
		return fmt.Errorf("authenticated admission: %w", err)
	}
	defer conn.Close()
	read := func() error {
		if err := conn.FlushTimeout(2 * time.Second); err != nil {
			return err
		}
		response, err := conn.Request("$JS.API.INFO", nil, 2*time.Second)
		if err != nil {
			return err
		}
		if len(response.Data) == 0 || strings.Contains(string(response.Data), `"error"`) {
			return errors.New("JetStream account read was empty or rejected")
		}
		return nil
	}
	if err := read(); err != nil {
		return fmt.Errorf("required first read: %w", err)
	}
	emit := func(state string) error {
		encoded, err := json.Marshal(map[string]any{
			"state": state, "elapsed_ms": time.Since(started).Milliseconds(), "time": time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		_, err = fmt.Println(string(encoded))
		return err
	}
	if err := emit("ready"); err != nil || mode == "once" {
		return err
	}
	if ready != nil {
		ready <- struct{}{}
	}
	for time.Since(started) < 5*time.Minute {
		time.Sleep(250 * time.Millisecond)
		if err := read(); err != nil {
			if conn.IsClosed() {
				return emit("closed")
			}
			return fmt.Errorf("required read failed while connection remained open: %w", err)
		}
	}
	return errors.New("pinned connection did not close before probe deadline")
}

func probe(url, role, cell, operationID string, identity []nats.Option, output *sync.Mutex) {
	result := map[string]any{"requested_url": url, "role": role, "time": time.Now().UTC()}
	defer func() {
		encoded, err := json.Marshal(result)
		if err != nil {
			fmt.Fprintln(os.Stderr, "encode diagnostic:", err)
			return
		}
		output.Lock()
		fmt.Println(string(encoded))
		output.Unlock()
	}()
	options := append([]nats.Option{nats.Timeout(2 * time.Second), nats.NoReconnect()}, identity...)
	conn, err := nats.Connect(bridgeURL(url), options...)
	if err != nil {
		result["connect_error"] = err.Error()
		return
	}
	defer conn.Close()
	result["connected_url"] = conn.ConnectedUrl()
	result["servers"] = conn.Servers()
	result["discovered_servers"] = conn.DiscoveredServers()
	js, err := jetstream.New(conn)
	if err != nil {
		result["jetstream_error"] = err.Error()
		return
	}
	read := func(name string, operation func(context.Context) (any, error)) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		value, err := operation(ctx)
		if err != nil {
			result[name+"_error"] = err.Error()
			return
		}
		if _, err := json.Marshal(value); err != nil {
			result[name+"_error"] = fmt.Sprintf("encode diagnostic query: %v", err)
			return
		}
		result[name] = value
	}
	read("account", func(ctx context.Context) (any, error) {
		info, err := js.AccountInfo(ctx)
		if err != nil {
			return nil, err
		}
		return accountDiagnostic(info), nil
	})
	for _, name := range []string{authority.ControlStreamName, delivery.IntentStream, "KV_TS_HOST_STATE"} {
		read("stream_"+name, func(ctx context.Context) (any, error) {
			stream, err := js.Stream(ctx, name)
			if err != nil {
				return nil, err
			}
			info, err := stream.Info(ctx)
			if err != nil {
				return nil, err
			}
			return streamDiagnostic(info), nil
		})
	}
	if role == "controller" {
		read("delivery_consumer", func(ctx context.Context) (any, error) {
			consumer, err := js.Consumer(ctx, delivery.IntentStream, delivery.IntentConsumer)
			if err != nil {
				return nil, err
			}
			info, err := consumer.Info(ctx)
			if err != nil {
				return nil, err
			}
			return consumerDiagnostic(info), nil
		})
	}
	read("authority", func(ctx context.Context) (any, error) {
		snapshot, err := authority.Observe(ctx, js, cell)
		if err != nil {
			return nil, err
		}
		return map[string]any{"candidate": snapshot.CandidateID, "epoch": snapshot.Epoch,
			"revision": snapshot.Revision, "expires_at": snapshot.ExpiresAt,
			"ready": snapshot.Ready, "reason": snapshot.Reason}, nil
	})
	if operationID != "" {
		read("delivery_operation", func(ctx context.Context) (any, error) {
			return operationDiagnostic(ctx, js, operationID)
		})
	}
	if role == "operator" {
		result["operator_read_paths"] = operatorReadPaths(conn, js, cell, operationID)
	}
}

type readTarget struct {
	label  string
	bucket string
	key    string
}

func readTargets(cell, operationID string) []readTarget {
	targets := make([]readTarget, 0, 3)
	if operationID != "" {
		sum := sha256.Sum256([]byte(operationID))
		targets = append(targets, readTarget{label: "delivery_operation",
			bucket: delivery.OperationBucket, key: "o_" + hex.EncodeToString(sum[:])})
	}
	targets = append(targets,
		readTarget{label: "host_session", bucket: "TS_HOST_STATE", key: "session." + cell + ".host-a"},
		readTarget{label: "host_report", bucket: "TS_HOST_STATE", key: "report." + cell + ".host-a.terrabase"})
	return targets
}

func (target readTarget) subject() string {
	return "$KV." + target.bucket + "." + target.key
}

// These two reads use the same operator connection but different JetStream
// routes. KeyValue.Get may use a replica's direct endpoint; GetLastMsg without
// DirectGet is sent to the stream leader. Each attempt owns a fresh deadline.
func operatorReadPaths(conn *nats.Conn, js jetstream.JetStream, cell, operationID string) map[string]any {
	results := make(map[string]any)
	for _, target := range readTargets(cell, operationID) {
		results[target.label] = map[string]any{
			"stream": "KV_" + target.bucket,
			"direct_kv": timedReadPath(func(ctx context.Context) (string, bool, uint64, error) {
				store, err := js.KeyValue(ctx, target.bucket)
				if err != nil {
					return "kv_open", false, 0, err
				}
				entry, err := store.Get(ctx, target.key)
				if err != nil {
					return "kv_get", false, 0, err
				}
				if entry == nil {
					return "kv_get", false, 0, errors.New("missing KV entry")
				}
				return "kv_get", true, entry.Revision(), nil
			}),
			"leader_api": timedReadPath(func(ctx context.Context) (string, bool, uint64, error) {
				legacy, err := conn.JetStream()
				if err != nil {
					return "jetstream_context", false, 0, err
				}
				message, err := legacy.GetLastMsg("KV_"+target.bucket, target.subject(), nats.Context(ctx))
				if err != nil {
					return "get_last_msg", false, 0, err
				}
				if message == nil {
					return "get_last_msg", false, 0, errors.New("missing stream message")
				}
				return "get_last_msg", true, message.Sequence, nil
			}),
		}
	}
	return results
}

func timedReadPath(call func(context.Context) (string, bool, uint64, error)) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	stage, found, revision, err := call(ctx)
	return map[string]any{"stage": stage,
		"elapsed_ms": float64(time.Since(started).Microseconds()) / 1000,
		"error":      readPathError(err), "found": found, "revision": revision}
}

func readPathError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return "deadline_exceeded"
	case errors.Is(err, jetstream.ErrKeyNotFound), errors.Is(err, nats.ErrMsgNotFound):
		return "not_found"
	case errors.Is(err, nats.ErrNoResponders):
		return "no_responders"
	case errors.Is(err, nats.ErrAuthorization):
		return "authorization"
	default:
		return "other"
	}
}

func operationDiagnostic(ctx context.Context, js jetstream.JetStream, operationID string) (any, error) {
	store, err := js.KeyValue(ctx, delivery.OperationBucket)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(operationID))
	entry, err := store.Get(ctx, "o_"+hex.EncodeToString(sum[:]))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return map[string]any{"state": "unclaimed"}, nil
	}
	if err != nil {
		return nil, err
	}
	var operation struct {
		Intent struct {
			OperationID    string `json:"operationId"`
			Generation     uint64 `json:"generation"`
			AuthorityEpoch uint64 `json:"authorityEpoch"`
		} `json:"intent"`
		Plan    []struct{} `json:"plan"`
		Receipt *struct {
			Status         string `json:"status"`
			Generation     uint64 `json:"generation"`
			AuthorityEpoch uint64 `json:"authorityEpoch"`
		} `json:"receipt"`
	}
	if err := json.Unmarshal(entry.Value(), &operation); err != nil {
		return nil, errors.New("operation metadata is malformed")
	}
	if operation.Intent.OperationID != operationID {
		return nil, errors.New("operation key and stored identity differ")
	}
	result := map[string]any{"state": "claimed", "revision": entry.Revision(),
		"generation": operation.Intent.Generation, "authority_epoch": operation.Intent.AuthorityEpoch,
		"plan_count": len(operation.Plan)}
	if operation.Receipt != nil {
		result["receipt"] = map[string]any{"status": operation.Receipt.Status,
			"generation":      operation.Receipt.Generation,
			"authority_epoch": operation.Receipt.AuthorityEpoch}
	}
	return result, nil
}

func accountDiagnostic(info *jetstream.AccountInfo) map[string]any {
	tiers := make(map[string]any, len(info.Tiers))
	for name, tier := range info.Tiers {
		tiers[name] = map[string]any{"memory": tier.Memory, "storage": tier.Store,
			"reserved_memory": tier.ReservedMemory, "reserved_storage": tier.ReservedStore,
			"streams": tier.Streams, "consumers": tier.Consumers}
	}
	return map[string]any{"api": map[string]any{"level": info.API.Level, "total": info.API.Total,
		"errors": info.API.Errors, "inflight": info.API.Inflight}, "tiers": tiers}
}

func streamDiagnostic(info *jetstream.StreamInfo) map[string]any {
	return map[string]any{"messages": info.State.Msgs, "first_seq": info.State.FirstSeq,
		"last_seq": info.State.LastSeq, "cluster": clusterDiagnostic(info.Cluster)}
}

func consumerDiagnostic(info *jetstream.ConsumerInfo) map[string]any {
	return map[string]any{"delivered": sequenceDiagnostic(info.Delivered),
		"ack_floor": sequenceDiagnostic(info.AckFloor), "ack_pending": info.NumAckPending,
		"redelivered": info.NumRedelivered, "waiting": info.NumWaiting,
		"pending": info.NumPending, "cluster": clusterDiagnostic(info.Cluster)}
}

func sequenceDiagnostic(info jetstream.SequenceInfo) map[string]any {
	return map[string]any{"consumer_seq": info.Consumer, "stream_seq": info.Stream,
		"last_active": info.Last}
}

func clusterDiagnostic(info *jetstream.ClusterInfo) any {
	if info == nil {
		return nil
	}
	replicas := make([]map[string]any, 0, len(info.Replicas))
	for _, peer := range info.Replicas {
		if peer == nil {
			continue
		}
		replicas = append(replicas, map[string]any{"name": peer.Name, "peer": peer.Peer,
			"current": peer.Current, "offline": peer.Offline, "pending": peer.Pending,
			"lag": peer.Lag, "active_ns": peer.Active.Nanoseconds()})
	}
	cluster := map[string]any{"name": info.Name, "raft_group": info.RaftGroup,
		"leader": info.Leader, "leader_since": info.LeaderSince, "replicas": replicas}
	if info.Desired != nil {
		desiredReplicas := make([]map[string]any, 0, len(info.Desired.Replicas))
		for _, peer := range info.Desired.Replicas {
			if peer == nil {
				continue
			}
			desiredReplicas = append(desiredReplicas, map[string]any{"name": peer.Name,
				"peer": peer.Peer, "offline": peer.Offline})
		}
		desired := map[string]any{"name": info.Desired.Name, "created": info.Desired.Created,
			"replicas": desiredReplicas}
		if info.Desired.Status != nil {
			desired["status"] = map[string]any{"type": string(info.Desired.Status.Type),
				"description": info.Desired.Status.Description}
		}
		cluster["desired"] = desired
	}
	return cluster
}
