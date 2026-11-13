package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
)

const sha = "1111111111111111111111111111111111111111"

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func encode(value any) []byte {
	data, err := json.Marshal(value)
	must(err)
	return data
}

func signed(key *rsa.PrivateKey, kid, run string) string {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString(encode(map[string]string{"alg": "RS256", "kid": kid}))
	claims := base64.RawURLEncoding.EncodeToString(encode(map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch",
		"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(),
		"repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale",
		"ref": "refs/heads/main", "sha": sha, "run_id": run, "event_name": "push",
		"workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main",
	}))
	input := header + "." + claims
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	must(err)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type artifactTransport struct{ endpoint string }

func (t artifactTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(request.URL.String(), "https://github.com/TerraScale/ts-orchestrator/releases/download/ci-"+sha+"-run-") {
		return nil, errors.New("unexpected artifact origin")
	}
	copy := request.Clone(request.Context())
	target, err := http.NewRequestWithContext(request.Context(), request.Method, t.endpoint+"/asset", nil)
	if err != nil {
		return nil, err
	}
	copy.URL, copy.Host = target.URL, target.Host
	return http.DefaultTransport.RoundTrip(copy)
}

func main() {
	require(len(os.Args) == 2, "binary argument required")
	bin, err := filepath.Abs(os.Args[1])
	must(err)
	work, err := os.MkdirTemp("", "node-list-e2e-")
	must(err)
	defer os.RemoveAll(work)
	command := func(args ...string) []byte {
		cmd := exec.Command(bin, args...)
		cmd.Env = os.Environ()
		data, err := cmd.Output()
		if err != nil {
			panic(fmt.Sprintf("command %s failed: %v", args[0], err))
		}
		return data
	}
	storeState := filepath.Join(work, "receiver")
	empty := []byte("{\"sequence\":0,\"nodes\":[]}\n")
	emptyPath := filepath.Join(work, "empty.json")
	must(os.WriteFile(emptyPath, empty, 0o600))
	store, err := nodelist.OpenEmbedded(storeState, empty)
	must(err)
	require(len(nodelist.Current()) == 0, "empty embedded list must leave current nodes empty")
	must(releasepush.NodesCLI(context.Background(), []string{"publish", sha, emptyPath, "not-a-region-file"}, io.Discard))
	inventory := []nodelist.Node{}
	for index := 1; index <= 3; index++ {
		state := filepath.Join(work, fmt.Sprintf("node-%d", index))
		public := command("node", "keys", state)
		require(bytes.Equal(public, command("node", "keys", state)), "node keys changed after a new process start")
		var keys nodelist.PublicKeys
		must(json.Unmarshal(public, &keys))
		require(len(keys.TLSSPKISHA256) == 64 && len(keys.WGPublicKey) == 44, "public output is incomplete")
		var fields map[string]any
		must(json.Unmarshal(public, &fields))
		require(len(fields) == 2, "private key material exposed")
		for _, name := range []string{"tls.key", "wg.key"} {
			info, err := os.Stat(filepath.Join(state, "node", name))
			must(err)
			require(info.Mode().Perm() == 0o600, "private key permissions differ from 0600")
			private, err := os.ReadFile(filepath.Join(state, "node", name))
			must(err)
			require(!bytes.Contains(public, bytes.TrimSpace(private)), "private bytes appeared in public output")
		}
		inventory = append(inventory, nodelist.Node{Name: fmt.Sprintf("ts-gru-%d", index), Region: "gru",
			PublicIP: fmt.Sprintf("192.0.2.%d", index), PrivateIP: fmt.Sprintf("10.251.0.%d", index),
			WGPublicKey: keys.WGPublicKey, TLSSPKISHA256: keys.TLSSPKISHA256})
	}
	inventoryPath := filepath.Join(work, "inventory.json")
	listPath := filepath.Join(work, "nodes.json")
	must(os.WriteFile(inventoryPath, encode(inventory), 0o600))
	command("node", "list", "build", "2", inventoryPath, listPath)
	listWire, err := os.ReadFile(listPath)
	must(err)
	list, err := nodelist.Decode(listWire)
	must(err)
	require(len(list.Nodes) == 3 && list.Nodes[2].MeshIP == "10.201.1.3", "builder did not derive node addresses")
	fmt.Println("ok enrolment: three nodes keep private 0600 keys across processes and expose public halves only")

	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	unknown, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	var asset, token atomic.Value
	asset.Store(listWire)
	token.Store(signed(signer, "run-key", "20"))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			must(json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
				"kty": "RSA", "kid": "run-key", "n": base64.RawURLEncoding.EncodeToString(signer.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(signer.E)).Bytes()),
			}}}))
		case "/mint":
			require(r.Header.Get("Authorization") == "bearer e2e-only", "mint lacks authenticated bearer")
			must(json.NewEncoder(w).Encode(map[string]string{"value": token.Load().(string)}))
		case "/asset":
			_, err := w.Write(asset.Load().([]byte))
			must(err)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", upstream.URL+"/mint?request=e2e"))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "e2e-only"))
	envelope := command("release", "nodes", "sign", sha, listPath)
	var release releasepush.NodesRelease
	must(json.Unmarshal(envelope, &release))
	require(release.Kind == "nodes" && release.Artifact.URL == releasepush.NodesURL(sha, "20"), "sign command did not bind the run artifact")
	verifier := releasepush.NewVerifier()
	verifier.JWKSURL = upstream.URL + "/jwks"
	auth, err := releasepush.NewAuth(verifier)
	must(err)
	options, err := releasepush.Options(storeState, auth)
	must(err)
	options.Host, options.Port = "127.0.0.1", -1
	options.CustomClientAuthentication = nil
	srv, err := server.NewServer(options)
	must(err)
	srv.Start()
	defer func() { srv.Shutdown(); srv.WaitForShutdown() }()
	require(srv.ReadyForConnections(5*time.Second), "release listener did not start")
	pin, err := releasepush.SPKIPin(options.TLSConfig.Certificates[0].Certificate[0])
	must(err)
	region := releasepush.Region{Region: "gru", NATS: "tls://" + srv.Addr().String(), SPKISHA256: pin}
	conn, err := releasepush.Dial(region, release.Token)
	must(err)
	defer conn.Close()
	handler := &releasepush.Handler{NodeList: store, Verifier: verifier,
		Client: &http.Client{Transport: artifactTransport{upstream.URL}}, Installed: make(chan struct{}, 1)}
	must(handler.Serve(conn))
	send := func(value releasepush.NodesRelease) releasepush.Reply {
		message, err := conn.Request(releasepush.SubjectNodes, encode(value), 5*time.Second)
		must(err)
		var reply releasepush.Reply
		must(json.Unmarshal(message.Data, &reply))
		return reply
	}
	bad := release
	parts := strings.Split(bad.Token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	must(err)
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	bad.Token = strings.Join(parts, ".")
	require(send(bad).State == "rejected", "bad signature accepted")
	bad.Token = signed(unknown, "unknown-key", "20")
	require(send(bad).State == "rejected", "unknown signer accepted")
	require(store.Snapshot().Sequence == 0, "rejected signatures changed state")
	asset.Store(append(append([]byte{}, listWire...), byte(' ')))
	require(send(release).State == "rejected", "tampered node list accepted")
	asset.Store(listWire)
	bad = release
	bad.Artifact.URL = releasepush.NodesURL(sha, "21")
	require(send(bad).State == "rejected", "unbound release URL accepted")
	reply := send(release)
	require(reply.State == "updated" && reply.Version == "2", "valid signed node list refused")
	require(len(nodelist.Current()) == 3, "accepted list not published to consumers")
	select {
	case <-handler.Installed:
		panic("node list update requested a binary restart")
	default:
	}
	require(send(release).State == "current", "idempotent node list refused")
	newer := list
	newer.Sequence = 3
	newerWire := encode(newer)
	must(os.WriteFile(listPath, newerWire, 0o600))
	asset.Store(newerWire)
	token.Store(signed(signer, "run-key", "21"))
	envelope = command("release", "nodes", "sign", sha, listPath)
	envelopePath := filepath.Join(work, "envelope.json")
	must(os.WriteFile(envelopePath, envelope, 0o600))
	regionsPath := filepath.Join(work, "regions.json")
	must(os.WriteFile(regionsPath, encode([]releasepush.Region{region}), 0o600))
	output := command("release", "nodes", "push", envelopePath, regionsPath)
	require(bytes.Contains(output, []byte("\"updated\"")), "enrolment push did not update receiver")
	require(store.Snapshot().Sequence == 3, "pushed newer sequence not held")
	asset.Store(listWire)
	must(os.WriteFile(listPath, listWire, 0o600))
	envelope = command("release", "nodes", "sign", sha, listPath)
	must(json.Unmarshal(envelope, &release))
	require(send(release).State == "rejected", "older node list sequence accepted")
	asset.Store(newerWire)
	must(os.WriteFile(listPath, newerWire, 0o600))
	token.Store(signed(signer, "run-key", "19"))
	envelope = command("release", "nodes", "sign", sha, listPath)
	must(json.Unmarshal(envelope, &release))
	require(send(release).State == "rejected", "older signed release run accepted")
	restarted, err := nodelist.OpenEmbedded(storeState, listWire)
	must(err)
	require(restarted.Snapshot().Sequence == 3, "older embedded list won over persisted push")
	_, err = restarted.Apply(list, 22)
	require(errors.Is(err, nodelist.ErrStale), "sequence floor lost after restart")
	embeddedNewer := list
	embeddedNewer.Sequence = 4
	restarted, err = nodelist.OpenEmbedded(storeState, encode(embeddedNewer))
	must(err)
	require(restarted.Snapshot().Sequence == 4, "newer embedded list did not win")
	_, err = restarted.Apply(embeddedNewer, 19)
	require(errors.Is(err, nodelist.ErrStale), "run floor lost after newer binary")
	changed := embeddedNewer
	changed.Nodes = append([]nodelist.Node(nil), embeddedNewer.Nodes...)
	changed.Nodes[0].PublicIP = "192.0.2.100"
	_, err = restarted.Apply(changed, 22)
	require(err != nil, "conflicting same-sequence node list accepted")

	workerStore, err := nodelist.OpenEmbedded(filepath.Join(work, "worker"), empty)
	must(err)
	worker := &releasepush.Handler{NodeList: workerStore, Verifier: verifier, Client: handler.Client, Installed: make(chan struct{}, 1)}
	must(worker.ServeWorker(conn, "ts.mesh.release.e2e"))
	relay := func(data []byte) releasepush.Reply {
		message, err := conn.Request("ts.mesh.release.e2e", data, 5*time.Second)
		must(err)
		var reply releasepush.Reply
		must(json.Unmarshal(message.Data, &reply))
		return reply
	}
	require(relay(encode(bad)).State == "rejected", "worker accepted a mismatched signed artifact")
	token.Store(signed(signer, "run-key", "22"))
	envelope = command("release", "nodes", "sign", sha, listPath)
	require(relay(envelope).State == "updated", "worker did not accept the signed nodes artifact")
	require(worker.NodeList.Snapshot().Sequence == 3, "worker did not persist its node list")
	select {
	case <-worker.Installed:
		panic("relayed node list requested a binary restart")
	default:
	}
	absent, err := nodelist.OpenEmbedded(filepath.Join(work, "absent"), nil)
	must(err)
	require(absent.Snapshot().Sequence == 0 && len(nodelist.Current()) == 0, "absent list changed consumer behavior")
	fmt.Println("ok worker release channel: signed node list verified and stored without a binary restart")
	fmt.Println("ok signed node list: valid accepted; tamper, bad signature, unknown signer, older sequence, older run and equivocation refused; floors survive restart")
	fmt.Println("ok enrolment commands: build, sign and pinned release push update the list without a binary restart")
}
