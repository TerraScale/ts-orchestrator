package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/callerkey"
)

type wireSnapshot struct {
	callerkey.Snapshot
	Content []byte
}
type secret struct {
	Current  wireSnapshot
	Versions []wireSnapshot
	Pending  []bool
	Etag     string
}
type store struct {
	sync.Mutex
	values  map[string]*secret
	writes  int
	fail    int
	after   bool
	crash   bool
	reads   chan struct{}
	release chan struct{}
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
func encoded(value any) []byte {
	data, err := json.Marshal(value, json.Deterministic(true))
	must(err)
	return data
}
func (s *store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Operation string
		Name      string
		Before    callerkey.Snapshot
		State     callerkey.PrivateState
		Value     []byte
		Version   int64
	}
	must(json.UnmarshalRead(r.Body, &in))
	s.Lock()
	defer s.Unlock()
	if in.Operation == "regions" {
		w.Write(encoded([]string{"sjc", "fra", "gru"}))
		return
	}
	value := s.values[in.Name]
	if value == nil {
		value = &secret{}
	}
	switch in.Operation {
	case "read":
		w.Write(encoded(value.Current))
		if s.reads != nil && in.Name == "sjc-1-terrabase-callers" {
			reads, release := s.reads, s.release
			s.Unlock()
			reads <- struct{}{}
			<-release
			s.Lock()
		}
		return
	case "private":
		w.Write(encoded(value))
		return
	}
	s.writes++
	if s.writes == s.fail && !s.after {
		http.Error(w, "injected write failure", 409)
		return
	}
	if in.Operation == "write" && value.Current.Version != in.Before.Version || in.Operation != "write" && value.Etag != in.State.Etag {
		http.Error(w, "conditional version conflict", 409)
		return
	}
	if in.Operation == "activate" {
		i := slices.IndexFunc(value.Versions, func(v wireSnapshot) bool { return v.Version == in.Version })
		require(i >= 0 && value.Pending[i], "promotion did not name pending version")
		value.Current = value.Versions[i]
		value.Pending[i] = false
	} else {
		require(len(in.Value) <= 16384, "publication exceeds store limit")
		next := wireSnapshot{callerkey.Snapshot{ID: in.Name, Version: int64(len(value.Versions) + 1)}, bytes.Clone(in.Value)}
		value.Versions = append(value.Versions, next)
		value.Pending = append(value.Pending, in.Operation == "stage")
		if in.Operation == "write" {
			value.Current = next
		}
	}
	value.Etag = strconv.Itoa(s.writes)
	s.values[in.Name] = value
	if s.writes == s.fail {
		if s.crash {
			pid, err := strconv.Atoi(r.Header.Get("Caller-Key-Pid"))
			must(err)
			must(syscall.Kill(pid, syscall.SIGKILL))
		}
		http.Error(w, "injected uncertain write", 409)
		return
	}
	w.Write(encoded(true))
}

type journey struct {
	binary, root, targets, reverse string
	store                          *store
	server                         *httptest.Server
}

func (j *journey) run(path string, args ...string) (string, error) {
	command := exec.Command(j.binary, append([]string{"caller-key"}, append(args, "--targets", path)...)...)
	command.Env = append(os.Environ(), "CALLER_KEY_STORE="+j.server.URL)
	output, err := command.CombinedOutput()
	j.store.Lock()
	defer j.store.Unlock()
	for name, v := range j.store.values {
		if !strings.HasSuffix(name, "-terrabase-key") {
			continue
		}
		for _, version := range v.Versions {
			var key struct {
				D string `json:"d"`
				X string `json:"x"`
			}
			must(json.Unmarshal(version.Content, &key))
			require(!bytes.Contains(output, []byte(key.D)) && !bytes.Contains(output, []byte(key.X)), "output contains private key material")
		}
	}
	return string(output), err
}
func (j *journey) ok(args ...string) string {
	out, err := j.run(j.targets, args...)
	require(err == nil, fmt.Sprintf("%v failed: %v %s", args, err, out))
	return out
}
func add(id string) []string {
	parts := strings.Split(id, ".")
	return []string{"add", "--service", parts[0], "--region", parts[1], "--kid", id, "--not-after", time.Now().Add(90 * 24 * time.Hour).UTC().Format(time.RFC3339)}
}
func (j *journey) reset() {
	j.store.Lock()
	defer j.store.Unlock()
	j.store.values = map[string]*secret{}
	j.store.writes, j.store.fail = 0, 0
	j.store.reads = nil
}
func (j *journey) converged() int {
	j.store.Lock()
	defer j.store.Unlock()
	if len(j.store.values) == 0 {
		return 0
	}
	var first []byte
	var registry callerkey.Registry
	for _, cell := range []string{"fra", "gru", "sjc"} {
		v := j.store.values[cell+"-1-terrabase-callers"]
		require(v != nil, "missing public registry")
		must(json.Unmarshal(v.Current.Content, &registry))
		require(registry.Intent == nil, "operation record remains")
		if first == nil {
			first = v.Current.Content
		} else {
			require(bytes.Equal(first, v.Current.Content), "regional lists differ")
		}
	}
	for name, v := range j.store.values {
		if !strings.HasSuffix(name, "-terrabase-key") {
			continue
		}
		versions := []wireSnapshot{v.Current}
		for i, pending := range v.Pending {
			if pending {
				versions = append(versions, v.Versions[i])
			}
		}
		for _, version := range versions {
			var key struct {
				Kid string `json:"kid"`
				X   string `json:"x"`
				Y   string `json:"y"`
				D   string `json:"d"`
			}
			must(json.Unmarshal(version.Content, &key))
			i := slices.IndexFunc(registry.Callers, func(c callerkey.Caller) bool { return c.Kid == key.Kid })
			require(i >= 0 && registry.Callers[i].JWK.X == key.X && registry.Callers[i].JWK.Y == key.Y, "signing key lacks matching public entry")
			decode := func(s string) *big.Int {
				b, err := base64.RawURLEncoding.DecodeString(s)
				must(err)
				require(len(b) == 32, "invalid scalar")
				return new(big.Int).SetBytes(b)
			}
			private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: decode(key.X), Y: decode(key.Y)}, D: decode(key.D)}
			digest := sha256.Sum256([]byte("caller-key journey"))
			signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
			must(err)
			require(ecdsa.VerifyASN1(&private.PublicKey, digest[:], signature), "invalid signing key")
			require(!bytes.Contains(first, []byte(key.D)), "public document contains private material")
		}
	}
	return len(first)
}
func (j *journey) seed(operation string) []string {
	j.reset()
	if operation == "first" {
		return add("ts-auth.sjc.1")
	}
	j.ok(add("ts-auth.sjc.1")...)
	if operation == "add" {
		return add("ts-auth.sjc.2")
	}
	j.ok(add("ts-auth.sjc.2")...)
	if operation == "activate" {
		return []string{"activate", "--kid", "ts-auth.sjc.2"}
	}
	j.ok("activate", "--kid", "ts-auth.sjc.2")
	return []string{"retire", "--kid", "ts-auth.sjc.1", "--replacement-kid", "ts-auth.sjc.2"}
}
func (j *journey) recover() {
	j.ok("recover")
	require(strings.Contains(j.ok("recover"), "no operation"), "second recovery changed state")
	j.converged()
}
func (j *journey) failures() {
	for _, operation := range []string{"first", "add", "activate", "retire"} {
		args := j.seed(operation)
		start := j.store.writes
		j.ok(args...)
		count := j.store.writes - start
		for _, mode := range []string{"before", "uncertain", "crash"} {
			for n := 1; n <= count; n++ {
				args = j.seed(operation)
				j.store.fail, j.store.after, j.store.crash = j.store.writes+n, mode != "before", mode == "crash"
				_, err := j.run(j.targets, args...)
				require(err != nil, fmt.Sprintf("%s %s write %d did not interrupt", operation, mode, n))
				j.store.fail = 0
				if mode == "crash" && n == 1 {
					for _, blocked := range [][]string{add("edge.gru.1"), {"activate", "--kid", "ts-auth.sjc.1"}, {"retire", "--kid", "ts-auth.sjc.1"}} {
						out, err := j.run(j.targets, blocked...)
						require(err != nil && strings.Contains(out, "operation in progress"), "intent did not block a changing command")
					}
				}
				j.recover()
				if n > 1 || mode != "before" {
					var registry callerkey.Registry
					must(json.Unmarshal(j.store.values["fra-1-terrabase-callers"].Current.Content, &registry))
					id := args[slices.Index(args, "--kid")+1]
					listed := slices.ContainsFunc(registry.Callers, func(c callerkey.Caller) bool { return c.Kid == id })
					private := j.store.values["sjc-1-ts-auth-terrabase-key"]
					stored := false
					if private != nil {
						for i, version := range private.Versions {
							var key struct {
								Kid string `json:"kid"`
							}
							must(json.Unmarshal(version.Content, &key))
							stored = stored || key.Kid == id && (private.Pending[i] || version.Version == private.Current.Version)
						}
					}
					if operation == "first" || operation == "add" {
						require(listed == stored, "add recovery did not resolve the public-only entry")
					}
					if operation == "retire" {
						require(!listed, "retire recovery retained the entry")
					}
					if operation == "activate" {
						var key struct {
							Kid string `json:"kid"`
						}
						must(json.Unmarshal(private.Current.Content, &key))
						require(key.Kid == id, "activation recovery did not promote the key")
					}
				}
			}
		}
		fmt.Println(operation, "-> recovery after every write boundary:", count, "writes x 3 failure modes")
	}
}
func (j *journey) concurrent(retire bool) {
	args := j.seed("add")
	other := add("edge.gru.1")
	if retire {
		j.ok(args...)
		j.ok("activate", "--kid", "ts-auth.sjc.2")
		args = add("ts-auth.sjc.3")
		other = []string{"retire", "--kid", "ts-auth.sjc.1", "--replacement-kid", "ts-auth.sjc.2"}
	}
	j.store.reads, j.store.release = make(chan struct{}, 2), make(chan struct{})
	var group sync.WaitGroup
	var results [2]error
	for i, command := range [][]string{args, other} {
		group.Add(1)
		go func() {
			defer group.Done()
			path := j.targets
			if i == 1 {
				path = j.reverse
			}
			_, results[i] = j.run(path, command...)
		}()
	}
	<-j.store.reads
	<-j.store.reads
	j.store.Lock()
	j.store.reads = nil
	close(j.store.release)
	j.store.Unlock()
	group.Wait()
	require((results[0] == nil) != (results[1] == nil), "concurrent commands did not serialize through conditional intent")
	j.recover()
}
func main() {
	root, err := os.MkdirTemp("", "caller-key-e2e-")
	must(err)
	defer os.RemoveAll(root)
	repo, err := os.Getwd()
	must(err)
	binary := filepath.Join(root, "ts-orch")
	adapter := filepath.Join(repo, "test/e2e/m1/callerkey/store.go.txt")
	overlay := filepath.Join(root, "overlay.json")
	must(os.WriteFile(overlay, encoded(map[string]any{"Replace": map[string]string{filepath.Join(repo, "internal/callerkey/vault.go"): adapter}}), 0600))
	build := exec.Command("nice", "-n", "19", "go", "build", "-overlay", overlay, "-trimpath", "-o", binary, "./cmd/terrascale-orchestrator")
	output, err := build.CombinedOutput()
	require(err == nil, fmt.Sprintf("binary build: %v %s", err, output))
	targets := []callerkey.Target{}
	for _, pair := range [][2]string{{"sjc", "us-sanjose-1"}, {"fra", "eu-frankfurt-1"}, {"gru", "sa-saopaulo-1"}} {
		targets = append(targets, callerkey.Target{Cell: pair[0], Vault: "ocid1.vault.oc1." + pair[1] + ".example", Key: "ocid1.key.oc1." + pair[1] + ".example", Compartment: "ocid1.compartment.oc1.example"})
	}
	s := &store{}
	server := httptest.NewServer(s)
	defer server.Close()
	j := journey{binary: binary, root: root, targets: filepath.Join(root, "targets.json"), reverse: filepath.Join(root, "reverse.json"), store: s, server: server}
	must(os.WriteFile(j.targets, encoded(targets), 0600))
	slices.Reverse(targets)
	must(os.WriteFile(j.reverse, encoded(targets), 0600))
	j.failures()
	j.concurrent(false)
	j.concurrent(true)
	fmt.Println("simultaneous adds in opposite region orders; simultaneous add and retire -> converged")
	j.reset()
	for _, pair := range [][2]string{{"ts-auth", "sjc"}, {"dashboard", "fra"}, {"edge", "gru"}} {
		j.ok(add(pair[0] + "." + pair[1] + ".1")...)
	}
	nearExpiry, expired := time.Now().Add(24*time.Hour).UTC(), time.Now().Add(-time.Hour).UTC()
	for _, v := range s.values {
		if !strings.HasSuffix(v.Current.ID, "-terrabase-callers") {
			continue
		}
		var r callerkey.Registry
		must(json.Unmarshal(v.Current.Content, &r))
		r.Callers[0].NotAfter = nearExpiry
		c := r.Callers[0]
		c.Kid, c.Caller, c.Kind = "agent.deploy.1", "agent:deploy", "operator"
		r.Callers = append(r.Callers, c)
		c.Kid, c.Caller = "op.admin.1", "op:admin"
		c.NotAfter = expired
		r.Callers = append(r.Callers, c)
		v.Current.Content = encoded(r)
	}
	require(strings.Contains(j.ok("list"), "expired"), "expired status absent")
	require(strings.Contains(j.ok("list"), "expires within 30 days"), "expiry warning absent")
	j.ok("retire", "--kid", "agent.deploy.1")
	j.ok("retire", "--kid", "op.admin.1")
	j.ok(add("edge.gru.2")...)
	j.ok("activate", "--kid", "edge.gru.2")
	j.ok("retire", "--kid", "edge.gru.1", "--replacement-kid", "edge.gru.2")
	j.converged()
	j.reset()
	j.ok(add("ts-auth.sjc.1")...)
	refuse := func(fragment string, args ...string) {
		start := s.writes
		out, err := j.run(j.targets, args...)
		require(err != nil && strings.Contains(out, fragment) && s.writes == start, "validation did not refuse without writes: "+out)
	}
	refuse("current", "retire", "--kid", "ts-auth.sjc.1")
	j.ok(add("ts-auth.sjc.2")...)
	refuse("pending", "retire", "--kid", "ts-auth.sjc.2")
	refuse("pending", add("ts-auth.sjc.3")...)
	j.ok("activate", "--kid", "ts-auth.sjc.2")
	refuse("--replacement-kid", "retire", "--kid", "ts-auth.sjc.1")
	bad := add("ts-auth.sjc.3")
	bad[len(bad)-1] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	refuse("30 days", bad...)
	j.reset()
	j.ok(add("ts-auth.sjc.10")...)
	start := j.converged()
	for n := 11; n <= 60; n++ {
		id := "ts-auth.sjc." + strconv.Itoa(n)
		j.ok(add(id)...)
		j.ok("activate", "--kid", id)
		j.ok("retire", "--kid", "ts-auth.sjc."+strconv.Itoa(n-1), "--replacement-kid", id)
		require(j.converged() == start, "retired history grows document")
	}
	fmt.Println("near-expiry rotation, expired operator/agent retirement, 50 rotations -> flat", start, "byte registries")
	_, err = j.run(j.targets, add("ts-auth.sjc.59")...)
	require(err != nil, "sequence reuse accepted")
	fmt.Println("caller-key real CLI subprocess journey -> passed")
}
