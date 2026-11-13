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
	Name    string
}
type secret struct {
	Current       wireSnapshot
	Versions      []wireSnapshot
	Pending       []bool
	Deleting      []bool
	DeletionTimes []time.Time
	Scheduled     map[int64]time.Time
	Etag          string
	Revision      int
}
type store struct {
	sync.Mutex
	values         map[string]*secret
	writes         int
	privateReads   int
	fail           int
	mode           string
	hidden         map[string]bool
	land           func() bool
	now            time.Time
	landAt         int
	hideAfterStage bool
	cases          int
	reads          chan struct{}
	release        chan struct{}
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
func (s *store) invariant() {
	for name, value := range s.values {
		if !strings.HasSuffix(name, "-terrabase-key") || value.Current.Version == 0 {
			continue
		}
		var key struct {
			Kid string `json:"kid"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		must(json.Unmarshal(value.Current.Content, &key))
		for _, cell := range []string{"fra", "gru", "sjc"} {
			registry := s.values[cell+"-1-terrabase-callers"]
			require(registry != nil, "current private key has no regional public registry")
			var public callerkey.Registry
			must(json.Unmarshal(registry.Current.Content, &public))
			require(slices.ContainsFunc(public.Callers, func(c callerkey.Caller) bool {
				return c.Kid == key.Kid && c.JWK.X == key.X && c.JWK.Y == key.Y
			}), "CURRENT private key lacks public half in "+cell)
		}
	}
}
func (s *store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Operation   string
		Name        string
		Before      callerkey.Snapshot
		State       callerkey.PrivateState
		Value       []byte
		Version     int64
		VersionName string
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
	case "read", "private":
		if in.Operation == "private" {
			s.privateReads++
		}
		if s.hidden[in.Name] {
			http.Error(w, "accepted write not readable yet", 404)
			return
		}
		if in.Operation == "private" {
			copy := *value
			copy.Scheduled = map[int64]time.Time{}
			copy.Versions, copy.Pending, copy.Deleting = nil, nil, nil
			for i, v := range value.Versions {
				if value.Deleting[i] {
					copy.Scheduled[v.Version] = value.DeletionTimes[i]
				}
				if !value.Deleting[i] {
					copy.Versions = append(copy.Versions, v)
					copy.Pending = append(copy.Pending, value.Pending[i])
				}
			}
			w.Write(encoded(copy))
			return
		}
		w.Write(encoded(value.Current))
		if s.reads != nil && in.Name == "sjc-1-terrabase-callers" {
			reads, release := s.reads, s.release
			s.Unlock()
			reads <- struct{}{}
			<-release
			s.Lock()
		}
		return
	}
	s.writes++
	if s.landAt > 0 && s.writes == s.landAt {
		require(s.land(), "injected delivery did not land before competing private write")
		s.land, s.landAt = nil, 0
	}
	apply := func() bool {
		value := s.values[in.Name]
		if value == nil {
			value = &secret{}
		}
		if in.Operation == "write" && value.Current.Version != in.Before.Version || in.Operation != "write" && value.Etag != in.State.Etag {
			return false
		}
		if in.Operation == "activate" || in.Operation == "discard" {
			i := slices.IndexFunc(value.Versions, func(v wireSnapshot) bool { return v.Version == in.Version })
			require(i >= 0, "version not found")
			if in.Operation == "activate" {
				require(value.Pending[i] && !value.Deleting[i], "promotion did not name usable pending version")
				value.Current = value.Versions[i]
				value.Pending[i] = false
			} else {
				require(!value.Pending[i] && value.Current.Version != in.Version, "only deprecated versions can be deleted")
				value.Deleting[i] = true
				value.DeletionTimes[i] = s.now.Add(7 * 24 * time.Hour)
			}
		} else {
			require(len(in.Value) <= 16384, "publication exceeds store limit")
			if in.Operation == "stage" {
				for i := range value.Pending {
					value.Pending[i] = false
				}
			}
			versionName := in.VersionName
			if in.Operation == "write" && strings.HasSuffix(in.Name, "-terrabase-key") {
				var key struct {
					Kid string `json:"kid"`
				}
				must(json.Unmarshal(in.Value, &key))
				versionName = key.Kid
			}
			next := wireSnapshot{Snapshot: callerkey.Snapshot{ID: in.Name, Version: int64(len(value.Versions) + 1)}, Content: bytes.Clone(in.Value), Name: versionName}
			value.Versions = append(value.Versions, next)
			value.Pending = append(value.Pending, in.Operation == "stage")
			value.Deleting = append(value.Deleting, false)
			value.DeletionTimes = append(value.DeletionTimes, time.Time{})
			if in.Operation == "write" {
				value.Current = next
			}
		}
		value.Revision++
		value.Etag = strconv.Itoa(value.Revision)
		s.values[in.Name] = value
		s.invariant()
		if s.hideAfterStage && in.Operation == "stage" {
			s.hidden[in.Name] = true
			s.hideAfterStage = false
		}
		return true
	}
	failing := s.writes == s.fail
	kill := func() {
		pid, err := strconv.Atoi(r.Header.Get("Caller-Key-Pid"))
		must(err)
		must(syscall.Kill(pid, syscall.SIGKILL))
	}
	if failing && s.mode == "before" {
		http.Error(w, "injected write failure", 409)
		return
	}
	if failing && s.mode == "late" {
		s.land = apply
		kill()
		http.Error(w, "request still in flight", 409)
		return
	}
	if !apply() {
		http.Error(w, "conditional version conflict", 409)
		return
	}
	if failing {
		if s.mode == "hidden" {
			s.hidden[in.Name] = true
		}
		if s.mode == "crash" || s.mode == "hidden" {
			kill()
		}
		http.Error(w, "injected uncertain write", 409)
		return
	}
	if in.Operation == "discard" {
		i := slices.IndexFunc(value.Versions, func(v wireSnapshot) bool { return v.Version == in.Version })
		require(value.DeletionTimes[i].Equal(s.now.Add(7*24*time.Hour)), "deletion grace differs")
		w.Write(encoded(value.DeletionTimes[i]))
		return
	}
	w.Write(encoded(true))
}

type journey struct {
	binary, root, targets, reverse string
	store                          *store
	server                         *httptest.Server
	seeds                          map[string][]byte
	seedArgs                       map[string][]string
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
	j.store.hidden = map[string]bool{}
	j.store.land = nil
	j.store.landAt = 0
	j.store.now = time.Now().UTC()
	j.store.hideAfterStage = false
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
	if snapshot, ok := j.seeds[operation]; ok {
		must(json.Unmarshal(snapshot, &j.store.values))
		return j.seedArgs[operation]
	}
	args := j.prepare(operation)
	if j.seeds == nil {
		j.seeds = map[string][]byte{}
		j.seedArgs = map[string][]string{}
	}
	j.seeds[operation] = encoded(j.store.values)
	j.seedArgs[operation] = args
	return args
}
func (j *journey) prepare(operation string) []string {
	if operation == "first" {
		return add("ts-auth.sjc.1")
	}
	j.ok(add("ts-auth.sjc.1")...)
	if operation == "add" {
		return add("ts-auth.sjc.2")
	}
	j.ok(add("ts-auth.sjc.2")...)
	if operation == "cancel" {
		j.expire("ts-auth.sjc.2")
		return []string{"retire", "--kid", "ts-auth.sjc.2"}
	}
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
func (j *journey) endState(operation string, applied bool) {
	j.converged()
	j.store.invariant()
	var registry callerkey.Registry
	value := j.store.values["fra-1-terrabase-callers"]
	if value == nil {
		return
	}
	must(json.Unmarshal(value.Current.Content, &registry))
	id := "ts-auth.sjc.2"
	if operation == "first" || operation == "retire" {
		id = "ts-auth.sjc.1"
	}
	listed := slices.ContainsFunc(registry.Callers, func(c callerkey.Caller) bool { return c.Kid == id })
	private := j.store.values["sjc-1-ts-auth-terrabase-key"]
	if operation == "first" || operation == "add" {
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
		require(!stored || listed, "add recovery lost a public entry for a visible private key")
		if applied {
			require(listed, "add recovery did not keep its public entry")
		}
	}
	if applied && (operation == "retire" || operation == "cancel") {
		require(!listed, "removal recovery retained public entry")
		if operation == "cancel" {
			for i, version := range private.Versions {
				var key struct {
					Kid string `json:"kid"`
				}
				must(json.Unmarshal(version.Content, &key))
				require(key.Kid != id || !private.Pending[i] && private.Deleting[i], "cancelled version remains usable")
			}
			_, err := j.run(j.targets, "activate", "--kid", id)
			require(err != nil, "cancelled version activated")
			_, err = j.run(j.targets, add(id)...)
			require(err != nil, "cancelled sequence reused")
			j.ok(add("ts-auth.sjc.3")...)
			j.converged()
		}
	}
	if applied && operation == "activate" {
		var key struct {
			Kid string `json:"kid"`
		}
		must(json.Unmarshal(private.Current.Content, &key))
		require(key.Kid == id, "activation did not finish forward")
	}
}
func (j *journey) failOriginal(operation, mode string, boundary int) {
	args := j.seed(operation)
	j.store.fail, j.store.mode = j.store.writes+boundary, mode
	_, err := j.run(j.targets, args...)
	require(err != nil, fmt.Sprintf("%s %s write %d did not interrupt", operation, mode, boundary))
	j.store.fail = 0
	j.store.invariant()
}
func (j *journey) failures() {
	for _, operation := range []string{"first", "add", "activate", "retire", "cancel"} {
		args := j.seed(operation)
		start := j.store.writes
		j.ok(args...)
		count := j.store.writes - start
		for _, mode := range []string{"before", "uncertain", "crash", "hidden", "late"} {
			for n := 1; n <= count; n++ {
				j.failOriginal(operation, mode, n)
				if mode == "hidden" {
					start := j.store.writes
					out, err := j.run(j.targets, "recover")
					if operation != "first" && operation != "add" {
						require(err != nil && j.store.writes == start, "unreadable removal mutated state")
					} else if err == nil {
						require(strings.Contains(out, "public entry kept; private key not visible"), "unreadable add did not report retained publication: "+out)
					}
					j.store.hidden = map[string]bool{}
				}
				if mode == "late" {
					_, _ = j.run(j.targets, "recover")
					j.store.Lock()
					require(j.store.land != nil, "missing in-flight request")
					landed := j.store.land()
					expected := n == 1 || (operation == "first" || operation == "add") && n == 7
					require(landed == expected, fmt.Sprintf("%s late original boundary %d delivery=%t expected=%t", operation, n, landed, expected))
					j.store.land = nil
					j.store.invariant()
					j.store.Unlock()
				}
				j.recover()
				j.endState(operation, n > 1 || mode != "before" && mode != "late")
				j.store.cases++
			}
		}
		boundaries := []int{1, 4}
		if operation == "first" || operation == "add" {
			boundaries = []int{1, 7}
		}
		if operation == "cancel" {
			boundaries = []int{1, 4, 5}
		}
		for _, original := range boundaries {
			j.failOriginal(operation, "crash", original)
			start := j.store.writes
			j.ok("recover")
			recoveryWrites := j.store.writes - start
			for _, mode := range []string{"before", "uncertain", "crash", "hidden", "late"} {
				for n := 1; n <= recoveryWrites; n++ {
					j.failOriginal(operation, "crash", original)
					j.store.fail, j.store.mode = j.store.writes+n, mode
					_, err := j.run(j.targets, "recover")
					require(err != nil, fmt.Sprintf("%s original %d recovery %s boundary %d did not interrupt", operation, original, mode, n))
					j.store.fail = 0
					j.store.invariant()
					if mode == "hidden" {
						before := j.store.writes
						_, err := j.run(j.targets, "recover")
						require(err != nil && j.store.writes == before, "recover changed an unreadable accepted recovery write")
						j.store.hidden = map[string]bool{}
					}
					if mode == "late" {
						j.recover()
						j.store.Lock()
						require(j.store.land != nil, "missing recovery request")
						require(!j.store.land(), "late recovery request overwrote a newer version")
						j.store.land = nil
						j.store.invariant()
						j.store.Unlock()
					}
					j.recover()
					j.endState(operation, true)
					j.store.cases++
				}
			}
		}
		fmt.Println(operation, "-> original and recovery interruptions, delayed visibility, late requests:", count, "original write boundaries")
	}
}
func (j *journey) expire(kid string) {
	j.setExpiry(kid, time.Now().Add(-time.Hour).UTC())
}
func (j *journey) setExpiry(kid string, expiry time.Time) {
	for name, v := range j.store.values {
		if !strings.HasSuffix(name, "-terrabase-callers") {
			continue
		}
		var r callerkey.Registry
		must(json.Unmarshal(v.Current.Content, &r))
		for i := range r.Callers {
			if r.Callers[i].Kid == kid {
				r.Callers[i].NotAfter = expiry
			}
		}
		v.Current.Content = encoded(r)
		j.store.invariant()
	}
}
func (j *journey) lateCreations() {
	for _, operation := range []string{"first", "add"} {
		for _, delay := range []time.Duration{0, 11 * time.Minute, 100 * 365 * 24 * time.Hour} {
			for _, ordering := range []string{"immediate", "after recover", "after another add", "during another add", "after retire attempt", "after replacement retirement"} {
				j.failOriginal(operation, "late", 7)
				j.store.now = j.store.now.Add(delay)
				id, replacement, next := "ts-auth.sjc.1", "ts-auth.sjc.2", "ts-auth.sjc.2"
				if operation == "add" {
					id, replacement, next = "ts-auth.sjc.2", "ts-auth.sjc.1", "ts-auth.sjc.3"
				}
				if ordering != "immediate" {
					out := j.ok("recover")
					require(strings.Contains(out, "public entry kept; private key not visible"), "add recovery did not describe retained entry: "+out)
					require(strings.Contains(j.ok("list"), "orphan (no private key visible)"), "orphan label missing")
					_, err := j.run(j.targets, add(id)...)
					require(err != nil, "interrupted add sequence reused")
				}
				if ordering == "after another add" || ordering == "after replacement retirement" {
					j.ok(add(next)...)
					if operation == "add" {
						j.ok("activate", "--kid", next)
						replacement = next
					}
				}
				if ordering == "during another add" {
					j.store.landAt = j.store.writes + 7
					out, err := j.run(j.targets, add(next)...)
					require(err != nil && strings.Contains(out, "interrupted"), "stale private writer did not conflict: "+out)
					j.recover()
				} else {
					if ordering == "after retire attempt" || ordering == "after replacement retirement" {
						before := j.store.writes
						out, err := j.run(j.targets, "retire", "--kid", id, "--replacement-kid", replacement)
						if operation == "first" && ordering == "after retire attempt" {
							require(err != nil && strings.Contains(out, "orphan public entry cannot be retired") && j.store.writes == before, "retire without current replacement mutated state: "+out)
						} else {
							require(err == nil, "positive replacement retirement failed: "+out)
						}
					}
					j.store.Lock()
					landed := j.store.land()
					j.store.land = nil
					j.store.invariant()
					j.store.Unlock()
					if ordering == "after another add" || ordering == "after replacement retirement" {
						require(!landed, "create-once name or conditional version allowed a stale private write")
					} else {
						require(landed, "accepted private creation failed without a competing version")
					}
					if operation == "add" && ordering == "after retire attempt" {
						_, err := j.run(j.targets, "activate", "--kid", id)
						require(err != nil, "late pending version activated without a public entry")
						j.ok("retire", "--kid", id)
					}
					j.recover()
				}
				j.store.invariant()
				j.store.cases++
			}
		}
	}
	fmt.Println("accepted first creation and pending rotation with simulated store-clock offsets (CLI wall clock unchanged): immediately, after recover, after/during another add, after retire attempt, after replacement retirement -> invariant holds after every mutation")
}

func (j *journey) overlappingCreations() {
	for _, delay := range []time.Duration{0, 11 * time.Minute, 100 * 365 * 24 * time.Hour} {
		for _, winner := range []string{"ts-auth.sjc.1", "ts-auth.sjc.2"} {
			j.failOriginal("first", "late", 7)
			first := j.store.land
			j.ok("recover")
			j.store.fail, j.store.mode = j.store.writes+7, "late"
			_, err := j.run(j.targets, add("ts-auth.sjc.2")...)
			require(err != nil, "second first creation did not interrupt")
			j.store.fail = 0
			second := j.store.land
			j.store.land = nil
			j.ok("recover")
			before := j.store.writes
			out, err := j.run(j.targets, "retire", "--kid", "ts-auth.sjc.1", "--replacement-kid", "ts-auth.sjc.2")
			require(err != nil && strings.Contains(out, "orphan public entry cannot be retired") && j.store.writes == before, "two outstanding creations permitted retirement: "+out)
			j.store.now = j.store.now.Add(delay)
			loser := "ts-auth.sjc.2"
			if winner == "ts-auth.sjc.2" {
				first, second = second, first
				loser = "ts-auth.sjc.1"
			}
			j.store.Lock()
			require(first(), "first accepted creation to land was rejected")
			j.store.invariant()
			require(!second(), "another accepted creation overwrote the create-once name")
			j.store.invariant()
			j.store.Unlock()
			j.recover()
			j.ok("retire", "--kid", loser, "--replacement-kid", winner)
			require(strings.Contains(j.ok(add("ts-auth.sjc.3")...), "pending"), "add after late first creation did not rotate")
			j.converged()
			j.store.invariant()
			j.store.cases++
		}
	}
	fmt.Println("two accepted first creations with simulated store-clock offsets (CLI wall clock unchanged), after both adds died, recover and retire refusal: either landing order -> one published CURRENT key, next add rotates")
}

func (j *journey) safetyNet() {
	j.failOriginal("first", "before", 7)
	j.recover()
	before := j.store.writes
	out, err := j.run(j.targets, "retire", "--kid", "ts-auth.sjc.1")
	require(err != nil && strings.Contains(out, "orphan public entry cannot be retired") && j.store.writes == before, "orphan retirement without secret was allowed: "+out)
	j.store.cases++
	j.failOriginal("first", "crash", 1)
	require(strings.Count(j.ok("list"), "NO REGISTRY") == 2, "absent registries were concealed")
	j.recover()
	j.store.cases++
	for _, intent := range []bool{false, true} {
		for _, mismatch := range []bool{false, true} {
			j.reset()
			j.ok(add("ts-auth.sjc.1")...)
			if intent {
				j.store.fail, j.store.mode = j.store.writes+1, "crash"
				_, err := j.run(j.targets, add("ts-auth.sjc.2")...)
				require(err != nil, "add intent did not interrupt")
				j.store.fail = 0
			}
			value := j.store.values["fra-1-terrabase-callers"]
			var registry callerkey.Registry
			must(json.Unmarshal(value.Current.Content, &registry))
			if mismatch {
				private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				must(err)
				registry.Callers[0].JWK.X = base64.RawURLEncoding.EncodeToString(private.X.FillBytes(make([]byte, 32)))
				registry.Callers[0].JWK.Y = base64.RawURLEncoding.EncodeToString(private.Y.FillBytes(make([]byte, 32)))
			} else {
				registry.Callers = slices.DeleteFunc(registry.Callers, func(c callerkey.Caller) bool { return c.Kid == "ts-auth.sjc.1" })
			}
			value.Current.Content = encoded(registry)
			before := j.store.writes
			out, err := j.run(j.targets, "list")
			require(err != nil && strings.Contains(out, "current key ts-auth.sjc.1 in region sjc has no public entry in regions fra") && j.store.writes == before, "list did not flag hand-made violation without writes: "+out)
			if !intent {
				out, err = j.run(j.targets, add("ts-auth.sjc.2")...)
				require(err != nil && strings.Contains(out, "run caller-key recover") && j.store.writes == before, "new intent admitted while current-key repair was required: "+out)
			}
			out = j.ok("recover")
			require(strings.Contains(out, "repaired current key ts-auth.sjc.1 in region fra"), "recover did not report repair: "+out)
			j.converged()
			j.store.invariant()
			j.ok("list")
			j.store.cases++
		}
	}
	for _, mode := range []string{"before", "uncertain", "crash", "hidden", "late"} {
		j.reset()
		j.ok(add("ts-auth.sjc.1")...)
		value := j.store.values["fra-1-terrabase-callers"]
		var registry callerkey.Registry
		must(json.Unmarshal(value.Current.Content, &registry))
		registry.Callers = []callerkey.Caller{}
		value.Current.Content = encoded(registry)
		j.store.fail, j.store.mode = j.store.writes+1, mode
		out, err := j.run(j.targets, "recover")
		require(err != nil, "repair write did not interrupt: "+out)
		j.store.fail = 0
		j.store.hidden = map[string]bool{}
		if mode == "late" {
			j.recover()
			j.store.Lock()
			require(!j.store.land(), "late repair overwrote a newer registry version")
			j.store.land = nil
			j.store.Unlock()
		}
		j.recover()
		j.store.invariant()
		j.store.cases++
	}
	for _, operation := range []string{"cancel", "activate"} {
		j.failOriginal(operation, "crash", 3)
		if operation == "activate" {
			j.expire("ts-auth.sjc.2")
		}
		private := j.store.values["sjc-1-ts-auth-terrabase-key"]
		versions, pending, deleting, times := private.Versions, private.Pending, private.Deleting, private.DeletionTimes
		private.Versions, private.Pending, private.Deleting, private.DeletionTimes = versions[:1], pending[:1], deleting[:1], times[:1]
		before := j.store.writes
		out, err := j.run(j.targets, "recover")
		require(err != nil && (strings.Contains(out, "version missing") || strings.Contains(out, "version not visible")) && j.store.writes == before, "missing cancellation evidence allowed mutations: "+out)
		private.Versions, private.Pending, private.Deleting, private.DeletionTimes = versions, pending, deleting, times
		j.recover()
		j.store.cases++
	}
	j.failOriginal("activate", "crash", 4)
	j.expire("ts-auth.sjc.2")
	require(strings.Contains(j.ok("recover"), "current key expired"), "already promoted expired recovery did not report expiry")
	j.store.cases++
	j.seed("cancel")
	require(strings.Contains(j.ok("list"), "expired; can only be cancelled"), "expired pending status missing")
	j.store.hideAfterStage = true
	out, err = j.run(j.targets, "retire", "--kid", "ts-auth.sjc.2")
	require(err != nil && strings.Contains(out, "interrupted") && !strings.Contains(out, "waiting"), "post-write interruption outcome missing: "+out)
	j.store.hidden = map[string]bool{}
	j.recover()
	j.endState("cancel", true)
	j.store.cases++
	fmt.Println("no-secret retirement refusal; current-key missing/mismatched public detection and repair with/without intent; expired-current output; cancellation readback interruption -> passed")
}

func (j *journey) expiredRecovery() {
	for _, lifetime := range []time.Duration{24 * time.Hour, -time.Hour} {
		j.failOriginal("activate", "crash", 3)
		j.setExpiry("ts-auth.sjc.2", time.Now().Add(lifetime))
		start := j.store.writes
		out := j.ok("recover")
		require(strings.Contains(out, "activation no longer valid; cancelled pending key") && strings.Contains(out, "deletion scheduled"), "recovery promoted invalid pending key: "+out)
		count := j.store.writes - start
		for _, mode := range []string{"before", "uncertain", "crash", "hidden", "late"} {
			for n := 1; n <= count; n++ {
				j.failOriginal("activate", "crash", 3)
				j.setExpiry("ts-auth.sjc.2", time.Now().Add(lifetime))
				j.store.fail, j.store.mode = j.store.writes+n, mode
				_, err := j.run(j.targets, "recover")
				require(err != nil, "invalid activation recovery did not interrupt")
				j.store.fail = 0
				j.store.invariant()
				j.store.hidden = map[string]bool{}
				if mode == "late" {
					j.store.Lock()
					require(j.store.land(), "immediate expired-recovery delivery was rejected without an intervening mutation")
					j.store.land = nil
					j.store.invariant()
					j.store.Unlock()
				}
				j.recover()
				var key struct {
					Kid string `json:"kid"`
				}
				private := j.store.values["sjc-1-ts-auth-terrabase-key"]
				must(json.Unmarshal(private.Current.Content, &key))
				require(key.Kid == "ts-auth.sjc.1", "recovery promoted expired or short-lived key")
				for _, cell := range []string{"fra", "gru", "sjc"} {
					var r callerkey.Registry
					must(json.Unmarshal(j.store.values[cell+"-1-terrabase-callers"].Current.Content, &r))
					require(!slices.ContainsFunc(r.Callers, func(c callerkey.Caller) bool { return c.Kid == "ts-auth.sjc.2" }), "invalid pending public entry retained")
				}
				j.store.cases++
			}
		}
	}
	fmt.Println("expired and less-than-minimum-life activation recovery -> cancellation at every recovery mutation boundary passed")
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
	build := exec.Command("nice", "-n", "19", "go", "build", "-p", "2", "-overlay", overlay, "-trimpath", "-o", binary, "./cmd/terrascale-orchestrator")
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
	j.reviewedCases()
	j.failures()
	j.lateCreations()
	j.overlappingCreations()
	j.safetyNet()
	j.expiredRecovery()
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
		j.store.invariant()
	}
	require(strings.Contains(j.ok("list"), "expired"), "expired status absent")
	require(strings.Contains(j.ok("list"), "expires within 30 days"), "expiry warning absent")
	for _, id := range []string{"agent.deploy.1", "op.admin.1"} {
		before := s.writes
		out, err := j.run(j.targets, "retire", "--kid", id)
		require(err != nil && strings.Contains(out, "does not manage that key's private half") && strings.Contains(out, "cannot prove a replacement is current") && s.writes == before, "unmanaged retirement did not explain its evidence boundary: "+out)
	}
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
	fmt.Println("near-expiry rotation, unmanaged retirement refusal, 50 rotations -> flat", start, "byte registries")
	_, err = j.run(j.targets, add("ts-auth.sjc.59")...)
	require(err != nil, "sequence reuse accepted")
	fmt.Println("caller-key real CLI subprocess journey -> passed;", s.cases, "fault cases")
}
