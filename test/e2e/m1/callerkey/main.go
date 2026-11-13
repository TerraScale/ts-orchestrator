package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/callerkey"
)

type store struct {
	values    map[string]callerkey.Snapshot
	writes    []string
	fail      string
	versions  map[string][]callerkey.KeyVersion
	revisions map[string]int
	regions   []string
}

func (s *store) Read(_ context.Context, _ callerkey.Target, name string) (callerkey.Snapshot, error) {
	value := s.values[name]
	value.Value = bytes.Clone(value.Value)
	return value, nil
}

func (s *store) Write(_ context.Context, _ callerkey.Target, name string, before callerkey.Snapshot, value []byte) error {
	if name == s.fail {
		return errors.New("publication refused")
	}
	if s.values[name].Version != before.Version {
		return errors.New("version conflict")
	}
	s.values[name] = callerkey.Snapshot{ID: name, Version: before.Version + 1, Value: bytes.Clone(value)}
	s.writes = append(s.writes, name)
	s.revisions[name]++
	if strings.HasSuffix(name, "-terrabase-key") {
		s.versions[name] = append(s.versions[name], callerkey.KeyVersion{Snapshot: s.values[name]})
	}
	return nil
}

func (s *store) Regions(context.Context) ([]string, error) { return slices.Clone(s.regions), nil }

func (s *store) Private(ctx context.Context, t callerkey.Target, name string) (callerkey.PrivateState, error) {
	current, err := s.Read(ctx, t, name)
	state := callerkey.PrivateState{Current: current, Etag: fmt.Sprint(s.revisions[name])}
	for _, v := range s.versions[name] {
		v.Value = bytes.Clone(v.Value)
		state.Versions = append(state.Versions, v)
	}
	return state, err
}

func (s *store) Stage(_ context.Context, _ callerkey.Target, name string, before callerkey.PrivateState, value []byte) error {
	if before.Etag != fmt.Sprint(s.revisions[name]) {
		return errors.New("version conflict")
	}
	version := callerkey.Snapshot{ID: name, Version: int64(len(s.versions[name]) + 1), Value: bytes.Clone(value)}
	s.versions[name] = append(s.versions[name], callerkey.KeyVersion{Snapshot: version, Pending: true})
	s.revisions[name]++
	s.writes = append(s.writes, name)
	return nil
}

func (s *store) Activate(_ context.Context, _ callerkey.Target, name string, before callerkey.PrivateState, version int64) error {
	if before.Etag != fmt.Sprint(s.revisions[name]) {
		return errors.New("version conflict")
	}
	for i, v := range s.versions[name] {
		if v.Version == version && v.Pending {
			s.values[name] = v.Snapshot
			s.versions[name][i].Pending = false
			s.revisions[name]++
			s.writes = append(s.writes, name)
			return nil
		}
	}
	return errors.New("pending version missing")
}

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func main() {
	root, err := os.MkdirTemp("", "caller-key-e2e-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)
	targets := []callerkey.Target{
		{Cell: "sjc", Vault: "ocid1.vault.oc1.us-sanjose-1.example", Key: "ocid1.key.oc1.us-sanjose-1.example", Compartment: "ocid1.compartment.oc1.example"},
		{Cell: "fra", Vault: "ocid1.vault.oc1.eu-frankfurt-1.example", Key: "ocid1.key.oc1.eu-frankfurt-1.example", Compartment: "ocid1.compartment.oc1.example"},
		{Cell: "gru", Vault: "ocid1.vault.oc1.sa-saopaulo-1.example", Key: "ocid1.key.oc1.sa-saopaulo-1.example", Compartment: "ocid1.compartment.oc1.example"},
	}
	data, err := json.Marshal(targets)
	if err != nil {
		panic(err)
	}
	targetsPath := filepath.Join(root, "targets.json")
	if err := os.WriteFile(targetsPath, data, 0600); err != nil {
		panic(err)
	}
	s := &store{values: map[string]callerkey.Snapshot{}, versions: map[string][]callerkey.KeyVersion{}, revisions: map[string]int{}, regions: []string{"sjc", "fra", "gru"}}
	var output bytes.Buffer
	run := func(args ...string) error {
		output.Reset()
		return callerkey.RunWithStore(context.Background(), append(args, "--targets", targetsPath), &output, s)
	}
	add := func(service, region, sequence string) error {
		return run("add", "--service", service, "--region", region, "--kid", service+"."+region+"."+sequence, "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	}
	secrets := map[string]string{"ts-auth": "sjc-1-ts-auth-terrabase-key", "dashboard": "fra-1-ts-dashboard-terrabase-key", "edge": "gru-1-orch-terrabase-key"}
	regions := map[string]string{"ts-auth": "sjc", "dashboard": "fra", "edge": "gru"}
	for _, service := range []string{"ts-auth", "dashboard", "edge"} {
		err := add(service, regions[service], "1")
		require(err == nil, "add failed")
		require(len(s.writes) == 4, "add must publish three registries and one private key")
		require(s.writes[3] == secrets[service], "private key published before registries")
		var key struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			D   string `json:"d"`
		}
		require(json.Unmarshal(s.values[secrets[service]].Value, &key) == nil, "invalid private JWK")
		require(key.Kid == service+"."+regions[service]+".1" && key.Kty == "EC" && key.Crv == "P-256", "wrong private JWK metadata")
		decode := func(text string) *big.Int {
			b, err := base64.RawURLEncoding.DecodeString(text)
			require(err == nil && len(b) == 32, "invalid key coordinate")
			return new(big.Int).SetBytes(b)
		}
		x, y, d := decode(key.X), decode(key.Y), decode(key.D)
		private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
		digest := sha256.Sum256([]byte("caller-key journey"))
		signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
		require(err == nil && ecdsa.VerifyASN1(&private.PublicKey, digest[:], signature), "private key cannot sign")
		require(!strings.Contains(output.String(), key.D) && !strings.Contains(output.String(), key.X), "output exposes key material")
		for _, target := range targets {
			var registry callerkey.Registry
			require(json.Unmarshal(s.values[target.Cell+"-1-terrabase-callers"].Value, &registry) == nil && registry.Version == 1, "invalid registry")
			index := slices.IndexFunc(registry.Callers, func(c callerkey.Caller) bool { return c.Kid == key.Kid })
			require(index >= 0, "caller missing from a cell")
			c := registry.Callers[index]
			require(c.Caller == service && c.Kind == "service" && c.JWK.X == key.X && c.JWK.Y == key.Y, "registry does not match private key")
			require(!bytes.Contains(s.values[target.Cell+"-1-terrabase-callers"].Value, []byte(key.D)), "private scalar in registry")
		}
		require(strings.Contains(output.String(), key.Kid+" current"), "first key was not current")
		require(run("activate", "--kid", key.Kid) == nil && strings.Contains(output.String(), "already current"), "first-key activation was not idempotent")
		require(run("list") == nil && strings.Contains(output.String(), key.Kid+" current") && strings.Contains(output.String(), "notAfter"), "first key list lacks stage or expiry")
		fmt.Println("add", service, "-> 3 public registries, first key current, matching private JWK, redacted output")
		s.writes = nil
	}
	refuse := func(fragment string, args ...string) {
		s.writes = nil
		err := run(args...)
		require(err != nil && strings.Contains(err.Error(), fragment), fmt.Sprint(args, ": expected ", fragment, ", got ", err))
		require(len(s.writes) == 0, "refused command wrote state")
	}
	change := func(cell string, edit func(*callerkey.Registry)) {
		name := cell + "-1-terrabase-callers"
		snapshot := s.values[name]
		var registry callerkey.Registry
		require(json.Unmarshal(snapshot.Value, &registry) == nil, "registry read failed")
		edit(&registry)
		snapshot.Value, err = json.Marshal(registry)
		require(err == nil, "registry encode failed")
		s.values[name] = snapshot
	}
	changeAll := func(edit func(*callerkey.Registry)) {
		for _, target := range targets {
			change(target.Cell, edit)
		}
	}
	refuse("sequence", "add", "--service", "ts-auth", "--region", "sjc", "--kid", "ts-auth.sjc.1", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	refuse("30 days", "add", "--service", "edge", "--region", "gru", "--kid", "edge.gru.2", "--not-after", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	refuse("current", "retire", "--kid", "dashboard.fra.1")
	old := bytes.Clone(s.values[secrets["ts-auth"]].Value)
	require(add("ts-auth", "sjc", "2") == nil, "rotation failed")
	require(bytes.Equal(old, s.values[secrets["ts-auth"]].Value), "pending rotation changed current key")
	require(run("list") == nil && strings.Contains(output.String(), "ts-auth.sjc.1 current") && strings.Contains(output.String(), "ts-auth.sjc.2 pending"), "list lost current/pending overlap")
	refuse("pending", "retire", "--kid", "ts-auth.sjc.2")
	refuse("current", "retire", "--kid", "ts-auth.sjc.1", "--replacement-kid", "ts-auth.sjc.2")
	refuse("listed in every region", "activate", "--kid", "ts-auth.sjc.9")
	refuse("pending", "add", "--service", "ts-auth", "--region", "sjc", "--kid", "ts-auth.sjc.3", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	var copied callerkey.Caller
	changeAll(func(r *callerkey.Registry) {
		for _, c := range r.Callers {
			if c.Kid == "ts-auth.sjc.2" {
				copied = c
			}
		}
		c := copied
		c.Kid = "ts-auth.sjc.9"
		r.Callers = append(r.Callers, c)
	})
	refuse("does not match", "activate", "--kid", "ts-auth.sjc.9")
	changeAll(func(r *callerkey.Registry) {
		r.Callers = slices.DeleteFunc(r.Callers, func(c callerkey.Caller) bool { return c.Kid == "ts-auth.sjc.9" })
	})
	for _, remaining := range []time.Duration{-time.Hour, 29 * 24 * time.Hour} {
		deadline := time.Now().Add(remaining).UTC()
		changeAll(func(r *callerkey.Registry) {
			for i := range r.Callers {
				if r.Callers[i].Kid == "ts-auth.sjc.1" {
					r.Callers[i].NotAfter = deadline
				}
			}
		})
		refuse("ts-auth.sjc.1 expires within 30 days", "activate", "--kid", "ts-auth.sjc.2")
		refuse("ts-auth.sjc.1 expires within 30 days", "add", "--service", "edge", "--region", "gru", "--kid", "edge.gru.2", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	}
	changeAll(func(r *callerkey.Registry) {
		for i := range r.Callers {
			if r.Callers[i].Kid == "ts-auth.sjc.1" {
				r.Callers[i].NotAfter = copied.NotAfter
			}
		}
	})
	saved := s.values["fra-1-terrabase-callers"]
	change("fra", func(r *callerkey.Registry) {
		r.Callers = slices.DeleteFunc(r.Callers, func(c callerkey.Caller) bool { return c.Kid == "ts-auth.sjc.2" })
	})
	refuse("registries differ", "activate", "--kid", "ts-auth.sjc.2")
	refuse("registries differ", "add", "--service", "edge", "--region", "gru", "--kid", "edge.gru.2", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	s.values["fra-1-terrabase-callers"] = saved
	require(run("activate", "--kid", "ts-auth.sjc.2") == nil, "activation failed")
	require(!bytes.Equal(old, s.values[secrets["ts-auth"]].Value), "activation retained old current")
	require(run("list") == nil && strings.Contains(output.String(), "ts-auth.sjc.2 current") && !strings.Contains(output.String(), "ts-auth.sjc.2 pending"), "activation did not promote pending")
	refuse("matching pending", "activate", "--kid", "ts-auth.sjc.1")
	refuse("--replacement-kid", "retire", "--kid", "ts-auth.sjc.1")
	refuse("--replacement-kid", "retire", "--kid", "ts-auth.sjc.1", "--replacement-kid", "edge.gru.1")
	changeAll(func(r *callerkey.Registry) {
		for i := range r.Callers {
			if r.Callers[i].Kid == "ts-auth.sjc.1" {
				r.Callers[i].NotAfter = time.Now().Add(-time.Hour).UTC()
			}
		}
	})
	require(run("retire", "--kid", "ts-auth.sjc.1", "--replacement-kid", "ts-auth.sjc.2") == nil, "expired old key could not retire")
	require(run("list") == nil && !strings.Contains(output.String(), "ts-auth.sjc.1") && strings.Contains(output.String(), "ts-auth.sjc.2 current"), "retire did not preserve current")
	fmt.Println("rotation -> pending, activation guards, promotion, explicit replacement retirement; expired and near-expiry entries block writes")
	changeAll(func(r *callerkey.Registry) {
		c := copied
		c.Kid = "ts-auth.fra.1"
		r.Callers = append(r.Callers, c)
	})
	refuse("last listed key for a region", "retire", "--kid", "ts-auth.fra.1")
	changeAll(func(r *callerkey.Registry) {
		r.Callers = slices.DeleteFunc(r.Callers, func(c callerkey.Caller) bool { return c.Kid == "ts-auth.fra.1" })
	})
	old = bytes.Clone(s.values[secrets["ts-auth"]].Value)
	s.fail = "fra-1-terrabase-callers"
	require(add("ts-auth", "sjc", "3") != nil && bytes.Equal(old, s.values[secrets["ts-auth"]].Value), "failed publication changed private key")
	s.fail = ""
	refuse("registries differ", "add", "--service", "edge", "--region", "gru", "--kid", "edge.gru.2", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	refuse("registries differ", "activate", "--kid", "ts-auth.sjc.2")
	s.fail = "fra-1-terrabase-callers"
	require(run("retire", "--kid", "ts-auth.sjc.3") != nil, "interrupted retire should fail")
	s.fail = ""
	refuse("registries differ", "add", "--service", "edge", "--region", "gru", "--kid", "edge.gru.2", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	require(run("retire", "--kid", "ts-auth.sjc.3") == nil, "partial retirement could not converge")
	for _, target := range targets {
		require(bytes.Equal(s.values[target.Cell+"-1-terrabase-callers"].Value, s.values["sjc-1-terrabase-callers"].Value), "retire did not converge registries")
	}
	refuse("sequence", "add", "--service", "ts-auth", "--region", "sjc", "--kid", "ts-auth.sjc.3", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	require(add("ts-auth", "sjc", "4") == nil, "fresh sequence after retirement failed")
	require(run("activate", "--kid", "ts-auth.sjc.4") == nil, "fresh rotation activation failed")
	changeAll(func(r *callerkey.Registry) {
		c := copied
		c.Kid = "ts-auth.sjc.8"
		r.Callers = append(r.Callers, c)
	})
	refuse("sequence", "add", "--service", "ts-auth", "--region", "sjc", "--kid", "ts-auth.sjc.7", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	require(run("retire", "--kid", "ts-auth.sjc.8") == nil, "unused public key retirement failed")
	refuse("sequence", "add", "--service", "ts-auth", "--region", "sjc", "--kid", "ts-auth.sjc.8", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	historical := callerkey.Snapshot{ID: secrets["ts-auth"], Version: 9, Value: []byte(`{"kid":"ts-auth.sjc.12"}`)}
	s.versions[secrets["ts-auth"]] = append(s.versions[secrets["ts-auth"]], callerkey.KeyVersion{Snapshot: historical})
	refuse("sequence", "add", "--service", "ts-auth", "--region", "sjc", "--kid", "ts-auth.sjc.11", "--not-after", time.Now().Add(90*24*time.Hour).UTC().Format(time.RFC3339))
	changeAll(func(r *callerkey.Registry) {
		c := copied
		c.Kid, c.Caller, c.Kind = "agent.deploy.1", "agent:deploy", "operator"
		r.Callers = append(r.Callers, c)
	})
	require(run("list") == nil && strings.Contains(output.String(), "agent.deploy.1"), "agent:name entry rejected")
	refuse("30 days", "add", "--service", "edge", "--region", "gru", "--kid", "ts-auth.gru.4", "--not-after", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	refuse("flag provided but not defined", "list", "--regions", "unused.json")
	s.regions = []string{"sjc", "fra"}
	refuse("every deployed region", "list")
	fmt.Println("retire guards, split add/activate refusals, interrupted retirement convergence, listed/retired/stored sequence reuse refusals, agent entries, discovered region coverage -> passed")
}
