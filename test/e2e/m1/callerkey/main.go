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
	values map[string]callerkey.Snapshot
	writes []string
	fail   string
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
	return nil
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
	regionsPath := filepath.Join(root, "regions.json")
	if err := os.WriteFile(regionsPath, []byte(`[{"region":"sjc"},{"region":"fra"},{"region":"gru"}]`), 0600); err != nil {
		panic(err)
	}
	s := &store{values: map[string]callerkey.Snapshot{}}
	var output bytes.Buffer
	run := func(args ...string) error {
		output.Reset()
		return callerkey.RunWithStore(context.Background(), append(args, "--targets", targetsPath, "--regions", regionsPath), &output, s)
	}
	add := func(service, region, sequence string) error {
		return run("add", "--service", service, "--region", region, "--kid", service+"."+region+"."+sequence, "--not-after", time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339))
	}
	secrets := map[string]string{"ts-auth": "sjc-1-ts-auth-terrabase-key", "ts-dashboard": "fra-1-ts-dashboard-terrabase-key", "edge": "gru-1-orch-terrabase-key"}
	regions := map[string]string{"ts-auth": "sjc", "ts-dashboard": "fra", "edge": "gru"}
	for _, service := range []string{"ts-auth", "ts-dashboard", "edge"} {
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
		fmt.Println("add", service, "-> 3 public registries, 1 matching private JWK, redacted output")
		s.writes = nil
	}
	require(add("ts-auth", "sjc", "1") != nil && len(s.writes) == 0, "duplicate kid changed secrets")
	old := bytes.Clone(s.values[secrets["ts-auth"]].Value)
	require(add("ts-auth", "sjc", "2") == nil, "rotation failed")
	require(!bytes.Equal(old, s.values[secrets["ts-auth"]].Value), "rotation retained old private key")
	require(run("list") == nil && strings.Contains(output.String(), "ts-auth.sjc.1") && strings.Contains(output.String(), "ts-auth.sjc.2"), "list lost overlapping keys")
	require(run("retire", "--kid", "ts-auth.sjc.1") == nil, "retire failed")
	require(run("list") == nil && !strings.Contains(output.String(), "ts-auth.sjc.1") && strings.Contains(output.String(), "ts-auth.sjc.2"), "retire did not preserve current key")
	fmt.Println("rotate, list, retire -> old and new overlap, old removed in every cell")
	old = bytes.Clone(s.values[secrets["ts-auth"]].Value)
	s.fail = "fra-1-terrabase-callers"
	require(add("ts-auth", "sjc", "3") != nil && bytes.Equal(old, s.values[secrets["ts-auth"]].Value), "failed registry publication changed caller private key")
	s.fail = ""
	require(run("retire", "--kid", "ts-auth.sjc.3") == nil, "partial publication could not be retired")
	require(run("list") == nil && !strings.Contains(output.String(), "ts-auth.sjc.3"), "partial key remains registered")
	fmt.Println("partial publication -> private key unchanged, incomplete kid retired")
	s.writes = nil
	require(run("add", "--service", "edge", "--region", "gru", "--kid", "ts-auth.gru.4", "--not-after", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)) != nil && len(s.writes) == 0, "mismatched kid accepted")
	require(os.WriteFile(regionsPath, []byte(`[{"region":"sjc"},{"region":"fra"}]`), 0600) == nil, "region file write failed")
	require(run("list") != nil, "incomplete region coverage accepted")
	fmt.Println("invalid caller and incomplete region targets -> rejected before writes")
}
