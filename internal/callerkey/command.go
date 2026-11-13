package callerkey

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const usage = `Usage: ts-orch caller-key <add|retire|list> --targets FILE [--regions deploy/m1/regions.json]
  add --service ts-auth|ts-dashboard|edge --region CELL --kid SERVICE.CELL.N --not-after RFC3339
  retire --kid SERVICE.CELL.N
  list

Targets is a JSON array of {cell, vault, key, compartment}, one per deployed region.
Add publishes the public registry in every cell before storing one private P-256 JWK
(with kid) in CELL-1-SERVICE-terrabase-key; edge uses CELL-1-orch-terrabase-key.
Output contains only key ids and secret names. Roll TerraBase before rolling callers.
If publication is interrupted, inspect list and retire the incomplete kid before retrying.
`

type Target struct {
	Cell        string `json:"cell"`
	Vault       string `json:"vault"`
	Key         string `json:"key"`
	Compartment string `json:"compartment"`
}

type Snapshot struct {
	ID      string
	Version int64
	Value   []byte `json:"-"`
}

type Store interface {
	Read(context.Context, Target, string) (Snapshot, error)
	Write(context.Context, Target, string, Snapshot, []byte) error
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type Caller struct {
	Kid      string    `json:"kid"`
	Caller   string    `json:"caller"`
	Kind     string    `json:"kind"`
	JWK      JWK       `json:"jwk"`
	Grants   []string  `json:"grants"`
	NotAfter time.Time `json:"notAfter"`
}

type Registry struct {
	Version int      `json:"version"`
	Callers []Caller `json:"callers"`
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	return RunWithStore(ctx, args, out, vaultStore{})
}

var kidRE = regexp.MustCompile(`^(ts-auth|ts-dashboard|edge)\.([a-z]{3})\.([1-9][0-9]*)$`)
var operatorRE = regexp.MustCompile(`^(op|agent)\.([a-z0-9-]+)\.([1-9][0-9]*)$`)
var dataGrantRE = regexp.MustCompile(`(?i)^data:[0-7][0-9a-hjkmnp-tv-z]{25}$`)

func RunWithStore(ctx context.Context, args []string, out io.Writer, store Store) error {
	if len(args) == 0 || slices.Contains([]string{"help", "--help", "-h"}, args[0]) {
		_, err := io.WriteString(out, usage)
		return err
	}
	if !slices.Contains([]string{"add", "retire", "list"}, args[0]) {
		return errors.New("unknown caller-key command")
	}
	flags := flag.NewFlagSet("caller-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	targetsPath := flags.String("targets", "", "regional Vault targets")
	regionsPath := flags.String("regions", "deploy/m1/regions.json", "deployed regions")
	service := flags.String("service", "", "service caller")
	region := flags.String("region", "", "caller region")
	kid := flags.String("kid", "", "key id")
	expiry := flags.String("not-after", "", "key expiry")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *targetsPath == "" {
		return errors.New("caller-key requires --targets and no positional arguments")
	}
	var notAfter time.Time
	if args[0] == "add" {
		parts := kidRE.FindStringSubmatch(*kid)
		var err error
		notAfter, err = time.Parse(time.RFC3339, *expiry)
		if len(parts) != 4 || parts[1] != *service || parts[2] != *region || err != nil || !notAfter.After(time.Now()) {
			return errors.New("add requires a matching service, region, numbered kid and future --not-after")
		}
	} else if *service != "" || *region != "" || *expiry != "" || args[0] == "list" && *kid != "" || args[0] == "retire" && !kidRE.MatchString(*kid) {
		return errors.New("list takes only targets and regions; retire requires a service kid")
	}
	var targets []Target
	var regions []struct {
		Region string `json:"region"`
	}
	if err := readJSON(*targetsPath, &targets); err != nil {
		return err
	}
	if err := readJSON(*regionsPath, &regions); err != nil {
		return err
	}
	cells := map[string]bool{}
	for _, r := range regions {
		if _, ok := catalog.LookupName(r.Region); !ok || cells[r.Region] {
			return errors.New("invalid or duplicate deployed region")
		}
		cells[r.Region] = true
	}
	if len(cells) == 0 || len(cells) != len(targets) {
		return errors.New("targets must cover every deployed region exactly once")
	}
	var selected Target
	seen := map[string]bool{}
	for _, t := range targets {
		entry, ok := catalog.LookupName(t.Cell)
		if !ok || !cells[t.Cell] || seen[t.Cell] || !strings.HasPrefix(t.Vault, "ocid1.vault.oc1."+entry.OCIRegion+".") || !strings.HasPrefix(t.Key, "ocid1.key.oc1."+entry.OCIRegion+".") || !strings.HasPrefix(t.Compartment, "ocid1.compartment.") {
			return errors.New("targets require distinct deployed cells and regional Vault, key and compartment OCIDs")
		}
		seen[t.Cell] = true
		if t.Cell == *region {
			selected = t
		}
	}
	if args[0] == "add" && selected.Cell == "" {
		return errors.New("caller region is not deployed")
	}
	snapshots := make([]Snapshot, len(targets))
	callers := map[string]Caller{}
	for i, t := range targets {
		current, err := store.Read(ctx, t, registryName(t))
		if err != nil {
			return err
		}
		snapshots[i] = current
		if current.Version == 0 {
			continue
		}
		var registry Registry
		if err := json.Unmarshal(current.Value, &registry, json.RejectUnknownMembers(true)); err != nil || registry.Version != 1 || registry.Callers == nil {
			return fmt.Errorf("invalid caller registry %s", registryName(t))
		}
		local := map[string]bool{}
		for _, c := range registry.Callers {
			if err := validateCaller(c); err != nil || local[c.Kid] {
				return fmt.Errorf("invalid caller entry in %s", registryName(t))
			}
			local[c.Kid] = true
			if previous, exists := callers[c.Kid]; exists {
				a, _ := json.Marshal(previous)
				b, _ := json.Marshal(c)
				if string(a) != string(b) {
					return errors.New("registries disagree on a caller key")
				}
			}
			callers[c.Kid] = c
		}
	}
	if args[0] == "list" {
		for _, t := range targets {
			if _, err := fmt.Fprintln(out, registryName(t)); err != nil {
				return err
			}
		}
		for _, id := range slices.SortedFunc(maps.Keys(callers), strings.Compare) {
			if _, err := fmt.Fprintln(out, id); err != nil {
				return err
			}
		}
		return nil
	}
	var private []byte
	var previous Snapshot
	var secret string
	if args[0] == "add" {
		if _, exists := callers[*kid]; exists {
			return errors.New("kid already registered; choose a new sequence number")
		}
		sequence, err := strconv.ParseUint(strings.TrimPrefix(*kid, *service+"."+*region+"."), 10, 64)
		if err != nil {
			return errors.New("kid sequence is out of range")
		}
		secret = selected.Cell + "-1-" + *service + "-terrabase-key"
		if *service == "edge" {
			secret = selected.Cell + "-1-orch-terrabase-key"
		}
		previous, err = store.Read(ctx, selected, secret)
		if err != nil {
			return err
		}
		defer clear(previous.Value)
		if previous.Version > 0 {
			var old struct {
				Kid string `json:"kid"`
			}
			if json.Unmarshal(previous.Value, &old) != nil || !strings.HasPrefix(old.Kid, *service+"."+*region+".") {
				return errors.New("existing private key has an invalid caller kid")
			}
			prior, err := strconv.ParseUint(strings.TrimPrefix(old.Kid, *service+"."+*region+"."), 10, 64)
			if err != nil || sequence <= prior {
				return errors.New("new kid sequence must exceed the stored caller key")
			}
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return errors.New("generate caller key failed")
		}
		pub := JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
		scalar := key.D.FillBytes(make([]byte, 32))
		defer clear(scalar)
		private, err = json.Marshal(struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			D   string `json:"d"`
		}{*kid, pub.Kty, pub.Crv, pub.X, pub.Y, base64.RawURLEncoding.EncodeToString(scalar)})
		if err != nil {
			return errors.New("encode caller key failed")
		}
		defer clear(private)
		grants := map[string][]string{
			"ts-auth":      {"data:00000000000000000000000002", "closure"},
			"ts-dashboard": {"data:00000000000000000000000005", "plans", "usage.read", "catalog.read"},
			"edge":         {"rollout"},
		}
		callers[*kid] = Caller{*kid, *service, "service", pub, grants[*service], notAfter.UTC()}
	} else {
		if _, exists := callers[*kid]; !exists {
			return errors.New("kid is not registered")
		}
		delete(callers, *kid)
	}
	registry := Registry{Version: 1, Callers: []Caller{}}
	for _, id := range slices.SortedFunc(maps.Keys(callers), strings.Compare) {
		registry.Callers = append(registry.Callers, callers[id])
	}
	value, err := json.Marshal(registry)
	if err != nil {
		return err
	}
	for i, t := range targets {
		if err := store.Write(ctx, t, registryName(t), snapshots[i], value); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, registryName(t)); err != nil {
			return err
		}
	}
	if args[0] == "add" {
		if err := store.Write(ctx, selected, secret, previous, private); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, secret); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(out, *kid)
	return err
}

func readJSON(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return errors.New("invalid caller-key input JSON")
	}
	return nil
}

func registryName(t Target) string { return t.Cell + "-1-terrabase-callers" }

func validateCaller(c Caller) error {
	if c.Kid == "" || c.Caller == "" || !slices.Contains([]string{"service", "operator"}, c.Kind) || c.NotAfter.IsZero() || len(c.Grants) == 0 || c.JWK.Kty != "EC" || c.JWK.Crv != "P-256" {
		return errors.New("invalid caller metadata")
	}
	if c.Kind == "service" {
		parts := kidRE.FindStringSubmatch(c.Kid)
		if len(parts) != 4 || parts[1] != c.Caller {
			return errors.New("invalid service caller id")
		}
		if _, ok := catalog.LookupName(parts[2]); !ok {
			return errors.New("unknown caller region")
		}
	} else {
		parts := operatorRE.FindStringSubmatch(c.Kid)
		if len(parts) != 4 || c.Caller != parts[1]+":"+parts[2] {
			return errors.New("invalid operator caller id")
		}
	}
	grants := map[string]bool{}
	for _, grant := range c.Grants {
		if grants[grant] || !slices.Contains([]string{"closure", "plans", "usage.read", "catalog.read", "rollout", "platform.read", "platform.write", "act-as", "admin", "audit.read"}, grant) && !dataGrantRE.MatchString(grant) {
			return errors.New("invalid caller grant")
		}
		grants[grant] = true
	}
	point := []byte{4}
	for _, coordinate := range []string{c.JWK.X, c.JWK.Y} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(coordinate)
		if err != nil || len(decoded) != 32 {
			return errors.New("invalid caller public key")
		}
		point = append(point, decoded...)
	}
	_, err := ecdh.P256().NewPublicKey(point)
	return err
}
