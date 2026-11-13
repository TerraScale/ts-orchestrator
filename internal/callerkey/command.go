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
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const minimumLifetime = 30 * 24 * time.Hour

const usage = `Usage: ts-orch caller-key <add|activate|retire|list> --targets FILE
  add --service ts-auth|dashboard|edge --region CELL --kid SERVICE.CELL.N --not-after RFC3339
  activate --kid SERVICE.CELL.N
  retire --kid SERVICE.CELL.N [--replacement-kid SERVICE.CELL.N]
  list

Targets is a JSON array of {cell, vault, key, compartment}, covering the authenticated footprint.
Add publishes every public registry before creating a first CURRENT key or a rotation PENDING key.
Roll TerraBase before shipping a first spec reference or activating a rotation.
Add and activate require identical registries and at least 30 days remaining on every listed key.
Output contains only key ids, secret names, stages and expiry times.
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

type KeyVersion struct {
	Snapshot
	Pending bool
}

type PrivateState struct {
	Current  Snapshot
	Versions []KeyVersion
	Etag     string
}

func (s PrivateState) Clear() {
	clear(s.Current.Value)
	for _, v := range s.Versions {
		clear(v.Value)
	}
}

type Store interface {
	Regions(context.Context) ([]string, error)
	Private(context.Context, Target, string) (PrivateState, error)
	Stage(context.Context, Target, string, PrivateState, []byte) error
	Activate(context.Context, Target, string, PrivateState, int64) error
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
	Retired []string `json:"retired,omitempty"`
}

func Run(ctx context.Context, args []string, out io.Writer) error {
	return RunWithStore(ctx, args, out, vaultStore{})
}

var kidRE = regexp.MustCompile(`^(ts-auth|dashboard|edge)\.([a-z]{3})\.([1-9][0-9]*)$`)
var operatorRE = regexp.MustCompile(`^(op|agent)\.([a-z0-9-]+)\.([1-9][0-9]*)$`)
var dataGrantRE = regexp.MustCompile(`(?i)^data:[0-7][0-9a-hjkmnp-tv-z]{25}$`)

func RunWithStore(ctx context.Context, args []string, out io.Writer, store Store) error {
	if len(args) == 0 || slices.Contains([]string{"help", "--help", "-h"}, args[0]) {
		_, err := io.WriteString(out, usage)
		return err
	}
	command := args[0]
	if !slices.Contains([]string{"add", "activate", "retire", "list"}, command) {
		return errors.New("unknown caller-key command")
	}
	flags := flag.NewFlagSet("caller-key", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	targetsPath := flags.String("targets", "", "regional Vault targets")
	service := flags.String("service", "", "service caller")
	cell := flags.String("region", "", "caller region")
	kid := flags.String("kid", "", "key id")
	replacement := flags.String("replacement-kid", "", "current replacement key id")
	expiry := flags.String("not-after", "", "key expiry")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *targetsPath == "" {
		return errors.New("caller-key requires --targets and no positional arguments")
	}
	parts := kidRE.FindStringSubmatch(*kid)
	var notAfter time.Time
	if command == "add" {
		var err error
		notAfter, err = time.Parse(time.RFC3339, *expiry)
		if len(parts) != 4 || parts[1] != *service || parts[2] != *cell || err != nil || !notAfter.After(time.Now().Add(minimumLifetime)) || *replacement != "" {
			return errors.New("add requires a matching service, region, numbered kid and --not-after more than 30 days away")
		}
	} else if *service != "" || *cell != "" || *expiry != "" || command != "retire" && *replacement != "" || command == "list" && *kid != "" || command != "list" && len(parts) != 4 {
		return errors.New("list takes only targets; activate and retire require a service kid")
	}
	var targets []Target
	if err := readJSON(*targetsPath, &targets); err != nil {
		return err
	}
	regions, err := store.Regions(ctx)
	if err != nil {
		return err
	}
	cells := map[string]bool{}
	for _, cell := range regions {
		if _, ok := catalog.LookupName(cell); !ok || cells[cell] {
			return errors.New("invalid or duplicate deployed region")
		}
		cells[cell] = true
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
		if len(parts) == 4 && t.Cell == parts[2] {
			selected = t
		}
	}
	if command != "list" && selected.Cell == "" {
		return errors.New("caller region is not deployed")
	}
	registries := make([]Registry, len(targets))
	snapshots := make([]Snapshot, len(targets))
	callers := map[string]Caller{}
	retired := map[string]bool{}
	for i, t := range targets {
		current, err := store.Read(ctx, t, registryName(t))
		if err != nil {
			return err
		}
		snapshots[i] = current
		registry := Registry{Version: 1, Callers: []Caller{}}
		if current.Version > 0 {
			if err := json.Unmarshal(current.Value, &registry, json.RejectUnknownMembers(true)); err != nil || registry.Version != 1 || registry.Callers == nil {
				return fmt.Errorf("invalid caller registry %s", registryName(t))
			}
		}
		local := map[string]bool{}
		for _, c := range registry.Callers {
			if err := validateCaller(c); err != nil || local[c.Kid] {
				return fmt.Errorf("invalid caller entry in %s", registryName(t))
			}
			local[c.Kid] = true
			if previous, exists := callers[c.Kid]; exists && !sameJSON(previous, c) && !(command == "retire" && c.Kid == *kid) {
				return errors.New("registries disagree on a caller key")
			}
			callers[c.Kid] = c
		}
		for _, id := range registry.Retired {
			if !kidRE.MatchString(id) || local[id] {
				return fmt.Errorf("invalid retired key in %s", registryName(t))
			}
			retired[id] = true
		}
		slices.SortFunc(registry.Callers, func(a, b Caller) int { return strings.Compare(a.Kid, b.Kid) })
		slices.Sort(registry.Retired)
		registries[i] = registry
	}
	if command == "list" {
		for i, t := range targets {
			if _, err := fmt.Fprintln(out, registryName(t)); err != nil {
				return err
			}
			for _, c := range registries[i].Callers {
				if _, err := fmt.Fprintln(out, registryName(t), c.Kid, "notAfter", c.NotAfter.UTC().Format(time.RFC3339)); err != nil {
					return err
				}
			}
			for _, service := range []string{"ts-auth", "dashboard", "edge"} {
				name := secretName(service, t.Cell)
				state, err := store.Private(ctx, t, name)
				if err != nil {
					return err
				}
				err = printPrivate(out, name, state)
				state.Clear()
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	if command == "add" || command == "activate" {
		for i := 1; i < len(registries); i++ {
			if !sameJSON(registries[0], registries[i]) {
				return errors.New("regional registries differ; converge with retire before add or activate")
			}
		}
		for _, c := range registries[0].Callers {
			if !c.NotAfter.After(time.Now().Add(minimumLifetime)) {
				return fmt.Errorf("key %s expires within 30 days; retire it before add or activate", c.Kid)
			}
		}
	}
	name := secretName(parts[1], parts[2])
	state, err := store.Private(ctx, selected, name)
	if err != nil {
		return err
	}
	defer state.Clear()
	currentKid, err := privateKid(state.Current)
	if err != nil {
		return err
	}
	for _, v := range state.Versions {
		id, err := privateKid(v.Snapshot)
		if err != nil || !strings.HasPrefix(id, parts[1]+"."+parts[2]+".") {
			return errors.New("stored private key has an invalid caller kid")
		}
	}
	if command == "activate" {
		if _, ok := callers[*kid]; !ok || retired[*kid] {
			return errors.New("activation requires the kid listed in every region")
		}
		if currentKid == *kid {
			_, err := fmt.Fprintln(out, name, *kid, "already current")
			return err
		}
		var pending int64
		for _, v := range state.Versions {
			if v.Pending {
				id, _ := privateKid(v.Snapshot)
				if id != *kid || pending != 0 {
					return errors.New("pending private key does not match activation kid")
				}
				pending = v.Version
			}
		}
		if pending == 0 {
			return errors.New("activation requires a matching pending private key")
		}
		if err := store.Activate(ctx, selected, name, state, pending); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, name, *kid, "current")
		return err
	}
	if command == "retire" {
		if _, ok := callers[*kid]; !ok && !retired[*kid] {
			return errors.New("kid is not registered")
		}
		if currentKid == *kid {
			return errors.New("cannot retire the current private key")
		}
		used := false
		for _, v := range state.Versions {
			id, _ := privateKid(v.Snapshot)
			if id == *kid {
				if v.Pending {
					return errors.New("cannot retire a pending private key")
				}
				used = true
			}
		}
		if used || *replacement != "" {
			replacementParts := kidRE.FindStringSubmatch(*replacement)
			if len(replacementParts) != 4 || replacementParts[1] != parts[1] || replacementParts[2] != parts[2] || *replacement != currentKid || *replacement == *kid {
				return errors.New("retiring a stored key requires --replacement-kid naming the current key for that caller and region")
			}
			for _, registry := range registries {
				if !slices.ContainsFunc(registry.Callers, func(c Caller) bool { return c.Kid == *replacement }) {
					return errors.New("replacement key must be listed in every region")
				}
			}
		}
		for _, registry := range registries {
			hasKey, hasOther := false, false
			for _, c := range registry.Callers {
				if c.Kid == *kid {
					hasKey = true
				}
				p := kidRE.FindStringSubmatch(c.Kid)
				if c.Kid != *kid && len(p) == 4 && p[1] == parts[1] && p[2] == parts[2] && !retired[c.Kid] {
					hasOther = true
				}
			}
			if hasKey && !hasOther {
				return errors.New("cannot retire the caller's last listed key for a region")
			}
		}
		retired[*kid] = true
	}
	var private []byte
	if command == "add" {
		sequence, err := keySequence(*kid)
		if err != nil {
			return err
		}
		prefix := parts[1] + "." + parts[2] + "."
		ids := []string{}
		for id := range callers {
			ids = append(ids, id)
		}
		for id := range retired {
			ids = append(ids, id)
		}
		if currentKid != "" {
			ids = append(ids, currentKid)
		}
		for _, v := range state.Versions {
			id, _ := privateKid(v.Snapshot)
			ids = append(ids, id)
			if v.Pending {
				return errors.New("activate the existing pending key before adding another")
			}
		}
		for _, id := range ids {
			if strings.HasPrefix(id, prefix) {
				prior, err := keySequence(id)
				if err != nil || sequence <= prior {
					return fmt.Errorf("new kid sequence must exceed listed, retired and stored key %s", id)
				}
			}
		}
		c, value, err := generateCaller(*kid, parts[1], notAfter)
		if err != nil {
			return err
		}
		private = value
		defer clear(private)
		callers[*kid] = c
	}
	registry := Registry{Version: 1, Callers: []Caller{}}
	for id, c := range callers {
		if !retired[id] {
			registry.Callers = append(registry.Callers, c)
		}
	}
	for id := range retired {
		registry.Retired = append(registry.Retired, id)
	}
	slices.SortFunc(registry.Callers, func(a, b Caller) int { return strings.Compare(a.Kid, b.Kid) })
	slices.Sort(registry.Retired)
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
	if command == "add" {
		stage := "pending"
		if state.Current.Version == 0 {
			stage = "current"
			err = store.Write(ctx, selected, name, state.Current, private)
		} else {
			err = store.Stage(ctx, selected, name, state, private)
		}
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, name, *kid, stage); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(out, *kid)
	return err
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func keySequence(id string) (uint64, error) {
	parts := kidRE.FindStringSubmatch(id)
	if len(parts) != 4 {
		return 0, errors.New("invalid service kid")
	}
	value, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil {
		return 0, errors.New("kid sequence is out of range")
	}
	return value, nil
}

func privateKid(s Snapshot) (string, error) {
	if s.Version == 0 {
		return "", nil
	}
	var key struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(s.Value, &key) != nil || !kidRE.MatchString(key.Kid) {
		return "", errors.New("stored private key has an invalid caller kid")
	}
	return key.Kid, nil
}

func printPrivate(out io.Writer, name string, state PrivateState) error {
	id, err := privateKid(state.Current)
	if err != nil {
		return err
	}
	if id != "" {
		if _, err := fmt.Fprintln(out, name, id, "current"); err != nil {
			return err
		}
	}
	for _, v := range state.Versions {
		if !v.Pending {
			continue
		}
		id, err := privateKid(v.Snapshot)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out, name, id, "pending"); err != nil {
			return err
		}
	}
	return nil
}

func secretName(service, cell string) string {
	service = map[string]string{"ts-auth": "ts-auth", "dashboard": "ts-dashboard", "edge": "orch"}[service]
	return cell + "-1-" + service + "-terrabase-key"
}

func generateCaller(kid, service string, expiry time.Time) (Caller, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Caller{}, nil, errors.New("generate caller key failed")
	}
	pub := JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
	scalar := key.D.FillBytes(make([]byte, 32))
	defer clear(scalar)
	private, err := json.Marshal(struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		D   string `json:"d"`
	}{kid, pub.Kty, pub.Crv, pub.X, pub.Y, base64.RawURLEncoding.EncodeToString(scalar)})
	if err != nil {
		return Caller{}, nil, errors.New("encode caller key failed")
	}
	grants := map[string][]string{
		"ts-auth":   {"data:00000000000000000000000002", "closure"},
		"dashboard": {"data:00000000000000000000000005", "plans", "usage.read", "catalog.read"},
		"edge":      {"rollout"},
	}
	return Caller{kid, service, "service", pub, grants[service], expiry.UTC()}, private, nil
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
