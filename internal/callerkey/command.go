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
const settleWindow = 10 * time.Minute

const usage = `Usage: ts-orch caller-key <add|activate|retire|recover|list> --targets FILE
  add --service ts-auth|dashboard|edge --region CELL --kid SERVICE.CELL.N --not-after RFC3339
  activate --kid SERVICE.CELL.N
  retire --kid SERVICE.CELL.N|op.NAME.N|agent.NAME.N [--replacement-kid SERVICE.CELL.N]
  recover
  list

Targets is a JSON array of {cell, vault, key, compartment}, covering the authenticated footprint.
Add publishes every public registry before creating a first CURRENT key or a rotation PENDING key.
Roll TerraBase before shipping a first spec reference or activating a rotation.
Interrupted operations require recover before another change. Expiring entries produce warnings.
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
	Metadata(context.Context, Target, string, int64, string) (PrivateMetadata, error)
	Private(context.Context, Target, string) (PrivateState, error)
	Stage(context.Context, Target, string, PrivateState, []byte, string) error
	Discard(context.Context, Target, string, PrivateState, int64) error
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
	Version   int               `json:"version"`
	Callers   []Caller          `json:"callers"`
	HighWater map[string]uint64 `json:"highWater,omitempty"`
	Intent    *Intent           `json:"intent,omitempty"`
}

type Intent struct {
	Operation      string    `json:"operation"`
	Kid            string    `json:"kid"`
	Caller         string    `json:"caller"`
	Cell           string    `json:"cell"`
	ID             string    `json:"id"`
	Started        time.Time `json:"started"`
	PrivateVersion int64     `json:"privateVersion,omitempty"`
	VersionName    string    `json:"versionName,omitempty"`
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
	if !slices.Contains([]string{"add", "activate", "retire", "recover", "list"}, command) {
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
	if command == "retire" && len(parts) == 0 {
		parts = operatorRE.FindStringSubmatch(*kid)
	}
	noKid := command == "list" || command == "recover"
	var notAfter time.Time
	if command == "add" {
		var err error
		notAfter, err = time.Parse(time.RFC3339, *expiry)
		if len(parts) != 4 || parts[1] != *service || parts[2] != *cell || err != nil || !notAfter.After(time.Now().Add(minimumLifetime)) || *replacement != "" {
			return errors.New("add requires a matching service, region, numbered kid and --not-after more than 30 days away")
		}
	} else if *service != "" || *cell != "" || *expiry != "" || command != "retire" && *replacement != "" || noKid && *kid != "" || !noKid && len(parts) != 4 {
		return errors.New("list and recover take only targets; activate requires a service kid; retire requires a caller kid")
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
	if !noKid && kidRE.MatchString(*kid) && selected.Cell == "" {
		return errors.New("caller region is not deployed")
	}
	slices.SortFunc(targets, func(a, b Target) int { return strings.Compare(a.Cell, b.Cell) })
	registries := make([]Registry, len(targets))
	snapshots := make([]Snapshot, len(targets))
	callers := map[string]Caller{}
	highWater := map[string]uint64{}
	var intent *Intent
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
			if previous, exists := callers[c.Kid]; exists && !sameJSON(previous, c) {
				return errors.New("registries disagree on a caller key")
			}
			callers[c.Kid] = c
		}

		for prefix, sequence := range registry.HighWater {
			if sequence == 0 || !kidRE.MatchString(prefix+".1") && !operatorRE.MatchString(prefix+".1") {
				return errors.New("invalid caller sequence high-water mark")
			}
			highWater[prefix] = max(highWater[prefix], sequence)
		}
		if registry.Intent != nil {
			if intent != nil && !sameJSON(intent, registry.Intent) {
				return errors.New("regional operation records disagree")
			}
			intent = registry.Intent
		}
		slices.SortFunc(registry.Callers, func(a, b Caller) int { return strings.Compare(a.Kid, b.Kid) })
		registries[i] = registry
	}
	if command == "list" {
		for i, t := range targets {
			if _, err := fmt.Fprintln(out, registryName(t)); err != nil {
				return err
			}
			if registries[i].Intent != nil {
				fmt.Fprintln(out, "operation in progress", registries[i].Intent.Operation, registries[i].Intent.Kid, registries[i].Intent.ID, "run caller-key recover")
			}
			for _, c := range registries[i].Callers {
				if _, err := fmt.Fprintln(out, registryName(t), c.Kid, "notAfter", c.NotAfter.UTC().Format(time.RFC3339), expiryStatus(c)); err != nil {
					return err
				}
			}
			for _, service := range []string{"ts-auth", "dashboard", "edge"} {
				name := secretName(service, t.Cell)
				state, _, err := privateHalf(ctx, store, t, name, nil)
				if err != nil {
					return err
				}
				err = printPrivate(out, name, state, callers)
				state.Clear()
				if err != nil {
					return err
				}
			}
		}
		return nil
	}

	if command == "recover" {
		if intent == nil {
			_, err := fmt.Fprintln(out, "no operation in progress")
			return err
		}
		return recoverOperation(ctx, out, store, targets, snapshots, registries, callers, highWater, intent)
	}
	if intent != nil {
		return fmt.Errorf("operation in progress: %s %s %s; run caller-key recover", intent.Operation, intent.Kid, intent.ID)
	}
	for i := 1; i < len(registries); i++ {
		if !sameJSON(registries[0], registries[i]) {
			return errors.New("regional registries differ without an operation record")
		}
	}
	if command == "add" || command == "activate" {
		for _, c := range callers {
			if status := expiryStatus(c); status != "valid" {
				fmt.Fprintln(out, "warning", c.Kid, status)
			}
		}
	}
	name := secretName(parts[1], parts[2])
	state := PrivateState{}
	if kidRE.MatchString(*kid) {
		state, _, err = privateHalf(ctx, store, selected, name, nil)
		if err != nil {
			return err
		}
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
		if _, ok := callers[*kid]; !ok {
			return errors.New("activation requires the kid listed in every region")
		}
		if currentKid != *kid && !callers[*kid].NotAfter.After(time.Now()) {
			return errors.New("expired pending key can only be cancelled")
		}
		if currentKid == *kid {
			_, err := fmt.Fprintln(out, name, *kid, "already current")
			return err
		}
		var pending int64
		for _, v := range state.Versions {
			if v.Pending {
				id, _ := privateKid(v.Snapshot)
				if id == currentKid {
					continue
				}
				if id != *kid || pending != 0 {
					return errors.New("pending private key does not match activation kid")
				}
				pending = v.Version
			}
		}
		if pending == 0 {
			return errors.New("activation requires a matching pending private key")
		}

		intent, err := newIntent(command, *kid, callers[*kid].Caller, parts[2])
		if err != nil {
			return err
		}
		intent.PrivateVersion = pending
		if err := writeIntent(ctx, store, targets, snapshots, registries, intent); err != nil {
			return err
		}
		if err := store.Activate(ctx, selected, name, state, pending); err != nil {
			return operationError(intent, err)
		}
		if err := clearIntent(ctx, store, targets, snapshots, registries); err != nil {
			return operationError(intent, err)
		}
		_, err = fmt.Fprintln(out, name, *kid, "current")
		return err
	}
	var privateVersion int64
	if command == "retire" {
		if _, ok := callers[*kid]; !ok {
			return errors.New("kid is not registered")
		}
		if currentKid == *kid {
			return errors.New("cannot retire the current private key")
		}
		used := false
		for _, v := range state.Versions {
			id, _ := privateKid(v.Snapshot)
			if id == *kid {
				privateVersion = v.Version
				if v.Pending {
					command = "cancel"
				} else {
					used = true
				}
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

		if sequence <= highWater[strings.TrimSuffix(*kid, "."+parts[3])] {
			return errors.New("new kid sequence must exceed the high-water mark")
		}
		if currentKid != "" {
			ids = append(ids, currentKid)
		}
		for _, v := range state.Versions {
			id, _ := privateKid(v.Snapshot)
			ids = append(ids, id)
			if v.Pending && id != currentKid {
				return errors.New("activate or cancel the existing pending key before adding another")
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

	caller := callers[*kid].Caller
	intent, err = newIntent(command, *kid, caller, selected.Cell)
	if err != nil {
		return err
	}
	intent.PrivateVersion = privateVersion
	if privateVersion == 0 && (command != "add" || state.Current.Version != 0) {
		intent.VersionName = *kid
	}
	if err := writeIntent(ctx, store, targets, snapshots, registries, intent); err != nil {
		return err
	}
	if command == "cancel" {
		if err := cancelPending(ctx, store, selected, name, state, intent); err != nil {
			return operationError(intent, err)
		}
	}
	advance(highWater, *kid)
	if command == "retire" || command == "cancel" {
		delete(callers, *kid)
	}
	registry := mergedRegistry(callers, highWater, intent)
	for i := range targets {
		if err := writeRegistry(ctx, store, targets[i], &snapshots[i], registry); err != nil {
			return operationError(intent, err)
		}
		registries[i] = registry
	}
	if command == "add" {
		stage := "pending"
		if state.Current.Version == 0 {
			stage = "current"
			err = store.Write(ctx, selected, name, state.Current, private)
		} else {
			err = store.Stage(ctx, selected, name, state, private, *kid)
		}
		if err != nil {
			return operationError(intent, err)
		}
		fmt.Fprintln(out, name, *kid, stage)
	}
	if err := clearIntent(ctx, store, targets, snapshots, registries); err != nil {
		return operationError(intent, err)
	}
	_, err = fmt.Fprintln(out, *kid)
	return err
}

func expiryStatus(c Caller) string {
	if !c.NotAfter.After(time.Now()) {
		return "expired"
	}
	if !c.NotAfter.After(time.Now().Add(minimumLifetime)) {
		return "expires within 30 days"
	}
	return "valid"
}

func advance(highWater map[string]uint64, kid string) {
	index := strings.LastIndexByte(kid, '.')
	sequence, _ := strconv.ParseUint(kid[index+1:], 10, 64)
	highWater[kid[:index]] = max(highWater[kid[:index]], sequence)
}

func mergedRegistry(callers map[string]Caller, highWater map[string]uint64, intent *Intent) Registry {
	r := Registry{Version: 1, Callers: []Caller{}, HighWater: highWater, Intent: intent}
	for _, c := range callers {
		r.Callers = append(r.Callers, c)
	}
	slices.SortFunc(r.Callers, func(a, b Caller) int { return strings.Compare(a.Kid, b.Kid) })
	return r
}

func newIntent(operation, kid, caller, cell string) (*Intent, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return &Intent{Operation: operation, Kid: kid, Caller: caller, Cell: cell, ID: fmt.Sprintf("%x", id), Started: time.Now().UTC()}, nil
}

func operationError(intent *Intent, err error) error {
	return fmt.Errorf("%s %s (%s) interrupted: %w; run caller-key recover, then use the next sequence for a failed add", intent.Operation, intent.Kid, intent.ID, err)
}

func writeRegistry(ctx context.Context, store Store, target Target, snapshot *Snapshot, registry Registry) error {
	value, err := json.Marshal(registry, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := store.Write(ctx, target, registryName(target), *snapshot, value); err != nil {
		return err
	}
	after, err := store.Read(ctx, target, registryName(target))
	if err != nil {
		return err
	}
	if string(after.Value) != string(value) {
		return errors.New("registry changed during publication")
	}
	*snapshot = after
	return nil
}

func writeIntent(ctx context.Context, store Store, targets []Target, snapshots []Snapshot, registries []Registry, intent *Intent) error {
	for i := range targets {
		registries[i].Intent = intent
		if err := writeRegistry(ctx, store, targets[i], &snapshots[i], registries[i]); err != nil {
			return operationError(intent, err)
		}
	}
	return nil
}

func clearIntent(ctx context.Context, store Store, targets []Target, snapshots []Snapshot, registries []Registry) error {
	for i := range targets {
		registries[i].Intent = nil
		if err := writeRegistry(ctx, store, targets[i], &snapshots[i], registries[i]); err != nil {
			return err
		}
	}
	return nil
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a, json.Deterministic(true))
	y, _ := json.Marshal(b, json.Deterministic(true))
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

func printPrivate(out io.Writer, name string, state PrivateState, callers map[string]Caller) error {
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
		current, _ := privateKid(state.Current)
		if id == current {
			continue
		}
		c, ok := callers[id]
		if !ok {
			return errors.New("pending private key has no public entry")
		}
		status := expiryStatus(c)
		if status == "expired" {
			status = "expired; can only be cancelled"
		}
		if _, err := fmt.Fprintln(out, name, id, "pending notAfter", c.NotAfter.UTC().Format(time.RFC3339), status); err != nil {
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
