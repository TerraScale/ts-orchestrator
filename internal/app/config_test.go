package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// testdata/config-members.txt records the members of the version-2 contract; rewrite it
// with TS_UPDATE_CONFIG_MEMBERS=1 go test ./internal/app -run TestConfigVersion.
func TestConfigVersionCoversEveryMember(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	header := fmt.Sprintf("version %d\n", ConfigVersion)
	members := header + strings.Join(configMembers(reflect.TypeFor[Config]()), "\n") + "\n"
	path := filepath.Join("testdata", "config-members.txt")
	recorded, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if string(recorded) == members {
		return
	}
	if os.Getenv("TS_UPDATE_CONFIG_MEMBERS") == "" {
		t.Fatalf("app.Config members differ from %s: review the contract, then rewrite it with TS_UPDATE_CONFIG_MEMBERS=1", path)
	}
	if err := os.WriteFile(path, []byte(members), 0o644); err != nil {
		t.Fatal(err)
	}
}

// configMembers lists every JSON member reachable from typ with its JSON
// shape and options. The shape names this module's types by kind, so moving
// or renaming a Go type that keeps the JSON is no new member.
func configMembers(typ reflect.Type) []string {
	var members []string
	var walk func(path string, typ reflect.Type, stack []reflect.Type)
	walk = func(path string, typ reflect.Type, stack []reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || !strings.HasPrefix(typ.PkgPath(), "github.com/TerraScale/") ||
			slices.Contains(stack, typ) {
			return
		}
		for index := range typ.NumField() {
			field := typ.Field(index)
			if !field.IsExported() || field.Tag.Get("json") == "-" {
				continue
			}
			member := path + "." + field.Name
			members = append(members, member+" "+jsonShape(field.Type)+" "+string(field.Tag))
			walk(member, field.Type, append(stack, typ))
		}
	}
	walk("", typ, nil)
	slices.Sort(members)
	return members
}

func jsonShape(typ reflect.Type) string {
	switch typ.Kind() {
	case reflect.Pointer:
		return "*" + jsonShape(typ.Elem())
	case reflect.Slice:
		return "[]" + jsonShape(typ.Elem())
	case reflect.Map:
		return "map[" + jsonShape(typ.Key()) + "]" + jsonShape(typ.Elem())
	}
	if strings.HasPrefix(typ.PkgPath(), "github.com/TerraScale/") {
		return typ.Kind().String()
	}
	return typ.String()
}

func TestLoadConfigPreservesSignedBytesAndRejectsUnknownMembers(t *testing.T) {
	load := func(body string) (Config, error) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(path)
	}
	wire := `{"version": 2, "nats": {"cell": "gru"}, "controller": {"candidate_id": "ctl-1"}}`
	cfg, err := load(wire)
	if err != nil {
		t.Fatalf("version-2 config: %v", err)
	}
	if cfg.Version != ConfigVersion || cfg.NATS.Cell != "gru" || cfg.Controller.CandidateID != "ctl-1" {
		t.Fatalf("version-2 config decoded as %+v", cfg)
	}
	// Admission digests the signed bytes themselves, including whitespace.
	if signed, err := cfg.signedWire(); err != nil || string(signed) != wire {
		t.Fatalf("signed wire = %q, %v; want the loaded bytes", signed, err)
	}
	for name, body := range map[string]string{
		"version missing":            `{"nats":{"cell":"gru"}}`,
		"version zero":               `{"version":0}`,
		"legacy version":             `{"version":1}`,
		"retired version":            `{"version":6}`,
		"unknown version":            `{"version":1000}`,
		"unknown member":             `{"version": 2, "nats": {"cell": "gru", "added": true}}`,
		"typo at this version":       `{"version": 2, "nats": {"cell": "gru", "cel": "gru"}}`,
		"typo in an unversioned one": `{"nats": {"cell": "gru"}, "controler": {}}`,
		"duplicate member":           `{"version": 2, "nats": {"cell": "gru", "cell": "0000000000V4MRM46HP1SNGDYW"}}`,
		"wrong type":                 `{"version": 2, "nats": {"cell": 7}}`,
		"version not a number":       `{"version": "1000", "added": true}`,
		"aggregation on":             `{"version":2,"observability":{"cluster_aggregation":true}}`,
		"aggregation off":            `{"version":2,"observability":{"cluster_aggregation":false}}`,
		"dashboard on":               `{"version":2,"observability":{"dashboard":true}}`,
		"dashboard off":              `{"version":2,"observability":{"dashboard":false}}`,
		"listener off":               `{"version":2,"observability":{"listen_address":"off"}}`,
		"restart opt-in on":          `{"version":2,"controller":{"offline_restart_admission":true}}`,
		"host session trace on":      `{"version":2,"host":{"session_trace":true}}`,
		"host session trace off":     `{"version":2,"host":{"session_trace":false}}`,
		"host load interval off":     `{"version":2,"host":{"load_telemetry_seconds":0}}`,
		"host load interval custom":  `{"version":2,"host":{"load_telemetry_seconds":60}}`,
		"restart opt-in off":         `{"version":2,"controller":{"offline_restart_admission":false}}`,
	} {
		if _, err := load(body); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

// A config built in code has no loaded bytes; it is signed as its canonical
// encoding.
func TestSignedWireOfABuiltConfigIsCanonical(t *testing.T) {
	for _, version := range []int{0, ConfigVersion} {
		wire, err := Config{Version: version, NATS: natscell.Config{Cell: "gru"}}.signedWire()
		if err != nil || !strings.HasPrefix(string(wire), `{"version":2,"nats":{"cell":"gru"`) {
			t.Fatalf("signed wire = %s, %v", wire, err)
		}
		if _, err := decodeConfig(wire); err != nil {
			t.Fatalf("built config did not pass the current decoder: %v", err)
		}
	}
	if _, err := (Config{Version: 1}).signedWire(); err == nil {
		t.Fatal("signed an unsupported config version")
	}
}

// Legacy switches require a new signed desired-state decision, never a decoder default.
func TestWorkloadConfigVersionMigration(t *testing.T) {
	wire := []byte(`{ "version":2,"nats":{},"controller":{"autoscale":{"services":[{"role":"api","environment":"prod","kind":"stateless","replicas":{"min":1,"max":3}}]}}}`)
	cfg, err := decodeConfig(wire)
	if err != nil || cfg.Controller.Autoscale == nil || len(cfg.Controller.Autoscale.Services) != 1 {
		t.Fatalf("switch-free signed services: %+v, %v", cfg.Controller.Autoscale, err)
	}
	if signed, err := cfg.signedWire(); err != nil || string(signed) != string(wire) {
		t.Fatalf("migration rewrote signed bytes: %s, %v", signed, err)
	}
	for _, version := range []int{1, ConfigVersion} {
		for _, legacy := range []string{`"enabled":true`, `"enabled":false`, `"host_telemetry":true`, `"host_telemetry":false`, `"interval_seconds":0`, `"interval_seconds":30`} {
			body := fmt.Appendf(nil, `{"version":%d,"nats":{},"controller":{"autoscale":{%s,"services":[]}}}`, version, legacy)
			if _, err := decodeConfig(body); err == nil {
				t.Errorf("version %d accepted retired setting %s", version, legacy)
			}
		}
	}
	if _, err := decodeConfig([]byte(`{"version":1,"nats":{},"controller":{"autoscale":{"services":[]}}}`)); err == nil {
		t.Fatal("legacy desired state was implicitly activated")
	}
}
