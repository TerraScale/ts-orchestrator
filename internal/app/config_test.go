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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// A new config member needs a new ConfigVersion, or an older binary would
// refuse a config that sets it as a typo. testdata/config-members.txt records
// the members of the current version; after raising ConfigVersion, rewrite it
// with TS_UPDATE_CONFIG_MEMBERS=1 go test ./internal/app -run TestConfigVersion.
func TestConfigVersionCoversEveryMember(t *testing.T) {
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
	if strings.HasPrefix(string(recorded), header) {
		t.Fatalf("app.Config members differ from %s: raise ConfigVersion to %d, then rewrite the file "+
			"with TS_UPDATE_CONFIG_MEMBERS=1", path, ConfigVersion+1)
	}
	if os.Getenv("TS_UPDATE_CONFIG_MEMBERS") == "" {
		t.Fatalf("%s records another config version: rewrite it with TS_UPDATE_CONFIG_MEMBERS=1", path)
	}
	if err := os.WriteFile(path, []byte(members), 0o644); err != nil {
		t.Fatal(err)
	}
}

// configMembers lists every JSON member reachable from typ with its Go type
// and JSON options.
func configMembers(typ reflect.Type) []string {
	var members []string
	var walk func(path string, typ reflect.Type, stack []reflect.Type)
	walk = func(path string, typ reflect.Type, stack []reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || !strings.HasPrefix(typ.PkgPath(), "git.terrascale.tech/") ||
			slices.Contains(stack, typ) {
			return
		}
		for index := range typ.NumField() {
			field := typ.Field(index)
			if !field.IsExported() || field.Tag.Get("json") == "-" {
				continue
			}
			member := path + "." + field.Name
			members = append(members, member+" "+field.Type.String()+" "+string(field.Tag))
			walk(member, field.Type, append(stack, typ))
		}
	}
	walk("", typ, nil)
	slices.Sort(members)
	return members
}

func TestLoadConfigSkipsOnlyANewerBinarysMembers(t *testing.T) {
	load := func(body string) (Config, error) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(path)
	}
	newer := `{"version": 1000, "nats": {"cell": "gru", "added": {"by": "a newer binary"}},
		"controller": {"candidate_id": "ctl-1"}, "added": true}`
	cfg, err := load(newer)
	if err != nil {
		t.Fatalf("config of a newer binary: %v", err)
	}
	if cfg.Version != 1000 || cfg.NATS.Cell != "gru" || cfg.Controller.CandidateID != "ctl-1" {
		t.Fatalf("config of a newer binary decoded as %+v", cfg)
	}
	// Admission digests the signed bytes themselves, whitespace and the
	// members this binary skipped included.
	if wire, err := cfg.signedWire(); err != nil || string(wire) != newer {
		t.Fatalf("signed wire = %q, %v; want the loaded bytes", wire, err)
	}
	for name, body := range map[string]string{
		"typo at this version":       `{"version": 1, "nats": {"cell": "gru", "cel": "gru"}}`,
		"typo in an unversioned one": `{"nats": {"cell": "gru"}, "controler": {}}`,
		"duplicate member":           `{"version": 1000, "nats": {"cell": "gru", "cell": "other"}}`,
		"wrong type":                 `{"version": 1000, "nats": {"cell": 7}}`,
		"version not a number":       `{"version": "1000", "added": true}`,
	} {
		if _, err := load(body); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
}

// A config built in code has no loaded bytes; it is signed as its canonical
// encoding.
func TestSignedWireOfABuiltConfigIsCanonical(t *testing.T) {
	wire, err := Config{NATS: natscell.Config{Cell: "gru"}}.signedWire()
	if err != nil || string(wire) == "" || !strings.HasPrefix(string(wire), `{"nats":{"cell":"gru"`) {
		t.Fatalf("signed wire = %s, %v", wire, err)
	}
}
