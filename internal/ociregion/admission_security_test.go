package ociregion

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBilledGiBRequiresLexicalInteger(t *testing.T) {
	for _, wire := range []string{`2.0`, `2e0`, `true`, `"2"`, `-1`, `0`} {
		t.Run(wire, func(t *testing.T) {
			value, err := decodeJSON([]byte(wire))
			if err != nil {
				t.Fatal(err)
			}
			_, err = capture(func() any { return positiveGiB(value, "image size") })
			if err == nil || !strings.Contains(err.Error(), "positive integer billed GiB") {
				t.Fatalf("admitted %s: %v", wire, err)
			}
		})
	}
	for _, wire := range []string{`1`, `2`, `9007199254740993`} {
		value, err := decodeJSON([]byte(wire))
		if err != nil {
			t.Fatal(err)
		}
		_, err = capture(func() any { return positiveGiB(value, "image size") })
		if err != nil {
			t.Fatalf("integer %s rejected: %v", wire, err)
		}
	}
}
func TestJSONRejectsNestedDuplicateAndTrailingValue(t *testing.T) {
	for _, wire := range []string{`{"plan":{"id":"first","id":"other"}}`, `{"valid":true}{"extra":true}`} {
		if _, err := decodeJSON([]byte(wire)); err == nil {
			t.Fatalf("accepted ambiguous JSON %s", wire)
		}
	}
}
func TestPlanPrivatePrefixChecksWholeNetwork(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/7", "172.16.0.0/11", "192.168.0.0/15"} {
		if privatePrefix(netip.MustParsePrefix(cidr)) {
			t.Fatalf("accepted public addresses within %s", cidr)
		}
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "192.0.2.0/24"} {
		if !privatePrefix(netip.MustParsePrefix(cidr)) {
			t.Fatalf("rejected contract private network %s", cidr)
		}
	}
}
func TestReadJSONRejectsSymlinkAndNonregularSource(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "plan.json")
	if err := os.WriteFile(path, []byte(`{"schema":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{link, directory} {
		if _, err := ReadJSON(source, 1024, "plan"); err == nil {
			t.Fatalf("read untrusted source %s", source)
		}
	}
}
func TestOCIListDoesNotTurnMalformedStorageResponseIntoEmptyInventory(t *testing.T) {
	for _, stdout := range []string{"", `{"prefixes":["hidden/"]}`, `{"data":[],"data":[{"size":100}]}`} {
		engine := &Engine{Dependency: func(name string, args []any, kwargs Object) (any, error) {
			if name != "subprocess.run" {
				return nil, errors.New("unexpected dependency")
			}
			return Object{"returncode": 0, "stdout": stdout}, nil
		}}
		_, err := engine.Invoke("oci", []any{"os", "object", "list", "--all"}, Object{})
		if err == nil {
			t.Fatalf("accepted uncounted object storage %q", stdout)
		}
	}
}
func TestMoneyRoundsTiesToEven(t *testing.T) {
	for amount, want := range map[string]string{"0.005": "0.00", "0.015": "0.02", "1.23445": "1.2344", "1.23455": "1.2346"} {
		places := 2
		if len(strings.Split(amount, ".")[1]) > 3 {
			places = 4
		}
		if got := fixed(amount, places); got != want {
			t.Fatalf("round(%s)=%s want %s", amount, got, want)
		}
	}
}
