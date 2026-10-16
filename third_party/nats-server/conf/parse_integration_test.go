// Copyright 2013-2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package conf_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/conf"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func configDiskFixture(t *testing.T, input string, includes map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, contents := range includes {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "nats.conf")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func configRejectedAtAdmission(t *testing.T, path string, fragments ...string) {
	t.Helper()
	_, parseErr := conf.ParseFileWithChecks(path)
	opts, admissionErr := server.ProcessConfigFile(path)
	if opts != nil {
		t.Fatal("Invalid disk configuration returned runnable server options")
	}
	for _, result := range []struct {
		boundary string
		err      error
	}{
		{"public file parser", parseErr},
		{"server configuration admission", admissionErr},
	} {
		if result.err == nil {
			t.Fatalf("%s accepted invalid disk configuration", result.boundary)
		}
		for _, fragment := range fragments {
			if fragment != "" && !strings.Contains(result.err.Error(), fragment) {
				t.Errorf("%s error %q does not contain %q", result.boundary, result.err, fragment)
			}
		}
	}
}

func TestConfigFileMalformedAdmission(t *testing.T) {
	for _, tc := range []struct {
		name, input, diagnostic string
	}{
		{"missing variable", "foo=$index", "variable reference"},
		{"literal percent variable", "foo = $%s", ""},
		{"malformed Unicode", `A@@Føøøø?˛ø:{øøøø˙˙`, "Unexpected EOF"},
		{"unterminated include", `include "9/�`, "Unexpected EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("index", "")
			if err := os.Unsetenv("index"); err != nil {
				t.Fatal(err)
			}
			t.Setenv("__UNIQ22__", "3xyz")
			path := configDiskFixture(t, tc.input, nil)
			configRejectedAtAdmission(t, path, tc.diagnostic)
			if tc.diagnostic == "variable reference" {
				_, err := server.ProcessConfigFile(path)
				if err == nil || !strings.HasPrefix(err.Error(), "variable reference") {
					t.Fatalf("Expected variable-reference diagnostic prefix, got %v", err)
				}
			}
		})
	}
}

func TestConfigFileInvalidValuesAdmission(t *testing.T) {
	for _, test := range []struct {
		name string
		conf string
		err  string
	}{
		{
			"invalid key without values",
			`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
			"config is invalid (:1:41)",
		},
		{
			"invalid untrimmed key without values",
			`              aaaaaaaaaaaaaaaaaaaaaaaaaaa`,
			"config is invalid (:1:41)",
		},
		{
			"invalid untrimmed key without values",
			`     aaaaaaaaaaaaaaaaaaaaaaaaaaa         `,
			"config is invalid (:1:41)",
		},
		{
			"invalid keys after comments",
			"\n          \t\t# with comments and no spaces to create key values\n         \t\t# is also an invalid config.\n         \t\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n                        ",
			"config is invalid (:5:25)",
		},
		{
			"comma separated without values are invalid",
			`
                        a,a,a,a,a,a,a,a,a,a,a
                        `,
			"config is invalid (:3:25)",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := configDiskFixture(t, test.conf, nil)
			want := strings.ReplaceAll(test.err, "(:", "("+path+":")
			configRejectedAtAdmission(t, path, want)
		})
	}
}

func TestConfigFileIncludeAdmissionDiagnostics(t *testing.T) {
	for _, test := range []struct {
		input    string
		includes map[string]string
		err      string
		linepos  string
	}{
		{
			`# includes
			accounts {
                          foo { include 'foo.conf'}
                          bar { users = [{user = "bar"}] }
                          quux { include 'quux.conf'}
                        }
                        `,
			map[string]string{
				"foo.conf":  ``,
				"quux.conf": `?????????????`,
			},
			"error parsing include file 'quux.conf', config is invalid",
			"quux.conf:1:1",
		},
		{
			`# includes
			accounts {
                          foo { include 'foo.conf'}
                          bar { include 'bar.conf'}
                          quux { include 'quux.conf'}
                        }
                        `,
			map[string]string{
				"foo.conf": ``, // Empty configs are ok
				"bar.conf": `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`,
				"quux.conf": `
                                   # just some comments,
                                   # and no key values also ok.
                                `,
			},
			"error parsing include file 'bar.conf', config is invalid",
			"bar.conf:1:34",
		},
	} {
		t.Run(fmt.Sprint(test.linepos), func(t *testing.T) {
			path := configDiskFixture(t, test.input, test.includes)
			configRejectedAtAdmission(t, path, test.err, test.linepos)
		})
	}
}

func configRuntimeServer(t *testing.T, path string) *server.Server {
	t.Helper()
	opts, err := server.ProcessConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Host != "127.0.0.1" || opts.Port != -1 {
		t.Fatal("Runtime configuration must specify an ephemeral loopback client listener")
	}
	opts.NoLog, opts.NoSigs = true, true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("Configured server did not become ready")
	}
	return s
}

func configAuthDelivery(t *testing.T, s *server.Server, user, password string) {
	t.Helper()
	nc, err := nats.Connect(s.ClientURL(), nats.UserInfo(user, password), nats.NoReconnect(), nats.Timeout(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	sub, err := nc.SubscribeSync("config.delivery")
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish("config.delivery", []byte("authorized")); err != nil {
		t.Fatal(err)
	}
	if err := nc.FlushTimeout(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Data) != "authorized" {
		t.Fatalf("Incorrect configured-user delivery: %q", msg.Data)
	}
}

func configAuthRejected(t *testing.T, s *server.Server, user, password string) {
	t.Helper()
	nc, err := nats.Connect(s.ClientURL(), nats.UserInfo(user, password), nats.NoReconnect(), nats.Timeout(2*time.Second))
	if nc != nil {
		nc.Close()
	}
	if !errors.Is(err, nats.ErrAuthorization) {
		t.Fatalf("Configured authentication should refuse %q: %v", user, err)
	}
}

const (
	configAliceHash = "$2a$10$UHR6GhotWhpLsKtVP0/i6.Nh9.fuY73cWjLoJjb2sKT8KISBcUW5q"
	configBobHash   = "$2a$11$dZM98SpGeI7dCFFGSpt.JObQcix8YHml4TBUZoge9R1uxnMIln5ly"
)

func TestConfigFileIncludedUsersRuntime(t *testing.T) {
	files := make(map[string]string)
	for _, name := range []string{"simple.conf", "includes/users.conf", "includes/passwords.conf"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(data)
	}
	input := strings.Replace(files["simple.conf"], "listen: 127.0.0.1:4222", "listen: 127.0.0.1:-1", 1)
	delete(files, "simple.conf")
	path := configDiskFixture(t, input, files)
	got, err := conf.ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"listen": "127.0.0.1:-1",
		"authorization": map[string]any{
			"ALICE_PASS": configAliceHash, "BOB_PASS": configBobHash,
			"users": []any{
				map[string]any{"user": "alice", "password": configAliceHash},
				map[string]any{"user": "bob", "password": configBobHash},
			},
			"timeout": float64(0.5),
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Included config values changed: got %#v, want %#v", got, want)
	}
	s := configRuntimeServer(t, path)
	configAuthDelivery(t, s, "alice", "foo")
	configAuthDelivery(t, s, "bob", "bar")
	configAuthRejected(t, s, "alice", "bar")
	configAuthRejected(t, s, "bob", "foo")
	configAuthDelivery(t, s, "alice", "foo")
}

func TestConfigFileIncludedTokenLocationsRuntime(t *testing.T) {
	passwords, err := os.ReadFile("includes/passwords.conf")
	if err != nil {
		t.Fatal(err)
	}
	input := `
authorization {

  include "./includes/passwords.conf"

  CAROL_PASS: foo

  users = [
   {user: alice, password: $ALICE_PASS}
   {user: bob,   password: $BOB_PASS}
   {user: carol, password: $CAROL_PASS}
  ]
}
` + "\nlisten: 127.0.0.1:-1\n"
	path := configDiskFixture(t, input, map[string]string{"includes/passwords.conf": string(passwords)})
	checked, err := conf.ParseFileWithChecks(path)
	if err != nil {
		t.Fatal(err)
	}
	type location interface {
		Value() any
		Line() int
		Position() int
		SourceFile() string
	}
	auth, ok := checked["authorization"].(location)
	if !ok {
		t.Fatal("Public checked parser did not expose authorization token location")
	}
	values, ok := auth.Value().(map[string]any)
	if !ok {
		t.Fatal("Authorization token did not contain a configuration map")
	}
	for _, expected := range []struct {
		key, value, file string
		line, column     int
	}{
		{"ALICE_PASS", configAliceHash, filepath.Join(filepath.Dir(path), "includes/passwords.conf"), 2, 1},
		{"BOB_PASS", configBobHash, filepath.Join(filepath.Dir(path), "includes/passwords.conf"), 3, 1},
		{"CAROL_PASS", "foo", path, 6, 3},
	} {
		token, ok := values[expected.key].(location)
		if !ok {
			t.Fatalf("Missing public location token for %s", expected.key)
		}
		if token.Value() != expected.value || token.Line() != expected.line || token.Position() != expected.column || token.SourceFile() != expected.file {
			t.Errorf("%s value/location: %v at %s:%d:%d; want %q at %s:%d:%d", expected.key,
				token.Value(), token.SourceFile(), token.Line(), token.Position(), expected.value, expected.file, expected.line, expected.column)
		}
	}
	s := configRuntimeServer(t, path)
	configAuthDelivery(t, s, "alice", "foo")
	configAuthDelivery(t, s, "bob", "bar")
	configAuthDelivery(t, s, "carol", "foo")
	configAuthRejected(t, s, "carol", "bar")
	configAuthDelivery(t, s, "bob", "bar")
}

func TestConfigFileUsedKeyMonitorRuntime(t *testing.T) {
	path := configDiskFixture(t, `
		host: 127.0.0.1
		port = -1
		monitor_port = $port
	`, nil)
	values, digest, err := conf.ParseFileWithChecksDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := values["port"]; !ok {
		t.Fatal("Config key used as a variable disappeared from the public digest result")
	}
	opts, err := server.ProcessConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Port != -1 || opts.HTTPPort != -1 || opts.ConfigDigest() != digest {
		t.Fatalf("Production configuration lost listener alias/digest: client %d, monitor %d, digest %q; want %q", opts.Port, opts.HTTPPort, opts.ConfigDigest(), digest)
	}
	s := configRuntimeServer(t, path)
	configAuthDelivery(t, s, "", "")
	addr := s.MonitorAddr()
	if addr == nil {
		t.Fatal("Config key used as a variable did not start a monitoring listener")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr.String()+"/varz", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), s.ID()) {
		t.Fatalf("Configured monitor did not serve this running server: status %d, body %s", res.StatusCode, body)
	}
}

// These fixtures use production server fields; generic-map originals remain separate gaps.
func TestConfigFileScalarOptionsRuntime(t *testing.T) {
	path := configDiskFixture(t, `
		listen: 127.0.0.1:-1
		server_name='1'; max_connections=22
		authorization { user: scalar; password: valid; timeout: 2.2 }
	`, nil)
	s := configRuntimeServer(t, path)
	v, err := s.Varz(nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "1" || v.MaxConn != 22 || v.AuthTimeout != 2.2 {
		t.Fatalf("Running server did not consume scalar configuration: name %q, max_connections %d, auth_timeout %v", v.Name, v.MaxConn, v.AuthTimeout)
	}
	configAuthDelivery(t, s, "scalar", "valid")
	configAuthRejected(t, s, "scalar", "wrong")
}

func TestConfigFileBooleanSpellingsRuntime(t *testing.T) {
	for i, literal := range []string{"true", "TRUE", "true", "yes", "on"} {
		t.Run(fmt.Sprintf("%d_%s", i, literal), func(t *testing.T) {
			path := configDiskFixture(t, "listen: 127.0.0.1:-1\nno_header_support = "+literal, nil)
			s := configRuntimeServer(t, path)
			nc, err := nats.Connect(s.ClientURL(), nats.NoReconnect(), nats.Timeout(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			if nc.HeadersSupported() {
				t.Fatal("Boolean spelling did not reach running-server INFO header capability")
			}
			msg := &nats.Msg{Subject: "config.headers", Header: nats.Header{"Test": []string{"value"}}}
			if err := nc.PublishMsg(msg); !errors.Is(err, nats.ErrHeadersNotSupported) {
				t.Fatalf("Configured header capability was not enforced: %v", err)
			}
			configAuthDelivery(t, s, "", "")
		})
	}
}

func TestConfigFileEnvironmentRuntime(t *testing.T) {
	for _, tc := range []struct {
		name, environment, directive, password string
	}{
		{"integer", "22", "max_connections: $__TS_CONF_VALUE__\nauthorization { user: env; password: valid }", "valid"},
		{"string", "xyz", "authorization { user: env; password: $__TS_CONF_VALUE__ }", "xyz"},
		{"numeric prefix", "3xyz", "authorization { user: env; password: $__TS_CONF_VALUE__ }", "3xyz"},
		{"numeric suffix string", "3Gyz", "authorization { user: env; password: $__TS_CONF_VALUE__ }", "3Gyz"},
		{"quoted numeric prefix", "'3xyz'", "authorization { user: env; password: $__TS_CONF_VALUE__ }", "3xyz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("__TS_CONF_VALUE__", tc.environment)
			path := configDiskFixture(t, "listen: 127.0.0.1:-1\n"+tc.directive, nil)
			s := configRuntimeServer(t, path)
			if tc.name == "integer" {
				v, err := s.Varz(nil)
				if err != nil {
					t.Fatal(err)
				}
				if v.MaxConn != 22 {
					t.Fatalf("Environment integer did not configure the running server: %d", v.MaxConn)
				}
			}
			configAuthDelivery(t, s, "env", tc.password)
			configAuthRejected(t, s, "env", "$__TS_CONF_VALUE__")
		})
	}
}

func TestConfigFileConvenientLimitsRuntime(t *testing.T) {
	for _, tc := range []struct {
		literal string
		bytes   int64
	}{
		{"8k", 8 * 1000},
		{"4kb", 4 * 1024},
		{"3ki", 3 * 1024},
		{"4ki", 4 * 1024},
		{"1m", 1000 * 1000},
		{"2MB", 2 * 1024 * 1024},
		{"2Mi", 2 * 1024 * 1024},
		{"64MiB", 64 * 1024 * 1024},
		{"2g", 2 * 1000 * 1000 * 1000},
		{"22GB", 22 * 1024 * 1024 * 1024},
		{"22Gi", 22 * 1024 * 1024 * 1024},
		{"22GiB", 22 * 1024 * 1024 * 1024},
		{"22TB", 22 * 1024 * 1024 * 1024 * 1024},
		{"22Ti", 22 * 1024 * 1024 * 1024 * 1024},
		{"22TiB", 22 * 1024 * 1024 * 1024 * 1024},
		{"22PB", 22 * 1024 * 1024 * 1024 * 1024 * 1024},
		{"22Pi", 22 * 1024 * 1024 * 1024 * 1024 * 1024},
		{"22PiB", 22 * 1024 * 1024 * 1024 * 1024 * 1024},
	} {
		t.Run(tc.literal, func(t *testing.T) {
			// max_pending is a byte-count limit, not an allocation; send only one byte.
			path := configDiskFixture(t, "listen: 127.0.0.1:-1\nmax_payload: 1\nmax_pending: "+tc.literal, nil)
			s := configRuntimeServer(t, path)
			v, err := s.Varz(nil)
			if err != nil {
				t.Fatal(err)
			}
			if v.MaxPending != tc.bytes {
				t.Fatalf("Running server limit: got %d, want %d", v.MaxPending, tc.bytes)
			}
			nc, err := nats.Connect(s.ClientURL(), nats.NoReconnect(), nats.Timeout(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			sub, err := nc.SubscribeSync("config.limit")
			if err != nil {
				t.Fatal(err)
			}
			if err := nc.Publish("config.limit", []byte("x")); err != nil {
				t.Fatal(err)
			}
			if err := nc.FlushTimeout(2 * time.Second); err != nil {
				t.Fatal(err)
			}
			msg, err := sub.NextMsg(2 * time.Second)
			if err != nil || string(msg.Data) != "x" {
				t.Fatalf("Configured byte limit prevented one-byte delivery: msg %v, error %v", msg, err)
			}
		})
	}
}

func TestConfigFileNestedVariableAuthRuntime(t *testing.T) {
	path := configDiskFixture(t, `
		listen: 127.0.0.1:-1
		PASSWORD = '22'
		accounts {
			INNER {
				PASSWORD = '11'
				users = [{user: inner, password: $PASSWORD}]
			}
			OUTER { users = [{user: outer, password: $PASSWORD}] }
		}
	`, nil)
	s := configRuntimeServer(t, path)
	configAuthDelivery(t, s, "inner", "11")
	configAuthDelivery(t, s, "outer", "22")
	configAuthRejected(t, s, "inner", "22")
	configAuthRejected(t, s, "outer", "11")
	configAuthDelivery(t, s, "inner", "11")
}

func TestConfigFileQuotedPasswordsRuntime(t *testing.T) {
	for _, tc := range []struct{ name, literal, password string }{
		{"expression", `'(true == "false")'`, `(true == "false")`},
		{"multiline", "'This is a multi-line\ntext block.'", "This is a multi-line\ntext block."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := configDiskFixture(t, "listen: 127.0.0.1:-1\nauthorization { user: quoted; password: "+tc.literal+" }", nil)
			s := configRuntimeServer(t, path)
			configAuthDelivery(t, s, "quoted", tc.password)
			configAuthRejected(t, s, "quoted", "wrong")
		})
	}
}

func TestConfigFileIncompleteBcryptRuntime(t *testing.T) {
	path := configDiskFixture(t, `
		listen: 127.0.0.1:-1
		authorization { users: [
			{user: invalid, password: $2a$11$ooo}
			{user: control, password: valid}
		] }
	`, nil)
	opts, err := server.ProcessConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Users) != 2 || opts.Users[0].Password != "$2a$11$ooo" {
		t.Fatal("Bcrypt-shaped literal was expanded or lost during production admission")
	}
	s := configRuntimeServer(t, path)
	configAuthDelivery(t, s, "control", "valid")
	configAuthRejected(t, s, "invalid", "$2a$11$ooo")
	configAuthRejected(t, s, "invalid", "foo")
	configAuthDelivery(t, s, "control", "valid")
}
