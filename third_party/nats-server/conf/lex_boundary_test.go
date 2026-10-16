package conf_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func lexerBoundaryServer(t *testing.T, path string) *server.Server {
	t.Helper()
	opts, err := server.ProcessConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	opts.NoLog, opts.NoSigs = true, true
	s, err := server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	go s.Start()
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("configuration did not start a client listener")
	}
	return s
}

func lexerBoundaryTraffic(t *testing.T, s *server.Server, wantName string, options ...nats.Option) {
	t.Helper()
	options = append(options, nats.Timeout(time.Second), nats.NoReconnect())
	nc, err := nats.Connect(s.ClientURL(), options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	if got := nc.ConnectedServerName(); got != wantName {
		t.Fatalf("wire server_name: got %q, want %q", got, wantName)
	}
	sub, err := nc.SubscribeSync("lexer.boundary")
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	want := []byte("config-loaded\x00" + wantName)
	if err := nc.Publish("lexer.boundary", want); err != nil {
		t.Fatal(err)
	}
	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "lexer.boundary" || !bytes.Equal(msg.Data, want) {
		t.Fatalf("configuration listener delivered %q on %q", msg.Data, msg.Subject)
	}
}

func TestLexerStringsConfigureRunningServer(t *testing.T) {
	for _, tc := range []struct {
		name, config, want string
	}{
		{"double", `server_name = "bar"`, "bar"},
		{"single", `server_name = 'bar'`, "bar"},
		{"compact", `server_name='bar'`, "bar"},
		{"crlf", "server_name='bar'\r\n", "bar"},
		{"tab", "server_name=\t'bar'\t", "bar"},
		{"raw", `server_name = bar`, "bar"},
		{"raw_quote", `server_name = bar' `, "bar"},
		{"numeric_prefix", `server_name = 3xyz`, "3xyz"},
		{"numeric_comma", `server_name = 3xyz,`, "3xyz"},
		{"numeric_semicolon", `server_name = 3xyz;`, "3xyz"},
		{"hex", `server_name = \x65`, "e"},
		{"escape_start", `server_name = "\\end"`, "\\end"},
		{"escape_end", `server_name = "start\\"`, "start\\"},
		{"hex_pair", `server_name = \x45\x71`, "Eq"},
		{"string_hex_pair", `server_name = start\x45\x71`, "startEq"},
		{"hex_middle", `server_name = start\x7Cend`, "start|end"},
		{"hex_prefix", `server_name = \x3c\x3eend`, "<>end"},
		{"hex_bookends", `server_name = \x3cmiddle\x3E`, "<middle>"},
		{"escaped_bool", `server_name = \\true`, "\\true"},
		{"escaped_variable", `server_name = \\$var`, "\\$var"},
		{"variable", "bar=bound\nserver_name = $bar", "bound"},
		{"variable_compact", "bar=bound\nserver_name =$bar", "bound"},
		{"variable_space", "bar=bound\nserver_name $bar", "bound"},
		{"comment", "# This is a comment\r\nserver_name = bar", "bar"},
		{"slash_comment", "// This is a comment\r\nserver_name = bar", "bar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "server.conf")
			data := "host: 127.0.0.1\nport: -1\n" + tc.config
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			lexerBoundaryTraffic(t, lexerBoundaryServer(t, path), tc.want)
		})
	}
}

func TestLexerMalformedConfigFilesRejected(t *testing.T) {
	for _, tc := range []struct {
		name, config, diagnostic string
	}{
		{"hex_eol", "server_name = xyz\\x\n", "Expected two hexadecimal digits"},
		{"hex_one_eol", "server_name = xyz\\xF\n", "Expected two hexadecimal digits"},
		{"hex_none", `server_name = "[\x]"`, "Expected two hexadecimal digits"},
		{"hex_one", `server_name = "[\xe]"`, "Expected two hexadecimal digits"},
		{"float", "max_payload = .2", "Floats must start with a digit"},
		{"key", " :foo = 22", "Unexpected key separator ':'"},
		{"escape", `server_name = \y`, "Invalid escape character 'y'"},
		{"double_eof", "server_name: \"localhost:4242\n\nhttp: localhost:8222\n", "Unexpected EOF."},
		{"single_eof", "server_name: 'localhost:4242\n\nhttp: localhost:8222\n", "Unexpected EOF."},
		{"map_eof", "authorization = {\n user = bar\n", "Unexpected EOF processing map."},
		{"block_eof", "server_name = (\n foo = bar\n", "Unexpected EOF processing block."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.conf")
			if err := os.WriteFile(path, []byte(tc.config), 0600); err != nil {
				t.Fatal(err)
			}
			opts, err := server.ProcessConfigFile(path)
			if err == nil || opts != nil || !strings.Contains(err.Error(), tc.diagnostic) {
				t.Fatalf("invalid disk configuration returned opts=%v err=%v; want %q", opts, err, tc.diagnostic)
			}
		})
	}
}

func TestLexerAuthorizationIncludesConfigureRunningServer(t *testing.T) {
	users := "users = [\n {user: alice, password: foo}\n {user: bob, password: bar}\n]\ntimeout: 0.5\n"
	for _, tc := range []struct {
		name, config, included string
	}{
		{"array_of_maps", "authorization {\n" + users + "}", ""},
		{"include_double", `include "users.conf"`, "authorization {\n" + users + "}"},
		{"include_single", `include 'users.conf'`, "authorization {\n" + users + "}"},
		{"include_raw", `include users.conf`, "authorization {\n" + users + "}"},
		{"map_include_raw", `authorization { include users.conf }`, users},
		{"map_include_compact", `authorization {include users.conf}`, users},
		{"map_include_single", `authorization { include 'users.conf' }`, users},
		{"map_include_double", `authorization { include "users.conf"}`, users},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "server.conf")
			if tc.included != "" {
				if err := os.WriteFile(filepath.Join(dir, "users.conf"), []byte(tc.included), 0600); err != nil {
					t.Fatal(err)
				}
			}
			data := "host: 127.0.0.1\nport: -1\nserver_name: lex-auth\n" + tc.config
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			s := lexerBoundaryServer(t, path)
			for _, user := range []struct{ name, password string }{{"alice", "foo"}, {"bob", "bar"}} {
				lexerBoundaryTraffic(t, s, "lex-auth", nats.UserInfo(user.name, user.password))
				nc, err := nats.Connect(s.ClientURL(), nats.UserInfo(user.name, "wrong"), nats.NoReconnect(), nats.Timeout(time.Second))
				if nc != nil {
					nc.Close()
				}
				if err == nil {
					t.Fatalf("configuration accepted incorrect password for %s", user.name)
				}
			}
		})
	}
}
