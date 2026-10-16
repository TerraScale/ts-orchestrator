// Copyright 2018-2026 The NATS Authors
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

package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func simpleAccountServer(t *testing.T) (*Server, *Account, *Account) {
	opts := defaultServerOptions
	s := New(&opts)

	// Now create two accounts.
	f, err := s.RegisterAccount("$foo")
	if err != nil {
		t.Fatalf("Error creating account 'foo': %v", err)
	}
	b, err := s.RegisterAccount("$bar")
	if err != nil {
		t.Fatalf("Error creating account 'bar': %v", err)
	}
	return s, f, b
}

func runAccountProtocolServer(t *testing.T, config string) *Server {
	t.Helper()
	conf := createConfFile(t, []byte("listen: 127.0.0.1:-1\nhttp: 127.0.0.1:-1\n"+config))
	s, _ := RunServerWithConfig(conf)
	t.Cleanup(s.Shutdown)
	return s
}

func accountInfoOverHTTP(t *testing.T, s *Server, account string) *Accountz {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://"+s.MonitorAddr().String()+"/accountz?acc="+url.QueryEscape(account), nil)
	require_NoError(t, err)
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	require_NoError(t, err)
	defer response.Body.Close()
	require_Equal(t, response.StatusCode, http.StatusOK)
	var accounts Accountz
	require_NoError(t, json.NewDecoder(response.Body).Decode(&accounts))
	if account != "" {
		require_NotNil(t, accounts.Account)
		require_Equal(t, accounts.Account.AccountName, account)
	}
	return &accounts
}

func sendAccountProtocol(t *testing.T, nc net.Conn, protocol string) {
	t.Helper()
	require_NoError(t, nc.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err := io.WriteString(nc, protocol)
	require_NoError(t, err)
}

func readAccountProtocol(t *testing.T, nc net.Conn, reader *bufio.Reader) string {
	t.Helper()
	require_NoError(t, nc.SetReadDeadline(time.Now().Add(2*time.Second)))
	line, err := reader.ReadString('\n')
	require_NoError(t, err)
	return line
}

func dialAccountProtocol(t *testing.T, s *Server) (net.Conn, *bufio.Reader) {
	t.Helper()
	nc, err := net.DialTimeout("tcp", s.Addr().String(), 2*time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { nc.Close() })
	reader := bufio.NewReader(nc)
	require_True(t, strings.HasPrefix(readAccountProtocol(t, nc, reader), "INFO "))
	return nc, reader
}

func connectAccountProtocol(t *testing.T, s *Server, username string) (net.Conn, *bufio.Reader) {
	t.Helper()
	nc, reader := dialAccountProtocol(t, s)
	sendAccountProtocol(t, nc, fmt.Sprintf("CONNECT {\"user\":%q,\"pass\":%q,\"verbose\":false}\r\nPING\r\n", username, username))
	require_Equal(t, readAccountProtocol(t, nc, reader), "PONG\r\n")
	return nc, reader
}

func TestAccountIsolationOverTCP(t *testing.T) {
	s := runAccountProtocolServer(t, `accounts {
		foo {users: [{user: foo, password: foo}]}
		bar {users: [{user: bar, password: bar}]}
	}`)
	foo, fr := connectAccountProtocol(t, s, "foo")
	bar, br := connectAccountProtocol(t, s, "bar")
	for _, peer := range []struct {
		nc     net.Conn
		reader *bufio.Reader
	}{{foo, fr}, {bar, br}} {
		sendAccountProtocol(t, peer.nc, "SUB foo 1\r\nPING\r\n")
		require_Equal(t, readAccountProtocol(t, peer.nc, peer.reader), "PONG\r\n")
	}
	sendAccountProtocol(t, foo, "PUB foo 5\r\nhello\r\n")
	require_Equal(t, readAccountProtocol(t, foo, fr), "MSG foo 1 5\r\n")
	require_Equal(t, readAccountProtocol(t, foo, fr), "hello\r\n")
	sendAccountProtocol(t, bar, "PING\r\n")
	require_Equal(t, readAccountProtocol(t, bar, br), "PONG\r\n")
	sendAccountProtocol(t, bar, "PUB foo 3\r\nbar\r\n")
	require_Equal(t, readAccountProtocol(t, bar, br), "MSG foo 1 3\r\n")
	require_Equal(t, readAccountProtocol(t, bar, br), "bar\r\n")
	sendAccountProtocol(t, foo, "PING\r\n")
	require_Equal(t, readAccountProtocol(t, foo, fr), "PONG\r\n")
}

func TestAccountExplicitSelectionRejectedOverTCP(t *testing.T) {
	s := runAccountProtocolServer(t, `accounts {
		A {users: [{user: ua, password: pa}]}
		B {users: [{user: ub, password: pb}]}
	}`)
	for _, extra := range []string{"", `,"account":"ANY"`, `,"new_account":true`, `,"account":"B"`, `,"account":"A"`} {
		t.Run(extra, func(t *testing.T) {
			nc, reader := dialAccountProtocol(t, s)
			sendAccountProtocol(t, nc, `CONNECT {"user":"ua","pass":"pa","verbose":false`+extra+"}\r\nPING\r\n")
			line := readAccountProtocol(t, nc, reader)
			if extra != "" {
				require_True(t, strings.HasPrefix(line, "-ERR 'Authorization Violation'"))
				return
			}
			require_Equal(t, line, "PONG\r\n")
			sendAccountProtocol(t, nc, "SUB own 1\r\nPUB own 2\r\nok\r\n")
			require_Equal(t, readAccountProtocol(t, nc, reader), "MSG own 1 2\r\n")
			require_Equal(t, readAccountProtocol(t, nc, reader), "ok\r\n")
		})
	}
}

func TestAccountStreamMappingLifecycleOverTCP(t *testing.T) {
	for _, finish := range []string{"unsubscribe", "disconnect"} {
		t.Run(finish, func(t *testing.T) {
			s := runAccountProtocolServer(t, `accounts {
				foo {users: [{user: foo, password: foo}], exports: [{stream: foo}]}
				bar {users: [{user: bar, password: bar}], imports: [{stream: {account: foo, subject: foo}, prefix: import}]}
			}`)
			publisher := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
			defer publisher.Close()
			nc, reader := connectAccountProtocol(t, s, "bar")
			sendAccountProtocol(t, nc, "SUB import.foo 1\r\nSUB import.foo bar 2\r\nPING\r\n")
			require_Equal(t, readAccountProtocol(t, nc, reader), "PONG\r\n")
			require_Equal(t, accountInfoOverHTTP(t, s, "foo").Account.SubCnt, uint32(2))
			require_Equal(t, accountInfoOverHTTP(t, s, "bar").Account.SubCnt, uint32(2))
			natsPub(t, publisher, "foo", []byte("hello"))
			seen := make(map[string]bool)
			for range 2 {
				line := readAccountProtocol(t, nc, reader)
				var subject, sid string
				var size int
				_, err := fmt.Sscanf(line, "MSG %s %s %d", &subject, &sid, &size)
				require_NoError(t, err)
				require_Equal(t, subject, "import.foo")
				require_Equal(t, size, 5)
				require_True(t, sid == "1" || sid == "2")
				require_True(t, !seen[sid])
				seen[sid] = true
				require_Equal(t, readAccountProtocol(t, nc, reader), "hello\r\n")
			}
			if finish == "unsubscribe" {
				sendAccountProtocol(t, nc, "UNSUB 1\r\nUNSUB 2\r\nPING\r\n")
				require_Equal(t, readAccountProtocol(t, nc, reader), "PONG\r\n")
			} else {
				require_NoError(t, nc.Close())
			}
			checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
				if got := accountInfoOverHTTP(t, s, "foo").Account.SubCnt; got != 0 {
					return fmt.Errorf("exporter retains %d shadow subscriptions", got)
				}
				if got := accountInfoOverHTTP(t, s, "bar").Account.SubCnt; got != 0 {
					return fmt.Errorf("importer retains %d subscriptions", got)
				}
				return nil
			})
		})
	}
}

func TestAccountStreamMappingMatrixOverTCP(t *testing.T) {
	for _, tc := range []struct {
		name, imports, subscription string
		subjects, mapped, payloads  []string
	}{
		{"no prefix", `{stream: {account: foo, subject: "*"}}`, "foo", []string{"foo"}, []string{"foo"}, []string{"hello"}},
		{"prefix wildcard subscriber", `{stream: {account: foo, subject: "*"}, prefix: "pub.imports."}`, "pub.imports.*", []string{"foo"}, []string{"pub.imports.foo"}, []string{"hello"}},
		{"prefix literal subscriber", `{stream: {account: foo, subject: "*"}, prefix: "pub.imports."}`, "pub.imports.foo", []string{"foo"}, []string{"pub.imports.foo"}, []string{"hello"}},
		{"multiple imports wildcard subscriber", `{stream: {account: foo, subject: foo}, prefix: "pub."}, {stream: {account: foo, subject: bar}, prefix: "pub."}`, "pub.*", []string{"foo", "bar"}, []string{"pub.foo", "pub.bar"}, []string{"hello", "world"}},
		{"literal prefix on full wildcard", `{stream: {account: foo, subject: "client.>"}, prefix: events}`, "events.>", []string{"client.one"}, []string{"events.client.one"}, []string{"hello"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := runAccountProtocolServer(t, fmt.Sprintf(`accounts {
				foo {users: [{user: foo, password: foo}], exports: [{stream: ">", accounts: [bar]}]}
				bar {users: [{user: bar, password: bar}], imports: [%s]}
				other {users: [{user: other, password: other}]}
			}`, tc.imports))
			publisher := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
			defer publisher.Close()
			client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
			defer client.Close()
			other := natsConnect(t, s.ClientURL(), nats.UserInfo("other", "other"), nats.NoReconnect())
			defer other.Close()
			isolated := natsSubSync(t, other, ">")
			sub := natsSubSync(t, client, tc.subscription)
			require_NoError(t, other.FlushTimeout(2*time.Second))
			require_NoError(t, client.FlushTimeout(2*time.Second))
			for i, subject := range tc.subjects {
				natsPub(t, publisher, subject, []byte(tc.payloads[i]))
				msg := natsNexMsg(t, sub, 2*time.Second)
				require_Equal(t, msg.Subject, tc.mapped[i])
				require_Equal(t, string(msg.Data), tc.payloads[i])
			}
			require_Equal(t, accountInfoOverHTTP(t, s, "foo").Account.SubCnt, uint32(len(tc.subjects)))
			require_Equal(t, accountInfoOverHTTP(t, s, "bar").Account.SubCnt, uint32(1))
			require_NoError(t, sub.Unsubscribe())
			require_NoError(t, client.FlushTimeout(2*time.Second))
			require_Equal(t, accountInfoOverHTTP(t, s, "foo").Account.SubCnt, uint32(0))
			require_Equal(t, accountInfoOverHTTP(t, s, "bar").Account.SubCnt, uint32(0))
			require_NoError(t, other.FlushTimeout(2*time.Second))
			pending, _, err := isolated.Pending()
			require_NoError(t, err)
			require_Equal(t, pending, 0)
		})
	}
}

func TestAccountMultiExporterStreamImportsOverTCP(t *testing.T) {
	for _, separatePrefixes := range []bool{false, true} {
		t.Run(strconv.FormatBool(separatePrefixes), func(t *testing.T) {
			fooPrefix, barPrefix, subscription := "", "", "test"
			if separatePrefixes {
				fooPrefix, barPrefix, subscription = "foo", "bar", "*.test"
			}
			s := runAccountProtocolServer(t, fmt.Sprintf(`accounts {
				foo {users: [{user: foo, password: foo}], exports: [{stream: test}]}
				bar {users: [{user: bar, password: bar}], exports: [{stream: test}]}
				importer {users: [{user: importer, password: importer}], imports: [
					{stream: {account: foo, subject: test}, prefix: %q},
					{stream: {account: bar, subject: test}, prefix: %q}
				]}
			}`, fooPrefix, barPrefix))
			client := natsConnect(t, s.ClientURL(), nats.UserInfo("importer", "importer"), nats.NoReconnect())
			defer client.Close()
			sub := natsSubSync(t, client, subscription)
			require_NoError(t, client.FlushTimeout(2*time.Second))
			for _, exporter := range []string{"foo", "bar"} {
				publisher := natsConnect(t, s.ClientURL(), nats.UserInfo(exporter, exporter), nats.NoReconnect())
				defer publisher.Close()
				natsPub(t, publisher, "test", []byte("hello-"+exporter))
				msg := natsNexMsg(t, sub, 2*time.Second)
				expected := "test"
				if separatePrefixes {
					expected = exporter + ".test"
				}
				require_Equal(t, msg.Subject, expected)
				require_Equal(t, string(msg.Data), "hello-"+exporter)
			}
		})
	}
}

func requireAccountStartupRejected(t *testing.T, config, diagnostic string) {
	t.Helper()
	configFile := createConfFile(t, []byte("listen: 127.0.0.1:-1\n"+config))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAccountStartupContractsOverProcess$")
	command.Env = append(os.Environ(), "NATS_TEST_ACCOUNT_STARTUP_CONFIG="+configFile)
	output, err := command.CombinedOutput()
	require_NoError(t, ctx.Err())
	exit, ok := errors.AsType[*exec.ExitError](err)
	require_True(t, ok)
	require_Equal(t, exit.ExitCode(), 1)
	require_True(t, len(output) > 0)
	if diagnostic != "" {
		require_Contains(t, string(output), diagnostic)
	}
}

func TestAccountStartupContractsOverProcess(t *testing.T) {
	if config := os.Getenv("NATS_TEST_ACCOUNT_STARTUP_CONFIG"); config != "" {
		fs := flag.NewFlagSet("nats-server", flag.ContinueOnError)
		opts, err := ConfigureOptions(fs, []string{"-c", config}, PrintServerAndExit, func() {}, PrintTLSHelpAndDie)
		if err != nil {
			PrintAndDie(err.Error())
		}
		s, err := NewServer(opts)
		if err != nil {
			PrintAndDie(err.Error())
		}
		s.ConfigureLogger()
		if err := Run(s); err != nil {
			PrintAndDie(err.Error())
		}
		s.WaitForShutdown()
		return
	}
	for _, tc := range []struct{ name, config, diagnostic string }{
		{"duplicate array account", `accounts: [foo, foo]`, "Duplicate Account Entry"},
		{"latency wildcard results", `accounts {foo {exports: [{service: "track.service",latency: {subject: "results.*",sampling: 100}}]}}`, ""},
		{"latency results loops to service", `accounts {foo {exports: [{service: "track.service",latency: {subject: "track.service",sampling: 100}}]}}`, ""},
		{"latency sampling negative", `accounts {foo {exports: [{service: "track.service",latency: {subject: "results",sampling: -1}}]}}`, ""},
		{"latency sampling exceeds100", `accounts {foo {exports: [{service: "track.service",latency: {subject: "results",sampling: 101}}]}}`, ""},
		{"mapping weight exceeds100", `accounts {weighted {mappings: {foo: [{dest: bar,weight: 150}]}}}`, ""},
		{"mapping duplicate destination", `accounts {weighted {mappings: {foo: [{dest: bar,weight: 50},{dest: bar,weight: 50}]}}}`, ""},
		{"mapping weight total exceeds100", `accounts {weighted {mappings: {foo: [{dest: bar,weight: 50},{dest: baz,weight: 60}]}}}`, ""},
		{"reserved global account", `accounts {$G {}}`, "Reserved Account"},
		{"duplicate users across accounts", `accounts {synadia {users: [{user: alice, password: foo}, {user: bob, password: bar}]} nats.io {users: [{user: alice, password: bar}]}}`, "Duplicate user"},
		{"unknown exporter account", `accounts {nats.io {imports: [{stream: {account: synadia, subject: foo}}]}}`, "account not defined"},
		{"missing service account original", `accounts {nats.io {imports = [{service: subject:"foo.*"}]}}`, ""},
		{"malformed wildcard original", `accounts {nats.io {imports = [{service: {account: "nats.io", subject:"foo.*"}]}}`, ""},
		{"unknown export keyword", `accounts {nats.io {exports: [{service: "foo.*", wat: true}]}}`, ""},
		{"unknown import keyword", `accounts {nats.io {imports: [{stream: {account: nats.io, subject: "foo.*"}, wat: true}]}}`, ""},
		{"export account object", `accounts {nats.io {exports: [{service: {account: nats.io, subject: "foo.*"}}]}}`, ""},
		{"wildcard stream prefix", `accounts {foo {exports: [{stream: "client.>"}]} bar {imports: [{stream: {account: foo, subject: "client.>"}, prefix: "events.>"}]}}`, "prefix can not contain wildcard"},
		{"duplicate stream import", `accounts {foo {exports: [{stream: test}]} bar {imports: [{stream: {account: foo, subject: test}}, {stream: {account: foo, subject: test}}]}}`, "stream import already exists"},
		{"unauthorized stream import", `accounts {foo {} bar {imports: [{stream: {account: foo, subject: foo}, prefix: import}]}}`, "authorization"},
		{"missing service exporter", `accounts {bar {imports: [{service: {account: missing, subject: "test.request"}, to: foo}]}}`, "account not defined"},
		{"invalid service destination", `accounts {foo {exports: [{service: "test.request"}]} bar {imports: [{service: {account: foo, subject: "test..request."}, to: foo}]}}`, ""},
		{"wildcard service with mapping", `accounts {foo {exports: [{service: "test.*"}]} bar {imports: [{service: {account: foo, subject: foo}, to: "test.*"}]}}`, ""},
		{"service import broader than export", `accounts {foo {exports: [{service: "test.*"}]} bar {imports: [{service: {account: foo, subject: "test.>"}}]}}`, "authorization"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireAccountStartupRejected(t, tc.config, tc.diagnostic)
		})
	}
}

func TestAccountOptionsAndGlobalOverTCP(t *testing.T) {
	t.Run("options accounts", func(t *testing.T) {
		foo, bar := NewAccount("foo"), NewAccount("bar")
		opts := DefaultOptions()
		opts.Host, opts.Port, opts.HTTPHost, opts.HTTPPort = "127.0.0.1", -1, "127.0.0.1", -1
		opts.Accounts = []*Account{foo, bar}
		opts.Users = []*User{{Username: "foo", Password: "foo", Account: foo}, {Username: "bar", Password: "bar", Account: bar}}
		s := RunServer(opts)
		defer s.Shutdown()
		accounts := accountInfoOverHTTP(t, s, "").Accounts
		require_Equal(t, len(accounts), 3)
		for _, name := range []string{"$G", "foo", "bar"} {
			require_True(t, slices.Contains(accounts, name))
		}
		for _, name := range []string{"foo", "bar"} {
			nc := natsConnect(t, s.ClientURL(), nats.UserInfo(name, name), nats.NoReconnect())
			defer nc.Close()
			sub := natsSubSync(t, nc, "initialized")
			require_NoError(t, nc.FlushTimeout(2*time.Second))
			natsPub(t, nc, "initialized", []byte(name))
			require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), name)
		}
	})
	t.Run("config array", func(t *testing.T) {
		s := runAccountProtocolServer(t, `accounts: [foo,bar]`)
		accounts := accountInfoOverHTTP(t, s, "").Accounts
		require_Equal(t, len(accounts), 3)
		for _, name := range []string{"$G", "foo", "bar"} {
			require_True(t, slices.Contains(accounts, name))
		}
	})
	t.Run("global default", func(t *testing.T) {
		s := runAccountProtocolServer(t, "")
		require_True(t, slices.Contains(accountInfoOverHTTP(t, s, "").Accounts, "$G"))
		nc := natsConnect(t, s.ClientURL(), nats.NoReconnect())
		defer nc.Close()
		sub := natsSubSync(t, nc, "global")
		require_NoError(t, nc.FlushTimeout(2*time.Second))
		natsPub(t, nc, "global", []byte("default account"))
		require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), "default account")
	})
}

func TestAccountUserBindingsOverTCP(t *testing.T) {
	for _, nkeyUsers := range []bool{false, true} {
		t.Run(strconv.FormatBool(nkeyUsers), func(t *testing.T) {
			type identity struct {
				name, account string
				option        nats.Option
			}
			var config string
			var users []identity
			if !nkeyUsers {
				config = `accounts {synadia {users: [{user: alice, password: foo}, {user: bob, password: bar}]} nats.io {users: [{user: derek, password: foo}, {user: ivan, password: bar}], msg_trace: {dest: my.trace.dest, sampling: 50%}}}`
				users = []identity{{"alice", "synadia", nats.UserInfo("alice", "foo")}, {"bob", "synadia", nats.UserInfo("bob", "bar")}, {"derek", "nats.io", nats.UserInfo("derek", "foo")}, {"ivan", "nats.io", nats.UserInfo("ivan", "bar")}}
			} else {
				config = `accounts {synadia {users: [{user: derek, password: foo}, {nkey: UCNGL4W5QX66CFX6A6DCBVDH5VOHMI7B2UZZU7TXAUQQSI2JPHULCKBR}]} nats {users: [{user: ivan, password: bar}, {nkey: UDPGQVFIWZ7Q5UH4I5E6DBCZULQS6VTVBG6CYBD7JV3G3N2GMQOMNAUH}]}}`
				users = []identity{{"derek", "synadia", nats.UserInfo("derek", "foo")}, {"ivan", "nats", nats.UserInfo("ivan", "bar")}}
				for i, seed := range []string{"SUAPM67TC4RHQLKBX55NIQXSMATZDOZK6FNEOSS36CAYA7F7TY66LP4BOM", "SUAIS5JPX4X4GJ7EIIJEQ56DH2GWPYJRPWN5XJEDENJOZHCBLI7SEPUQDE"} {
					kp, err := nkeys.FromSeed([]byte(seed))
					require_NoError(t, err)
					pub, err := kp.PublicKey()
					require_NoError(t, err)
					account := "synadia"
					if i == 1 {
						account = "nats"
					}
					users = append(users, identity{pub, account, nats.Nkey(pub, func(nonce []byte) ([]byte, error) {
						if len(nonce) == 0 {
							return nil, fmt.Errorf("server omitted authentication nonce")
						}
						return kp.Sign(nonce)
					})})
				}
			}
			s := runAccountProtocolServer(t, config)
			var clients []*nats.Conn
			var subs []*nats.Subscription
			for _, user := range users {
				nc := natsConnect(t, s.ClientURL(), user.option, nats.NoReconnect())
				defer nc.Close()
				clients = append(clients, nc)
				subs = append(subs, natsSubSync(t, nc, "binding"))
				require_NoError(t, nc.FlushTimeout(2*time.Second))
			}
			for i, publisher := range clients {
				natsPub(t, publisher, "binding", []byte(users[i].name))
				for j, sub := range subs {
					if users[i].account == users[j].account {
						require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), users[i].name)
					}
				}
			}
			for i, nc := range clients {
				require_NoError(t, nc.FlushTimeout(2*time.Second))
				pending, _, err := subs[i].Pending()
				require_NoError(t, err)
				require_Equal(t, pending, 0)
				require_Equal(t, accountInfoOverHTTP(t, s, users[i].account).Account.ClientCnt, 2)
			}
		})
	}
}

func TestAccountServiceMappingsOverTCP(t *testing.T) {
	for _, tc := range []struct {
		name, export, local, destination string
		private                          bool
	}{
		{"literal public", "test.request", "foo", "test.request", false},
		{"wildcard export public", "ngs.update.*", "ngs.update", "ngs.update.$bar", false},
		{"wildcard export private", "ngs.update.*", "ngs.update", "ngs.update.$bar", true},
		{"wildcard identity import", "test.*", "test.*", "test.*", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			approval := ""
			if tc.private {
				approval = ", accounts: [bar]"
			}
			to := ""
			if tc.local != tc.destination {
				to = fmt.Sprintf(", to: %q", tc.local)
			}
			s := runAccountProtocolServer(t, fmt.Sprintf(`accounts {
				foo {users: [{user: foo,password: foo}], exports: [{service: %q%s}]}
				bar {users: [{user: bar,password: bar}], imports: [{service: {account: foo,subject: %q}%s}]}
			}`, tc.export, approval, tc.destination, to))
			responder := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
			defer responder.Close()
			client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
			defer client.Close()
			requests := natsSubSync(t, responder, tc.export)
			replies := natsSubSync(t, client, "reply")
			require_NoError(t, responder.FlushTimeout(2*time.Second))
			require_NoError(t, client.FlushTimeout(2*time.Second))
			local, destination := tc.local, tc.destination
			if tc.local == "test.*" {
				local, destination = "test.22", "test.22"
			}
			natsPubReq(t, client, local, replies.Subject, []byte("help"))
			request := natsNexMsg(t, requests, 2*time.Second)
			require_Equal(t, request.Subject, destination)
			require_Equal(t, string(request.Data), "help")
			require_True(t, strings.HasPrefix(request.Reply, "_R_."))
			require_Equal(t, len(accountInfoOverHTTP(t, s, "foo").Account.Responses), 1)
			natsPub(t, responder, request.Reply, []byte("22"))
			response := natsNexMsg(t, replies, 2*time.Second)
			require_Equal(t, response.Subject, "reply")
			require_Equal(t, string(response.Data), "22")
			require_Equal(t, response.Reply, "")
			require_Equal(t, len(accountInfoOverHTTP(t, s, "foo").Account.Responses), 0)
		})
	}
}

func TestAccountAdditiveExportPermissionsOverTCP(t *testing.T) {
	for _, kind := range []string{"stream", "service"} {
		t.Run(kind, func(t *testing.T) {
			s := runAccountProtocolServer(t, fmt.Sprintf(`accounts {
				foo {users: [{user: foo,password: foo}], exports: [
					{%s: "test.request"},
					{%s: "test.request",accounts: [bar]},
					{%s: "test.request",accounts: [baz]}
				]}
				bar {users: [{user: bar,password: bar}], imports: [{%s: {account: foo,subject: "test.request"}}]}
				baz {users: [{user: baz,password: baz}], imports: [{%s: {account: foo,subject: "test.request"}}]}
			}`, kind, kind, kind, kind, kind))
			exports := accountInfoOverHTTP(t, s, "foo").Account.Exports
			require_Equal(t, len(exports), 1)
			require_Equal(t, exports[0].Subject, jwt.Subject("test.request"))
			require_Equal(t, len(exports[0].ApprovedAccounts), 2)
			require_True(t, slices.Contains(exports[0].ApprovedAccounts, "bar"))
			require_True(t, slices.Contains(exports[0].ApprovedAccounts, "baz"))
			publisher := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
			defer publisher.Close()
			var requests *nats.Subscription
			if kind == "service" {
				requests = natsSubSync(t, publisher, "test.request")
				require_NoError(t, publisher.FlushTimeout(2*time.Second))
			}
			for _, account := range []string{"bar", "baz"} {
				nc := natsConnect(t, s.ClientURL(), nats.UserInfo(account, account), nats.NoReconnect())
				defer nc.Close()
				if kind == "stream" {
					sub := natsSubSync(t, nc, "test.request")
					require_NoError(t, nc.FlushTimeout(2*time.Second))
					natsPub(t, publisher, "test.request", []byte(account))
					require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), account)
					require_NoError(t, sub.Unsubscribe())
				} else {
					replies := natsSubSync(t, nc, nats.NewInbox())
					require_NoError(t, nc.FlushTimeout(2*time.Second))
					natsPubReq(t, nc, "test.request", replies.Subject, []byte(account))
					request := natsNexMsg(t, requests, 2*time.Second)
					require_Equal(t, request.Subject, "test.request")
					require_Equal(t, string(request.Data), account)
					natsPub(t, publisher, request.Reply, []byte("reply:"+account))
					require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "reply:"+account)
				}
			}
		})
	}
}

func TestAccountConfiguredMappingsOverTCP(t *testing.T) {
	s := runAccountProtocolServer(t, `accounts {synadia {
		users: [{user: derek,password: foo}]
		mappings: {
			foo: bar
			foo.*: [{dest: "bar.v1.$1",weight: 40%},{destination: "baz.v2.$1",weight: 20}]
			bar.*.*: "RAB.$2.$1"
		}
	}}`)
	mappings := accountInfoOverHTTP(t, s, "synadia").Account.Mappings
	require_Equal(t, len(mappings), 3)
	require_Equal(t, mappings["foo"][0].Subject, "bar")
	require_Equal(t, mappings["bar.*.*"][0].Subject, "RAB.$2.$1")
	nc := natsConnect(t, s.ClientURL(), nats.UserInfo("derek", "foo"), nats.NoReconnect())
	defer nc.Close()
	sub := natsSubSync(t, nc, ">")
	require_NoError(t, nc.FlushTimeout(2*time.Second))
	for _, tc := range []struct {
		subject      string
		destinations []string
	}{
		{"foo", []string{"bar"}},
		{"bar.first.second", []string{"RAB.second.first"}},
		{"foo.key", []string{"foo.key", "bar.v1.key", "baz.v2.key"}},
	} {
		natsPub(t, nc, tc.subject, []byte(tc.subject))
		msg := natsNexMsg(t, sub, 2*time.Second)
		require_True(t, slices.Contains(tc.destinations, msg.Subject))
		require_Equal(t, string(msg.Data), tc.subject)
	}
}

func TestAccountWeightedMappingsOverTCP(t *testing.T) {
	s := runAccountProtocolServer(t, `accounts {weighted {
		users: [{user: weighted,password: weighted}]
		mappings: {foo: [{dest: bar,weight: 50},{dest: baz,weight: 30}]}
	}}`)
	nc := natsConnect(t, s.ClientURL(), nats.UserInfo("weighted", "weighted"), nats.NoReconnect())
	defer nc.Close()
	var subs []*nats.Subscription
	for _, subject := range []string{"foo", "bar", "baz"} {
		subs = append(subs, natsSubSync(t, nc, subject))
	}
	require_NoError(t, nc.FlushTimeout(2*time.Second))
	total := 5000
	for i := range total {
		natsPub(t, nc, "foo", []byte(strconv.Itoa(i)))
	}
	require_NoError(t, nc.FlushTimeout(2*time.Second))
	seen := make(map[int]bool, total)
	for i, weight := range []uint8{20, 50, 30} {
		pending, _, err := subs[i].Pending()
		require_NoError(t, err)
		expected := total / int(100/weight)
		tolerance := expected / 5
		require_True(t, pending >= expected-tolerance && pending <= expected+tolerance)
		for range pending {
			msg := natsNexMsg(t, subs[i], 2*time.Second)
			require_Equal(t, msg.Subject, subs[i].Subject)
			id, err := strconv.Atoi(string(msg.Data))
			require_NoError(t, err)
			require_True(t, id >= 0 && id < total && !seen[id])
			seen[id] = true
		}
	}
	require_Equal(t, len(seen), total)
}

func TestAccountServiceResponseCleanupOverTCP(t *testing.T) {
	s := runAccountProtocolServer(t, `accounts {
		foo {users: [{user: foo,password: foo}], exports: [{service: "test.request",response_type: stream}]}
		bar {users: [{user: bar,password: bar}], imports: [{service: {account: foo,subject: "test.request"},to: foo}]}
	}`)
	responder := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
	defer responder.Close()
	requests := natsSubSync(t, responder, "test.request")
	require_NoError(t, responder.FlushTimeout(2*time.Second))
	client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
	defer client.Close()
	replies := natsSubSync(t, client, "bar")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	natsPubReq(t, client, "foo", "bar", []byte("help"))
	request := natsNexMsg(t, requests, 2*time.Second)
	require_Equal(t, request.Subject, "test.request")
	require_Equal(t, string(request.Data), "help")
	require_True(t, strings.HasPrefix(request.Reply, "_R_."))
	for i := range 10 {
		natsPub(t, responder, request.Reply, []byte(strconv.Itoa(i)))
	}
	for i := range 10 {
		response := natsNexMsg(t, replies, 2*time.Second)
		require_Equal(t, response.Subject, "bar")
		require_Equal(t, string(response.Data), strconv.Itoa(i))
	}
	require_Equal(t, len(accountInfoOverHTTP(t, s, "foo").Account.Responses), 1)
	client.Close()
	checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
		if pending := len(accountInfoOverHTTP(t, s, "foo").Account.Responses); pending != 0 {
			return fmt.Errorf("stream response remained after requester close: %d", pending)
		}
		return nil
	})
	client = natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
	defer client.Close()
	natsPubReq(t, client, "foo", "bar", []byte("no reply interest"))
	request = natsNexMsg(t, requests, 2*time.Second)
	require_Equal(t, string(request.Data), "no reply interest")
	natsPub(t, responder, request.Reply, []byte("discarded"))
	require_NoError(t, responder.FlushTimeout(2*time.Second))
	checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
		if pending := len(accountInfoOverHTTP(t, s, "foo").Account.Responses); pending != 0 {
			return fmt.Errorf("response with no reply interest remained: %d", pending)
		}
		return nil
	})
}

func TestAccountSharedReplyCleanupOverTCP(t *testing.T) {
	for _, count := range []int{15, 1600} {
		for _, removal := range []string{"expiry", "unsubscribe", "disconnect"} {
			t.Run(fmt.Sprintf("%d/%s", count, removal), func(t *testing.T) {
				s := runAccountProtocolServer(t, `accounts {
					foo {users: [{user: foo,password: foo}], exports: [{service: test,response_threshold: "5s"}]}
					bar {users: [{user: bar,password: bar}], imports: [{service: {account: foo,subject: test}}]}
				}`)
				responder := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
				defer responder.Close()
				requests := natsSubSync(t, responder, "test")
				require_NoError(t, responder.FlushTimeout(2*time.Second))
				client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
				defer client.Close()
				replies := natsSubSync(t, client, "my.inbox")
				require_NoError(t, client.FlushTimeout(2*time.Second))
				for i := range count {
					natsPubReq(t, client, "test", "my.inbox", []byte(strconv.Itoa(i)))
				}
				stale := make([]*nats.Msg, 0, count)
				for i := range count {
					request := natsNexMsg(t, requests, 2*time.Second)
					require_Equal(t, request.Subject, "test")
					require_Equal(t, string(request.Data), strconv.Itoa(i))
					stale = append(stale, request)
				}
				require_Equal(t, len(accountInfoOverHTTP(t, s, "foo").Account.Responses), count)
				switch removal {
				case "unsubscribe":
					require_NoError(t, replies.Unsubscribe())
					require_NoError(t, client.FlushTimeout(2*time.Second))
				case "disconnect":
					client.Close()
				}
				wait := 2 * time.Second
				if removal == "expiry" {
					wait = 7 * time.Second
				}
				checkFor(t, wait, 10*time.Millisecond, func() error {
					if pending := len(accountInfoOverHTTP(t, s, "foo").Account.Responses); pending != 0 {
						return fmt.Errorf("%s left %d of %d responses", removal, pending, count)
					}
					return nil
				})
				if removal == "disconnect" {
					client = natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
					defer client.Close()
				}
				if removal != "expiry" {
					replies = natsSubSync(t, client, "my.inbox")
					require_NoError(t, client.FlushTimeout(2*time.Second))
				}
				natsPubReq(t, client, "test", "my.inbox", []byte("current"))
				current := natsNexMsg(t, requests, 2*time.Second)
				require_Equal(t, string(current.Data), "current")
				require_Equal(t, len(accountInfoOverHTTP(t, s, "foo").Account.Responses), 1)
				for _, request := range stale {
					natsPub(t, responder, request.Reply, []byte("stale"))
				}
				natsPub(t, responder, current.Reply, []byte("current reply"))
				require_NoError(t, responder.FlushTimeout(2*time.Second))
				require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "current reply")
				natsPub(t, client, "my.inbox", []byte("local marker"))
				require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "local marker")
				require_Equal(t, len(accountInfoOverHTTP(t, s, "foo").Account.Responses), 0)
			})
		}
	}
}

func TestAccountServiceLatencyOverTCP(t *testing.T) {
	s := runAccountProtocolServer(t, `system_account: SYS
 accounts {
  SYS {}
  foo {users: [{user: foo,password: foo}], exports: [{service: "track.service",latency: {subject: results,sampling: 100}}]}
  bar {users: [{user: bar,password: bar}], imports: [{service: {account: foo,subject: "track.service"},to: req}]}
 }`)
	responder := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
	defer responder.Close()
	requests := natsSubSync(t, responder, "track.service")
	metrics := natsSubSync(t, responder, "results")
	require_NoError(t, responder.FlushTimeout(2*time.Second))
	client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
	defer client.Close()
	replies := natsSubSync(t, client, "resp")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	start := time.Now()
	natsPubReq(t, client, "req", "resp", []byte("help"))
	request := natsNexMsg(t, requests, 2*time.Second)
	require_Equal(t, request.Subject, "track.service")
	require_Equal(t, string(request.Data), "help")
	time.Sleep(25 * time.Millisecond)
	natsPub(t, responder, request.Reply, []byte("22"))
	require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "22")
	metric := natsNexMsg(t, metrics, 2*time.Second)
	var latency ServiceLatency
	require_NoError(t, json.Unmarshal(metric.Data, &latency))
	require_Equal(t, latency.Type, ServiceLatencyType)
	require_Equal(t, latency.Status, 200)
	require_True(t, latency.RequestStart.Sub(start) <= 5*time.Millisecond)
	require_True(t, latency.ServiceLatency >= 25*time.Millisecond)
	require_True(t, latency.TotalLatency >= latency.ServiceLatency)
	require_True(t, latency.RequestHeader == nil)
}

func TestAccountLatencySamplingHeadersOverTCP(t *testing.T) {
	s := runAccountProtocolServer(t, `system_account: SYS
 accounts {
  SYS {}
  foo {users: [{user: foo,password: foo}], exports: [{service: "track.service",latency: {subject: results,sampling: headers}}]}
  bar {users: [{user: bar,password: bar}], imports: [{service: {account: foo,subject: "track.service"},to: req}]}
 }`)
	responder := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
	defer responder.Close()
	requests := natsSubSync(t, responder, "track.service")
	metrics := natsSubSync(t, responder, "results")
	require_NoError(t, responder.FlushTimeout(2*time.Second))
	client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
	defer client.Close()
	replies := natsSubSync(t, client, "resp")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	issue := func(t *testing.T, payload string, header http.Header) {
		t.Helper()
		require_NoError(t, client.PublishMsg(&nats.Msg{Subject: "req", Reply: "resp", Data: []byte(payload), Header: nats.Header(header)}))
		request := natsNexMsg(t, requests, 2*time.Second)
		require_Equal(t, string(request.Data), payload)
		natsPub(t, responder, request.Reply, []byte(payload))
		require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), payload)
	}
	for i, tc := range []struct {
		sample bool
		header http.Header
	}{
		{false, http.Header{"Uber-Trace-Id": []string{"0:0:0:0"}}},
		{false, http.Header{"Uber-Trace-Id": []string{"0:0:0:00"}}},
		{true, http.Header{"Uber-Trace-Id": []string{"0:0:0:1"}}},
		{true, http.Header{"Uber-Trace-Id": []string{"0:0:0:01"}}},
		{true, http.Header{"Uber-Trace-Id": []string{"0:0:0:5"}}},
		{true, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:5adb976bfc1f95c1:479fefe9525eddb:1"}}},
		{true, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:479fefe9525eddb:0:1"}}},
		{false, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:5adb976bfc1f95c1:479fefe9525eddb:0"}}},
		{false, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:479fefe9525eddb:0:0"}}},
		{true, http.Header{"X-B3-Sampled": []string{"1"}}},
		{false, http.Header{"X-B3-Sampled": []string{"0"}}},
		{true, http.Header{"X-B3-TraceId": []string{"80f198ee56343ba864fe8b2a57d3eff7"}}},
		{false, http.Header{"X-B3-TraceId": []string{"80f198ee56343ba864fe8b2a57d3eff7"}, "X-B3-Sampled": []string{"0"}}},
		{true, http.Header{"X-B3-TraceId": []string{"80f198ee56343ba864fe8b2a57d3eff7"}, "X-B3-Sampled": []string{"1"}}},
		{false, http.Header{"B3": []string{"0"}}},
		{false, http.Header{"B3": []string{"0-0-0-0"}}},
		{false, http.Header{"B3": []string{"0-0-0"}}},
		{true, http.Header{"B3": []string{"0-0-1-0"}}},
		{true, http.Header{"B3": []string{"0-0-1"}}},
		{true, http.Header{"B3": []string{"0-0-d"}}},
		{true, http.Header{"B3": []string{"80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1"}}},
		{true, http.Header{"B3": []string{"80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1-05e3ac9a4f6e3b90"}}},
		{false, http.Header{"B3": []string{"80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-0-05e3ac9a4f6e3b90"}}},
		{true, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}}},
		{true, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-27"}}},
		{false, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"}}},
		{false, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-22"}}},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			issue(t, strconv.Itoa(i), tc.header)
			expected := tc.header
			if !tc.sample {
				expected = http.Header{"X-B3-Traceid": []string{fmt.Sprintf("marker%d", i)}, "X-B3-Sampled": []string{"1"}}
				// Both responses use one responder socket, so the sampled marker orders the internal metrics queue.
				issue(t, "marker", expected)
			}
			metric := natsNexMsg(t, metrics, 2*time.Second)
			var latency ServiceLatency
			require_NoError(t, json.Unmarshal(metric.Data, &latency))
			require_Equal(t, latency.Status, 200)
			require_Equal(t, len(latency.RequestHeader), len(expected))
			for key, values := range expected {
				require_Equal(t, latency.RequestHeader.Get(key), values[0])
			}
		})
	}
}

func TestAccountImportAuthorizationMatrixOverTCP(t *testing.T) {
	exports := []string{
		``,
		`{stream: foo}`,
		`{stream: foo},{stream: "*",accounts: ["$bar"]}`,
		`{stream: ">"}`,
		`{stream: "foo.*",account_token_position: 2},{stream: "bar.*.foo",account_token_position: 2}`,
		`{service: "a.*",account_token_position: 2},{service: "b.*.a",account_token_position: 2}`,
		`{stream: "foo.*.baz.>",accounts: ["$bar"]}`,
	}
	for i, tc := range []struct {
		phase                  int
		kind, account, subject string
		allowed                bool
	}{
		{0, "stream", "$bar", "foo", false},
		{0, "stream", "$bar", "*", false},
		{0, "stream", "$bar", ">", false},
		{0, "stream", "$bar", "foo.*", false},
		{0, "stream", "$bar", "foo.>", false},
		{1, "stream", "$bar", "foo", true},
		{1, "stream", "$bar", "bar", false},
		{1, "stream", "$bar", "*", false},
		{2, "stream", "$bar", "foo", true},
		{2, "stream", "$bar", "bar", true},
		{2, "stream", "$bar", "baz", true},
		{2, "stream", "$bar", "foo.bar", false},
		{2, "stream", "$bar", ">", false},
		{2, "stream", "$bar", "*", true},
		{2, "stream", "$bar", "foo.*", false},
		{2, "stream", "$bar", "*.*", false},
		{2, "stream", "$bar", "*.>", false},
		{3, "stream", "$bar", "foo", true},
		{3, "stream", "$bar", "bar", true},
		{3, "stream", "$bar", "baz", true},
		{3, "stream", "$bar", "foo.bar", true},
		{3, "stream", "$bar", ">", true},
		{3, "stream", "$bar", "*", true},
		{3, "stream", "$bar", "foo.*", true},
		{3, "stream", "$bar", "*.*", true},
		{3, "stream", "$bar", "*.>", true},
		{4, "stream", "$bar", "foo.$bar", true},
		{4, "stream", "$bar", "bar.$bar.foo", true},
		{4, "stream", "$bar", "baz.foo.$bar", false},
		{4, "stream", "$bar", "foo.X", false},
		{4, "stream", "$bar", "bar.X.foo", false},
		{4, "stream", "$bar", "baz.foo.X", false},
		{5, "service", "$bar", "a.$bar", true},
		{5, "service", "$bar", "b.$bar.a", true},
		{5, "service", "$bar", "c.a.$bar", false},
		{5, "service", "$bar", "a.X", false},
		{5, "service", "$bar", "b.X.a", false},
		{5, "service", "$bar", "c.a.X", false},
		{6, "stream", "$bar", "foo.bar.baz.1", true},
		{6, "stream", "$bar", "foo.bar.baz.*", true},
		{6, "stream", "$bar", "foo.*.baz.1.1", true},
		{6, "stream", "$bar", "foo.22.baz.22", true},
		{6, "stream", "$bar", "foo.bar.baz", false},
		{6, "stream", "$bar", "", false},
		{6, "stream", "$bar", "foo.bar.*.*", false},
		{6, "stream", "foobar", "foo.bar.baz.1", false},
		{6, "stream", "baz", "foo.bar.baz.1", false},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			config := fmt.Sprintf(`accounts {
    "$foo" {users: [{user: foo,password: foo}],exports: [%s]}
    %q {users: [{user: importer,password: importer}],imports: [{%s: {account: "$foo",subject: %q}}]}
   }`, exports[tc.phase], tc.account, tc.kind, tc.subject)
			if tc.account != "$bar" {
				config = fmt.Sprintf(`accounts {
     "$foo" {exports: [%s]}
     "$bar" {}
     %q {imports: [{%s: {account: "$foo",subject: %q}}]}
    }`, exports[tc.phase], tc.account, tc.kind, tc.subject)
			}
			if !tc.allowed {
				requireAccountStartupRejected(t, config, "")
				return
			}
			s := runAccountProtocolServer(t, config)
			require_Equal(t, len(accountInfoOverHTTP(t, s, tc.account).Account.Imports), 1)
			publisher := natsConnect(t, s.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
			defer publisher.Close()
			client := natsConnect(t, s.ClientURL(), nats.UserInfo("importer", "importer"), nats.NoReconnect())
			defer client.Close()
			literal := strings.ReplaceAll(tc.subject, "*", "one")
			literal = strings.ReplaceAll(literal, ">", "two")
			if tc.kind == "stream" {
				observed := natsSubSync(t, client, tc.subject)
				require_NoError(t, client.FlushTimeout(2*time.Second))
				natsPub(t, publisher, literal, []byte(tc.subject))
				msg := natsNexMsg(t, observed, 2*time.Second)
				require_Equal(t, msg.Subject, literal)
				require_Equal(t, string(msg.Data), tc.subject)
			} else {
				requests := natsSubSync(t, publisher, tc.subject)
				replies := natsSubSync(t, client, nats.NewInbox())
				require_NoError(t, publisher.FlushTimeout(2*time.Second))
				require_NoError(t, client.FlushTimeout(2*time.Second))
				natsPubReq(t, client, literal, replies.Subject, []byte(tc.subject))
				request := natsNexMsg(t, requests, 2*time.Second)
				require_Equal(t, request.Subject, literal)
				require_Equal(t, string(request.Data), tc.subject)
				natsPub(t, publisher, request.Reply, []byte("authorized reply"))
				require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "authorized reply")
			}
		})
	}
	for _, kind := range []string{"stream", "service"} {
		t.Run(kind+" invalid account token position", func(t *testing.T) {
			requireAccountStartupRejected(t, fmt.Sprintf(`accounts {foo {exports: [{%s: "baz.*.>",account_token_position: 3}]}}`, kind), "")
		})
	}
}

func TestAccountStreamImportRefreshOverTCP(t *testing.T) {
	header := "listen: 127.0.0.1:-1\nhttp: 127.0.0.1:-1\n"
	configFor := func(imports string) string {
		return header + fmt.Sprintf(`accounts {
			foo {users: [{user: foo,password: foo}],exports: [{stream: ">"}]}
			diff_name {users: [{user: diff_name,password: diff_name}],exports: [{stream: ">"}]}
			bar {users: [{user: bar,password: bar}],imports: [%s]}
		}`, imports)
	}
	phases := []struct {
		imports string
		want    map[string]string
	}{
		{`{stream: {account: foo,subject: foo},prefix: myPrefix}`, map[string]string{"foo:foo": "myPrefix.foo"}},
		{`{stream: {account: foo,subject: foo},prefix: myPrefix}`, map[string]string{"foo:foo": "myPrefix.foo"}},
		{`{stream: {account: foo,subject: foo},prefix: myPrefix},{stream: {account: foo,subject: "foo.>"}}`, map[string]string{"foo:foo": "myPrefix.foo", "foo:foo.one": "foo.one"}},
		{`{stream: {account: foo,subject: "foo.>"}},{stream: {account: foo,subject: foo},prefix: myPrefix}`, map[string]string{"foo:foo": "myPrefix.foo", "foo:foo.one": "foo.one"}},
		{`{stream: {account: foo,subject: bar}}`, map[string]string{"foo:bar": "bar"}},
		{`{stream: {account: foo,subject: baz}}`, map[string]string{"foo:baz": "baz"}},
		{`{stream: {account: foo,subject: bar},prefix: prefix}`, map[string]string{"foo:bar": "prefix.bar"}},
		{`{stream: {account: foo,subject: bar},prefix: diff_prefix}`, map[string]string{"foo:bar": "diff_prefix.bar"}},
		{`{stream: {account: diff_name,subject: bar},prefix: prefix}`, map[string]string{"diff_name:bar": "prefix.bar"}},
	}
	config := createConfFile(t, []byte(configFor(phases[0].imports)))
	s, _ := RunServerWithConfig(config)
	defer s.Shutdown()
	client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
	defer client.Close()
	observed := natsSubSync(t, client, ">")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	var publishers []*nats.Conn
	for _, account := range []string{"foo", "diff_name"} {
		nc := natsConnect(t, s.ClientURL(), nats.UserInfo(account, account), nats.NoReconnect())
		defer nc.Close()
		publishers = append(publishers, nc)
	}
	for i, phase := range phases {
		require_NoError(t, os.WriteFile(config, []byte(configFor(phase.imports)), 0600))
		require_NoError(t, s.Reload())
		for j, account := range []string{"foo", "diff_name"} {
			for _, subject := range []string{"foo", "foo.one", "bar", "baz"} {
				natsPub(t, publishers[j], subject, []byte(account+":"+subject))
			}
			require_NoError(t, publishers[j].FlushTimeout(2*time.Second))
		}
		marker := fmt.Sprintf("phase%d", i)
		natsPub(t, client, "local.marker", []byte(marker))
		seen := make(map[string]bool)
		for {
			msg := natsNexMsg(t, observed, 2*time.Second)
			if msg.Subject == "local.marker" {
				require_Equal(t, string(msg.Data), marker)
				break
			}
			key := string(msg.Data)
			destination, ok := phase.want[key]
			require_True(t, ok && !seen[key])
			require_Equal(t, msg.Subject, destination)
			seen[key] = true
		}
		require_Equal(t, len(seen), len(phase.want))
		require_True(t, client.IsConnected())
	}
}

func TestAccountServiceImportMultiplicityOverTCP(t *testing.T) {
	for _, exporter := range []string{"foo", "baz"} {
		t.Run("duplicate "+exporter, func(t *testing.T) {
			requireAccountStartupRejected(t, fmt.Sprintf(`accounts {
				%s {exports: [{service: remote1},{service: remote2}]}
				bar {imports: [{service: {account: %s,subject: remote1},to: foo},{service: {account: %s,subject: remote2},to: foo}]}
			}`, exporter, exporter, exporter), "duplicate")
		})
	}
	configFor := func(active []string) string {
		var imports []string
		for _, account := range active {
			imports = append(imports, fmt.Sprintf(`{service: {account: %s,subject: remote1},to: foo}`, account))
		}
		return "listen: 127.0.0.1:-1\nhttp: 127.0.0.1:-1\n" + fmt.Sprintf(`accounts {
			foo {users: [{user: foo,password: foo}],exports: [{service: remote1}]}
			baz {users: [{user: baz,password: baz}],exports: [{service: remote1}]}
			bat {users: [{user: bat,password: bat}],exports: [{service: remote1}]}
			bar {users: [{user: bar,password: bar}],imports: [%s]}
		}`, strings.Join(imports, ","))
	}
	config := createConfFile(t, []byte(configFor([]string{"foo", "baz", "bat"})))
	s, _ := RunServerWithConfig(config)
	defer s.Shutdown()
	client := natsConnect(t, s.ClientURL(), nats.UserInfo("bar", "bar"), nats.NoReconnect())
	defer client.Close()
	replies := natsSubSync(t, client, "reply")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	var responders []*nats.Conn
	var requests []*nats.Subscription
	for _, account := range []string{"foo", "baz", "bat"} {
		nc := natsConnect(t, s.ClientURL(), nats.UserInfo(account, account), nats.NoReconnect())
		defer nc.Close()
		responders = append(responders, nc)
		requests = append(requests, natsSubSync(t, nc, "remote1"))
		require_NoError(t, nc.FlushTimeout(2*time.Second))
	}
	for i, active := range [][]string{{"foo", "baz", "bat"}, {"foo", "baz", "bat"}, {"foo", "bat"}, {"foo"}, {"foo"}, {}} {
		require_NoError(t, os.WriteFile(config, []byte(configFor(active)), 0600))
		require_NoError(t, s.Reload())
		require_Equal(t, len(accountInfoOverHTTP(t, s, "bar").Account.Imports), len(active))
		payload := fmt.Sprintf("request%d", i)
		natsPubReq(t, client, "foo", "reply", []byte(payload))
		require_NoError(t, client.FlushTimeout(2*time.Second))
		for j, account := range []string{"foo", "baz", "bat"} {
			natsPub(t, responders[j], "remote1", []byte("local marker"))
			if slices.Contains(active, account) {
				request := natsNexMsg(t, requests[j], 2*time.Second)
				require_Equal(t, string(request.Data), payload)
				require_True(t, strings.HasPrefix(request.Reply, "_R_."))
				natsPub(t, responders[j], request.Reply, []byte(account))
			}
			require_Equal(t, string(natsNexMsg(t, requests[j], 2*time.Second).Data), "local marker")
			require_NoError(t, responders[j].FlushTimeout(2*time.Second))
		}
		seen := make(map[string]bool)
		for range active {
			account := string(natsNexMsg(t, replies, 2*time.Second).Data)
			require_True(t, slices.Contains(active, account) && !seen[account])
			seen[account] = true
		}
		natsPub(t, client, "reply", []byte("reply marker"))
		require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "reply marker")
	}
}

func runAccountClaimsProtocolServer(t *testing.T, claims ...*jwt.AccountClaims) (*Server, nats.Option) {
	t.Helper()
	sysKP, sysAccount, sysClaim := NewJwtAccountClaim("sys")
	preload := map[string]string{sysAccount: encodeClaim(t, sysClaim, sysAccount)}
	for _, claim := range claims {
		preload[claim.Subject] = encodeClaim(t, claim, claim.Subject)
	}
	encoded, err := json.Marshal(preload)
	require_NoError(t, err)
	s := runAccountProtocolServer(t, fmt.Sprintf(`
		operator: %s
		system_account: %s
		resolver: {type: full,dir: %q,allow_delete: true}
		resolver_preload: %s
		jetstream: {store_dir: %q,max_mem_store: 64Mb,max_file_store: 64Mb}
	`, ojwt, sysAccount, t.TempDir(), encoded, t.TempDir()))
	return s, createUserCredsEx(t, jwt.NewUserClaims("sys"), sysKP)
}

func updateAccountClaimOverTCP(nc *nats.Conn, account, token string) error {
	msg, err := nc.Request(fmt.Sprintf("$SYS.REQ.ACCOUNT.%s.CLAIMS.UPDATE", account), []byte(token), 2*time.Second)
	if err != nil {
		return err
	}
	var response ServerAPIClaimUpdateResponse
	if err := json.Unmarshal(msg.Data, &response); err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("account update refused: %+v", response.Error)
	}
	if response.Data == nil || response.Data.Account != account || response.Data.Code != 200 {
		return fmt.Errorf("unexpected account update: %s", msg.Data)
	}
	return nil
}

func TestAccountDefaultPermissionsAdmissionRaceOverTCP(t *testing.T) {
	kp, account, claim := NewJwtAccountClaim("account")
	claim.DefaultPermissions.Pub.Allow.Add("allowed", "even")
	claim.DefaultPermissions.Sub.Allow.Add(">")
	user := jwt.NewUserClaims("inherited")
	creds := createUserCredsEx(t, user, kp)
	explicit := jwt.NewUserClaims("explicit")
	explicit.Permissions.Pub.Allow.Add("explicit")
	explicit.Permissions.Sub.Allow.Add(">")
	explicitCreds := createUserCredsEx(t, explicit, kp)
	var tokens []string
	for i := range 1000 {
		claim.Name = fmt.Sprintf("refresh%d", i)
		phase := "even"
		if i%2 != 0 {
			phase = "odd"
		}
		claim.DefaultPermissions.Pub.Allow = jwt.StringList{"allowed", phase}
		tokens = append(tokens, encodeClaim(t, claim, account))
	}
	s, sysCreds := runAccountClaimsProtocolServer(t, claim)
	sc := natsConnect(t, s.ClientURL(), sysCreds, nats.NoReconnect())
	defer sc.Close()
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 1000 {
			nc, err := nats.Connect(s.ClientURL(), creds, nats.NoReconnect(), nats.Timeout(2*time.Second))
			if err != nil {
				results <- err
				return
			}
			sub, err := nc.SubscribeSync("allowed")
			if err == nil {
				err = nc.FlushTimeout(2 * time.Second)
			}
			if err == nil {
				err = nc.Publish("allowed", []byte("inherited"))
			}
			if err == nil {
				var msg *nats.Msg
				msg, err = sub.NextMsg(2 * time.Second)
				if err == nil && string(msg.Data) != "inherited" {
					err = fmt.Errorf("unexpected inherited payload: %q", msg.Data)
				}
			}
			nc.Close()
			if err != nil {
				results <- err
				return
			}
		}
		results <- nil
	})
	workers.Go(func() {
		for _, token := range tokens {
			if err := updateAccountClaimOverTCP(sc, account, token); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	})
	workers.Wait()
	for range 2 {
		require_NoError(t, <-results)
	}
	for _, tc := range []struct {
		creds           nats.Option
		allowed, denied string
	}{{creds, "odd", "even"}, {explicitCreds, "explicit", "allowed"}} {
		violations := make(chan error, 1)
		nc := natsConnect(t, s.ClientURL(), tc.creds, nats.NoReconnect(), nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { violations <- err }))
		defer nc.Close()
		sub := natsSubSync(t, nc, ">")
		require_NoError(t, nc.FlushTimeout(2*time.Second))
		natsPub(t, nc, tc.allowed, []byte("allowed"))
		require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), "allowed")
		natsPub(t, nc, tc.denied, []byte("denied"))
		require_NoError(t, nc.FlushTimeout(2*time.Second))
		select {
		case err := <-violations:
			require_True(t, errors.Is(err, nats.ErrPermissionViolation))
			require_Contains(t, err.Error(), fmt.Sprintf("%q", tc.denied))
		case <-time.After(2 * time.Second):
			t.Fatal("missing inherited/explicit permission refusal")
		}
		natsPub(t, nc, tc.allowed, []byte("marker"))
		require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), "marker")
	}
}

func deleteAccountClaimsOverTCP(nc *nats.Conn, signer nkeys.KeyPair, accounts ...string) error {
	issuer, err := signer.PublicKey()
	if err != nil {
		return err
	}
	claim := jwt.NewGenericClaims(issuer)
	claim.Data["accounts"] = accounts
	token, err := claim.Encode(signer)
	if err != nil {
		return err
	}
	msg, err := nc.Request("$SYS.REQ.CLAIMS.DELETE", []byte(token), 2*time.Second)
	if err != nil {
		return err
	}
	var response ServerAPIClaimUpdateResponse
	if err := json.Unmarshal(msg.Data, &response); err != nil {
		return err
	}
	if response.Error != nil {
		return fmt.Errorf("account deletion refused: %+v", response.Error)
	}
	if response.Data == nil || response.Data.Code != 200 {
		return fmt.Errorf("unexpected account deletion: %s", msg.Data)
	}
	return nil
}

func TestAccountJetStreamRemovalLifecycleOverTCP(t *testing.T) {
	var claims []*jwt.AccountClaims
	var keys []nkeys.KeyPair
	for i := range 50 {
		kp, _, claim := NewJwtAccountClaim(fmt.Sprintf("account%d", i))
		claim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 65536, DiskStorage: 65536, Streams: 1, Consumer: 1}
		claims = append(claims, claim)
		keys = append(keys, kp)
	}
	s, sysCreds := runAccountClaimsProtocolServer(t, claims...)
	sc := natsConnect(t, s.ClientURL(), sysCreds, nats.NoReconnect())
	defer sc.Close()
	for i, claim := range claims {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			creds := createUserCredsEx(t, jwt.NewUserClaims("tenant"), keys[i])
			closed := make(chan struct{})
			nc := natsConnect(t, s.ClientURL(), creds, nats.NoReconnect(), nats.ClosedHandler(func(_ *nats.Conn) { close(closed) }))
			defer nc.Close()
			js, err := nc.JetStream(nats.MaxWait(2 * time.Second))
			require_NoError(t, err)
			_, err = js.AddStream(&nats.StreamConfig{Name: "S", Subjects: []string{"work"}, Storage: nats.MemoryStorage})
			require_NoError(t, err)
			_, err = js.Publish("work", []byte("before deletion"))
			require_NoError(t, err)
			require_True(t, accountInfoOverHTTP(t, s, claim.Subject).Account.JetStream)
			if i == 0 {
				require_Error(t, deleteAccountClaimsOverTCP(sc, keys[i], claim.Subject))
				_, err = js.AccountInfo()
				require_NoError(t, err)
			}
			started, finished, stop := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				defer close(finished)
				first := true
				for {
					if _, err := js.AccountInfo(); err != nil {
						return
					}
					if first {
						close(started)
						first = false
					}
					select {
					case <-stop:
						return
					default:
					}
				}
			}()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("JetStream reader did not reach the live account")
			}
			require_NoError(t, deleteAccountClaimsOverTCP(sc, oKp, claim.Subject))
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("deleted JetStream tenant stayed connected")
			}
			close(stop)
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("JetStream reader stayed blocked after deletion")
			}
			checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
				if accountInfoOverHTTP(t, s, claim.Subject).Account.JetStream {
					return fmt.Errorf("deleted account still exposes JetStream")
				}
				return nil
			})
			rejected, err := nats.Connect(s.ClientURL(), creds, nats.NoReconnect(), nats.Timeout(2*time.Second))
			if rejected != nil {
				rejected.Close()
			}
			require_Error(t, err)
			claim.Name = fmt.Sprintf("restored%d", i)
			require_NoError(t, updateAccountClaimOverTCP(sc, claim.Subject, encodeClaim(t, claim, claim.Subject)))
			renewed := natsConnect(t, s.ClientURL(), creds, nats.NoReconnect())
			defer renewed.Close()
			js, err = renewed.JetStream(nats.MaxWait(2 * time.Second))
			require_NoError(t, err)
			_, err = js.AccountInfo()
			require_NoError(t, err)
		})
	}
}

func TestAccountServiceRemovalConcurrentRefreshOverTCP(t *testing.T) {
	exporterKP, exporter, exportClaim := NewJwtAccountClaim("exporter")
	importerKP, importer, importClaim := NewJwtAccountClaim("importer")
	for i := range 8 {
		subject := jwt.Subject(fmt.Sprintf("svc.%d", i))
		exportClaim.Exports.Add(&jwt.Export{Subject: subject, Type: jwt.Service})
		importClaim.Imports.Add(&jwt.Import{Account: exporter, Subject: subject, Type: jwt.Service})
	}
	var reads, restores []string
	for i := range 2000 {
		importClaim.Name = fmt.Sprintf("reader%d", i)
		reads = append(reads, encodeClaim(t, importClaim, importer))
	}
	for i := range 50 {
		importClaim.Name = fmt.Sprintf("restore%d", i)
		restores = append(restores, encodeClaim(t, importClaim, importer))
	}
	s, sysCreds := runAccountClaimsProtocolServer(t, exportClaim, importClaim)
	sc := natsConnect(t, s.ClientURL(), sysCreds, nats.NoReconnect())
	defer sc.Close()
	scDelete := natsConnect(t, s.ClientURL(), sysCreds, nats.NoReconnect())
	defer scDelete.Close()
	responder := natsConnect(t, s.ClientURL(), createUserCredsEx(t, jwt.NewUserClaims("responder"), exporterKP), nats.NoReconnect())
	defer responder.Close()
	requests := natsSubSync(t, responder, "svc.*")
	require_NoError(t, responder.FlushTimeout(2*time.Second))
	creds := createUserCredsEx(t, jwt.NewUserClaims("requester"), importerKP)
	client := natsConnect(t, s.ClientURL(), creds, nats.NoReconnect())
	defer client.Close()
	replies := natsSubSync(t, client, "reply")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	natsPubReq(t, client, "svc.0", "reply", []byte("before deletion"))
	request := natsNexMsg(t, requests, 2*time.Second)
	natsPub(t, responder, request.Reply, request.Data)
	require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "before deletion")
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Go(func() {
		for _, token := range reads {
			if err := updateAccountClaimOverTCP(sc, importer, token); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	})
	workers.Go(func() {
		for _, token := range restores {
			if err := deleteAccountClaimsOverTCP(scDelete, oKp, importer); err != nil {
				results <- err
				return
			}
			if err := updateAccountClaimOverTCP(scDelete, importer, token); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	})
	workers.Wait()
	for range 2 {
		require_NoError(t, <-results)
	}
	require_NoError(t, deleteAccountClaimsOverTCP(scDelete, oKp, importer))
	rejected, err := nats.Connect(s.ClientURL(), creds, nats.NoReconnect(), nats.Timeout(2*time.Second))
	if rejected != nil {
		rejected.Close()
	}
	require_Error(t, err)
	importClaim.Name = "final restore"
	require_NoError(t, updateAccountClaimOverTCP(sc, importer, encodeClaim(t, importClaim, importer)))
	client = natsConnect(t, s.ClientURL(), creds, nats.NoReconnect())
	defer client.Close()
	replies = natsSubSync(t, client, "reply")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	for i := range 8 {
		subject := fmt.Sprintf("svc.%d", i)
		natsPubReq(t, client, subject, "reply", []byte(subject))
		request := natsNexMsg(t, requests, 2*time.Second)
		require_Equal(t, request.Subject, subject)
		require_Equal(t, string(request.Data), subject)
		natsPub(t, responder, request.Reply, []byte("reply:"+subject))
		require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "reply:"+subject)
	}
	natsPub(t, client, "reply", []byte("local marker"))
	require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "local marker")
	require_Equal(t, len(accountInfoOverHTTP(t, s, exporter).Account.Responses), 0)
}

func TestAccountRemoteTrackingLatencyRaceOverTCP(t *testing.T) {
	accounts := `system_account: SYS
	accounts {
		SYS {}
		foo {users: [{user: foo,password: foo}],exports: [{service: "track.service",latency: {subject: results,sampling: headers}}]}
		bar {users: [{user: bar,password: bar}],imports: [{service: {account: foo,subject: "track.service"},to: req,share: true}]}
	}`
	a := runAccountProtocolServer(t, "server_name: A\ncluster: {name: latency,listen: 127.0.0.1:-1}\n"+accounts)
	b := runAccountProtocolServer(t, fmt.Sprintf("server_name: B\ncluster: {name: latency,listen: 127.0.0.1:-1,routes: [nats://%s]}\n%s", a.ClusterAddr().String(), accounts))
	checkClusterFormed(t, a, b)
	responder := natsConnect(t, b.ClientURL(), nats.UserInfo("foo", "foo"), nats.Name("responder"), nats.NoReconnect())
	defer responder.Close()
	requests := natsSubSync(t, responder, "track.service")
	require_NoError(t, responder.FlushTimeout(2*time.Second))
	observer := natsConnect(t, a.ClientURL(), nats.UserInfo("foo", "foo"), nats.NoReconnect())
	defer observer.Close()
	metrics := natsSubSync(t, observer, "results")
	require_NoError(t, observer.FlushTimeout(2*time.Second))
	checkSubInterest(t, a, "foo", "track.service", 2*time.Second)
	client := natsConnect(t, a.ClientURL(), nats.UserInfo("bar", "bar"), nats.Name("requester"), nats.NoReconnect())
	defer client.Close()
	replies := natsSubSync(t, client, "reply")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	for i := range 1000 {
		id := strconv.Itoa(i)
		require_NoError(t, client.PublishMsg(&nats.Msg{Subject: "req", Reply: "reply", Data: []byte(id), Header: nats.Header{"X-B3-Traceid": []string{id}, "X-B3-Sampled": []string{"1"}}}))
	}
	for i := range 1000 {
		request := natsNexMsg(t, requests, 2*time.Second)
		require_Equal(t, request.Subject, "track.service")
		require_Equal(t, string(request.Data), strconv.Itoa(i))
		natsPub(t, responder, request.Reply, request.Data)
	}
	for i := range 1000 {
		require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), strconv.Itoa(i))
	}
	seen := make(map[string]bool)
	for range 1000 {
		metric := natsNexMsg(t, metrics, 2*time.Second)
		var latency ServiceLatency
		require_NoError(t, json.Unmarshal(metric.Data, &latency))
		require_Equal(t, latency.Status, 200)
		require_NotNil(t, latency.Requestor)
		require_NotNil(t, latency.Responder)
		require_Equal(t, latency.Requestor.Name, "requester")
		require_Equal(t, latency.Responder.Name, "responder")
		require_NotEqual(t, latency.Requestor.Server, latency.Responder.Server)
		id := latency.RequestHeader.Get("X-B3-Traceid")
		index, err := strconv.Atoi(id)
		require_NoError(t, err)
		require_True(t, index >= 0 && index < 1000 && !seen[id])
		seen[id] = true
		require_True(t, latency.TotalLatency >= latency.ServiceLatency)
	}
	require_Equal(t, len(seen), 1000)
	require_Equal(t, len(accountInfoOverHTTP(t, a, "foo").Account.Responses), 0)
}

func TestAccountRemoteLimitEvictionOverTCP(t *testing.T) {
	configFor := func(routes string) string {
		return fmt.Sprintf(`listen: 127.0.0.1:-1
			http: 127.0.0.1:-1
			server_name: A
			cluster: {name: limits,listen: 127.0.0.1:-1,routes: [%s]}
			system_account: SYS
			accounts {
				SYS {users: [{user: sys,password: sys}]}
				TENANT {users: [{user: tenant,password: tenant}],limits: {max_connections: 5}}
			}`, routes)
	}
	config := createConfFile(t, []byte(configFor("")))
	a, _ := RunServerWithConfig(config)
	defer a.Shutdown()
	// The original contract caps the local account; the remote peer keeps its four real connections.
	b := runAccountProtocolServer(t, `server_name: B
		cluster: {name: limits,listen: 127.0.0.1:-1}
		system_account: SYS
		accounts {
			SYS {users: [{user: sys,password: sys}]}
			TENANT {users: [{user: tenant,password: tenant}]}
		}`)
	var local, remote []*nats.Conn
	for range 3 {
		nc := natsConnect(t, a.ClientURL(), nats.UserInfo("tenant", "tenant"), nats.NoReconnect())
		defer nc.Close()
		local = append(local, nc)
		require_NoError(t, nc.FlushTimeout(2*time.Second))
	}
	for range 4 {
		nc := natsConnect(t, b.ClientURL(), nats.UserInfo("tenant", "tenant"), nats.NoReconnect())
		defer nc.Close()
		remote = append(remote, nc)
		require_NoError(t, nc.FlushTimeout(2*time.Second))
	}
	observer := natsConnect(t, a.ClientURL(), nats.UserInfo("sys", "sys"), nats.NoReconnect())
	defer observer.Close()
	events := natsSubSync(t, observer, "$SYS.ACCOUNT.TENANT.CONNS")
	require_NoError(t, observer.FlushTimeout(2*time.Second))
	require_NoError(t, os.WriteFile(config, []byte(configFor("nats://"+b.ClusterAddr().String())), 0600))
	require_NoError(t, a.Reload())
	checkClusterFormed(t, a, b)
	deadline := time.Now().Add(2 * time.Second)
	for {
		remaining := time.Until(deadline)
		require_True(t, remaining > 0)
		msg := natsNexMsg(t, events, remaining)
		var count AccountNumConns
		require_NoError(t, json.Unmarshal(msg.Data, &count))
		if count.Server.ID == b.ID() && count.Conns == 4 {
			break
		}
	}
	checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
		if !local[1].IsClosed() || !local[2].IsClosed() {
			return fmt.Errorf("newest local clients stayed connected")
		}
		return nil
	})
	require_True(t, local[0].IsConnected())
	for _, nc := range remote {
		require_True(t, nc.IsConnected())
	}
	require_Equal(t, accountInfoOverHTTP(t, a, "TENANT").Account.ClientCnt, 1)
	require_Equal(t, accountInfoOverHTTP(t, b, "TENANT").Account.ClientCnt, 4)
	sub := natsSubSync(t, local[0], "survivor")
	require_NoError(t, local[0].FlushTimeout(2*time.Second))
	natsPub(t, local[0], "survivor", []byte("oldest survived"))
	require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), "oldest survived")
}

func TestAccountStaleActivationExpiryOverTCP(t *testing.T) {
	exporterKP, exporter, exportClaim := NewJwtAccountClaim("exporter")
	otherKP, other, otherClaim := NewJwtAccountClaim("other")
	importerKP, importer, importClaim := NewJwtAccountClaim("importer")
	exportClaim.Exports.Add(&jwt.Export{Subject: "private", Type: jwt.Stream, TokenReq: true})
	otherClaim.Exports.Add(&jwt.Export{Subject: "other.subject", Type: jwt.Stream})
	activation := jwt.NewActivationClaims(importer)
	activation.IssuerAccount, activation.ImportSubject, activation.ImportType = exporter, "private", jwt.Stream
	activation.Expires = time.Now().Unix() + 3
	token, err := activation.Encode(exporterKP)
	require_NoError(t, err)
	private := &jwt.Import{Account: exporter, Subject: "private", Type: jwt.Stream, Token: token}
	public := &jwt.Import{Account: other, Subject: "other.subject", Type: jwt.Stream}
	importClaim.Imports.Add(private, public)
	s, sysCreds := runAccountClaimsProtocolServer(t, exportClaim, otherClaim, importClaim)
	sc := natsConnect(t, s.ClientURL(), sysCreds, nats.NoReconnect())
	defer sc.Close()
	exporterClient := natsConnect(t, s.ClientURL(), createUserCredsEx(t, jwt.NewUserClaims("exporter"), exporterKP), nats.NoReconnect())
	defer exporterClient.Close()
	otherClient := natsConnect(t, s.ClientURL(), createUserCredsEx(t, jwt.NewUserClaims("other"), otherKP), nats.NoReconnect())
	defer otherClient.Close()
	client := natsConnect(t, s.ClientURL(), createUserCredsEx(t, jwt.NewUserClaims("importer"), importerKP), nats.NoReconnect())
	defer client.Close()
	privateSub := natsSubSync(t, client, "private")
	publicSub := natsSubSync(t, client, "other.subject")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	natsPub(t, exporterClient, "private", []byte("activation admitted"))
	require_Equal(t, string(natsNexMsg(t, privateSub, 2*time.Second).Data), "activation admitted")
	natsPub(t, otherClient, "other.subject", []byte("public baseline"))
	require_Equal(t, string(natsNexMsg(t, publicSub, 2*time.Second).Data), "public baseline")
	importClaim.Imports = jwt.Imports{public}
	importClaim.Name = "private import removed"
	require_NoError(t, updateAccountClaimOverTCP(sc, importer, encodeClaim(t, importClaim, importer)))
	// checkActivation retains its AfterFunc closure without a cancel handle when this import is removed.
	time.Sleep(time.Until(time.Unix(activation.Expires, 0).Add(time.Second + 100*time.Millisecond)))
	for _, im := range accountInfoOverHTTP(t, s, importer).Account.Imports {
		if im.Account == other && im.Subject == "other.subject" {
			require_False(t, im.Invalid)
		}
	}
	natsPub(t, otherClient, "other.subject", []byte("unrelated import survives stale expiry"))
	require_Equal(t, string(natsNexMsg(t, publicSub, 2*time.Second).Data), "unrelated import survives stale expiry")
	natsPub(t, exporterClient, "private", []byte("removed import leaked"))
	require_NoError(t, exporterClient.FlushTimeout(2*time.Second))
	natsPub(t, client, "private", []byte("local marker"))
	require_Equal(t, string(natsNexMsg(t, privateSub, 2*time.Second).Data), "local marker")
}

func TestAccountServiceImportConcurrencyOverTCP(t *testing.T) {
	exporterKP, exporter, exportClaim := NewJwtAccountClaim("exporter")
	importerKP, importer, importClaim := NewJwtAccountClaim("importer")
	exportClaim.Exports.Add(&jwt.Export{Subject: "svc.>", Type: jwt.Service})
	s, sysCreds := runAccountClaimsProtocolServer(t, exportClaim, importClaim)
	var tokens []string
	for i := range 100 {
		importClaim.Imports.Add(&jwt.Import{Account: exporter, Subject: jwt.Subject(fmt.Sprintf("svc.%d", i)), Type: jwt.Service})
		importClaim.Name = fmt.Sprintf("imports%d", i+1)
		tokens = append(tokens, encodeClaim(t, importClaim, importer))
	}
	results := make(chan error, 100)
	var workers sync.WaitGroup
	for _, token := range tokens {
		workers.Go(func() {
			sc, err := nats.Connect(s.ClientURL(), sysCreds, nats.NoReconnect(), nats.Timeout(2*time.Second))
			if err != nil {
				results <- err
				return
			}
			defer sc.Close()
			results <- updateAccountClaimOverTCP(sc, importer, token)
		})
	}
	workers.Wait()
	for range 100 {
		require_NoError(t, <-results)
	}
	sc := natsConnect(t, s.ClientURL(), sysCreds, nats.NoReconnect())
	defer sc.Close()
	importClaim.Name = "final100"
	require_NoError(t, updateAccountClaimOverTCP(sc, importer, encodeClaim(t, importClaim, importer)))
	imports := make(map[jwt.Subject]bool)
	for _, im := range accountInfoOverHTTP(t, s, importer).Account.Imports {
		if im.Account == exporter {
			require_False(t, im.Invalid)
			require_False(t, imports[im.Subject])
			imports[im.Subject] = true
		}
	}
	require_Equal(t, len(imports), 100)
	responder := natsConnect(t, s.ClientURL(), createUserCredsEx(t, jwt.NewUserClaims("responder"), exporterKP), nats.NoReconnect())
	defer responder.Close()
	requests := natsSubSync(t, responder, "svc.>")
	require_NoError(t, responder.FlushTimeout(2*time.Second))
	client := natsConnect(t, s.ClientURL(), createUserCredsEx(t, jwt.NewUserClaims("requester"), importerKP), nats.NoReconnect())
	defer client.Close()
	replies := natsSubSync(t, client, "reply")
	require_NoError(t, client.FlushTimeout(2*time.Second))
	for i := range 100 {
		subject := fmt.Sprintf("svc.%d", i)
		require_True(t, imports[jwt.Subject(subject)])
		natsPubReq(t, client, subject, "reply", []byte(subject))
		request := natsNexMsg(t, requests, 2*time.Second)
		require_Equal(t, request.Subject, subject)
		require_Equal(t, string(request.Data), subject)
		natsPub(t, responder, request.Reply, []byte("reply:"+subject))
		require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), "reply:"+subject)
	}
	natsPubReq(t, client, "svc.unimported", "reply", []byte("must not forward"))
	require_NoError(t, client.FlushTimeout(2*time.Second))
	natsPub(t, responder, "svc.unimported", []byte("local marker"))
	require_Equal(t, string(natsNexMsg(t, requests, 2*time.Second).Data), "local marker")
}

func TestAccountConfiguredImportsExportsOverTCP(t *testing.T) {
	data, err := os.ReadFile("./configs/accounts.conf")
	require_NoError(t, err)
	config := string(data)
	var credentials []nats.Option
	for _, original := range []string{
		"UC6NLCN7AS34YOJVCYD4PJ3QB7QGLYG5B5IMBT25VW5K4TNUJODM7BOX",
		"UBAAQWTW6CG2G6ANGNKB5U2B7HRWHSGMZEZX3AQSAJOQDAUGJD46LD2E",
		"UBRYMDSRTC6AVJL6USKKS3FIOE466GMEU67PZDGOWYSYHWA7GSKO42VW",
		"UDEREK22W43P2NFQCSKGM6BWD23OVWEDR7JE7LSNCD232MZIC4X2MEKZ",
	} {
		// The checked-in fixture has public keys only; fresh identities preserve all four account bindings.
		kp, err := nkeys.CreateUser()
		require_NoError(t, err)
		pub, err := kp.PublicKey()
		require_NoError(t, err)
		config = strings.ReplaceAll(config, original, pub)
		credentials = append(credentials, nats.Nkey(pub, func(nonce []byte) ([]byte, error) { return kp.Sign(nonce) }))
	}
	s := runAccountProtocolServer(t, config)
	for _, tc := range []struct {
		account          string
		streams, service int
		exports          int
	}{{"synadia", 0, 1, 4}, {"nats.io", 2, 1, 4}, {"cncf", 0, 0, 0}} {
		info := accountInfoOverHTTP(t, s, tc.account).Account
		streams, service := 0, 0
		for _, im := range info.Imports {
			if im.Type == jwt.Stream {
				streams++
			} else if im.Type == jwt.Service {
				service++
			}
		}
		require_Equal(t, streams, tc.streams)
		require_Equal(t, service, tc.service)
		require_Equal(t, len(info.Exports), tc.exports)
	}
	for _, export := range accountInfoOverHTTP(t, s, "nats.io").Account.Exports {
		want, ok := map[jwt.Subject]jwt.ResponseType{"nats.time": "Streamed", "nats.photo": "Chunked", "nats.add": "Singleton", "nats.sub": "Singleton"}[export.Subject]
		require_True(t, ok)
		require_Equal(t, export.ResponseType, want)
	}
	var clients []*nats.Conn
	var probes []*nats.Subscription
	for i, creds := range credentials {
		account := "synadia"
		if i >= 2 {
			account = "nats.io"
		}
		nc := natsConnect(t, s.ClientURL(), creds, nats.Name(account), nats.NoReconnect())
		defer nc.Close()
		clients = append(clients, nc)
		probes = append(probes, natsSubSync(t, nc, "binding"))
		require_NoError(t, nc.FlushTimeout(2*time.Second))
	}
	for i, nc := range clients {
		natsPub(t, nc, "binding", []byte(strconv.Itoa(i)))
		for j, sub := range probes {
			if i/2 == j/2 {
				require_Equal(t, string(natsNexMsg(t, sub, 2*time.Second).Data), strconv.Itoa(i))
			}
		}
	}
	for i, nc := range clients {
		require_NoError(t, nc.FlushTimeout(2*time.Second))
		pending, _, err := probes[i].Pending()
		require_NoError(t, err)
		require_Equal(t, pending, 0)
	}
	for _, tc := range []struct {
		subject, mapped string
		trace           bool
	}{{"public.synadia", "imports.synadia.public.synadia", true}, {"synadia.private.one", "synadia.private.one", false}} {
		sub := natsSubSync(t, clients[2], tc.mapped)
		trace := natsSubSync(t, clients[0], "trace.stream")
		require_NoError(t, clients[2].FlushTimeout(2*time.Second))
		require_NoError(t, clients[0].FlushTimeout(2*time.Second))
		msg := &nats.Msg{Subject: tc.subject, Data: []byte(tc.subject), Header: nats.Header{MsgTraceDest: []string{trace.Subject}}}
		require_NoError(t, clients[0].PublishMsg(msg))
		received := natsNexMsg(t, sub, 2*time.Second)
		require_Equal(t, received.Subject, tc.mapped)
		require_Equal(t, string(received.Data), tc.subject)
		var event MsgTraceEvent
		require_NoError(t, json.Unmarshal(natsNexMsg(t, trace, 2*time.Second).Data, &event))
		require_Equal(t, len(event.StreamExports()), 1)
		if tc.trace {
			require_Equal(t, len(event.Egresses()), 1)
			require_Equal(t, event.Egresses()[0].Account, "nats.io")
		} else {
			require_Equal(t, len(event.Egresses()), 0)
		}
		require_NoError(t, sub.Unsubscribe())
		require_NoError(t, trace.Unsubscribe())
	}
	for _, tc := range []struct {
		requester, responder int
		local, destination   string
		responses            int
		trace                bool
	}{{0, 2, "nats.time", "nats.time", 3, true}, {2, 0, "synadia.request", "pub.special.request", 1, false}} {
		requester, responder := clients[tc.requester], clients[tc.responder]
		requests := natsSubSync(t, responder, tc.destination)
		replies := natsSubSync(t, requester, "reply")
		trace := natsSubSync(t, requester, "trace.service")
		require_NoError(t, responder.FlushTimeout(2*time.Second))
		require_NoError(t, requester.FlushTimeout(2*time.Second))
		require_NoError(t, requester.PublishMsg(&nats.Msg{Subject: tc.local, Reply: "reply", Data: []byte("help"), Header: nats.Header{MsgTraceDest: []string{trace.Subject}}}))
		request := natsNexMsg(t, requests, 2*time.Second)
		require_Equal(t, request.Subject, tc.destination)
		require_Equal(t, string(request.Data), "help")
		for i := range tc.responses {
			natsPub(t, responder, request.Reply, []byte(strconv.Itoa(i)))
			require_Equal(t, string(natsNexMsg(t, replies, 2*time.Second).Data), strconv.Itoa(i))
		}
		var event MsgTraceEvent
		require_NoError(t, json.Unmarshal(natsNexMsg(t, trace, 2*time.Second).Data, &event))
		require_Equal(t, len(event.ServiceImports()), 1)
		if tc.trace {
			require_Equal(t, len(event.Egresses()), 1)
		} else {
			require_Equal(t, len(event.Egresses()), 0)
		}
		require_NoError(t, requests.Unsubscribe())
		require_NoError(t, replies.Unsubscribe())
		require_NoError(t, trace.Unsubscribe())
	}
}

func TestRegisterDuplicateAccounts(t *testing.T) {
	s, _, _ := simpleAccountServer(t)
	if _, err := s.RegisterAccount("$foo"); err == nil {
		t.Fatal("Expected an error registering 'foo' twice")
	}
}

func TestAccountIsolation(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	cfoo, crFoo, _ := newClientForServer(s)
	defer cfoo.close()
	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error register client with 'foo' account: %v", err)
	}
	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()
	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error register client with 'bar' account: %v", err)
	}

	// Make sure they are different accounts/sl.
	if cfoo.acc == cbar.acc {
		t.Fatalf("Error, accounts the same for both clients")
	}

	// Now do quick test that makes sure messages do not cross over.
	// setup bar as a foo subscriber.
	cbar.parseAsync("SUB foo 1\r\nPING\r\nPING\r\n")
	l, err := crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response incorrect: %q", l)
	}

	cfoo.parseAsync("SUB foo 1\r\nPUB foo 5\r\nhello\r\nPING\r\n")
	l, err = crFoo.ReadString('\n')
	if err != nil {
		t.Fatalf("Error for client 'foo' from server: %v", err)
	}

	matches := msgPat.FindAllStringSubmatch(l, -1)[0]
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'\n", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crFoo, []byte("hello\r\n"), t)

	// Now make sure nothing shows up on bar.
	l, err = crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response incorrect: %q", l)
	}
}

func TestAccountIsolationExportImport(t *testing.T) {
	checkIsolation := func(t *testing.T, pubSubj string, ncExp, ncImp *nats.Conn) {
		// We keep track of 2 subjects.
		// One subject (pubSubj) is based off the stream import.
		// The other subject "fizz" is not imported and should be isolated.

		gotSubjs := map[string]int{
			pubSubj: 0,
			"fizz":  0,
		}
		count := int32(0)
		ch := make(chan struct{}, 1)
		if _, err := ncImp.Subscribe(">", func(m *nats.Msg) {
			gotSubjs[m.Subject] += 1
			if n := atomic.AddInt32(&count, 1); n == 3 {
				ch <- struct{}{}
			}
		}); err != nil {
			t.Fatalf("Error on subscribe: %v", err)
		}
		// Since both prod and cons use same server, flushing here will ensure
		// that the interest is registered and known at the time we publish.
		ncImp.Flush()

		if err := ncExp.Publish(pubSubj, []byte(fmt.Sprintf("ncExp pub %s", pubSubj))); err != nil {
			t.Fatal(err)
		}
		if err := ncImp.Publish(pubSubj, []byte(fmt.Sprintf("ncImp pub %s", pubSubj))); err != nil {
			t.Fatal(err)
		}

		if err := ncExp.Publish("fizz", []byte("ncExp pub fizz")); err != nil {
			t.Fatal(err)
		}
		if err := ncImp.Publish("fizz", []byte("ncImp pub fizz")); err != nil {
			t.Fatal(err)
		}

		wantSubjs := map[string]int{
			// Subscriber ncImp should receive publishes from ncExp and ncImp.
			pubSubj: 2,
			// Subscriber ncImp should only receive the publish from ncImp.
			"fizz": 1,
		}

		// Wait for at least the 3 expected messages
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("Expected 3 messages, got %v", atomic.LoadInt32(&count))
		}
		// But now wait a bit to see if subscription receives more than expected.
		time.Sleep(50 * time.Millisecond)

		if got, want := len(gotSubjs), len(wantSubjs); got != want {
			t.Fatalf("unexpected subjs len, got=%d; want=%d", got, want)
		}

		for key, gotCnt := range gotSubjs {
			if wantCnt := wantSubjs[key]; gotCnt != wantCnt {
				t.Errorf("unexpected receive count for subject %q, got=%d, want=%d", key, gotCnt, wantCnt)
			}
		}
	}

	cases := []struct {
		name     string
		exp, imp string
		pubSubj  string
	}{
		{
			name: "export literal, import literal",
			exp:  "foo", imp: "foo",
			pubSubj: "foo",
		},
		{
			name: "export full wildcard, import literal",
			exp:  "foo.>", imp: "foo.bar",
			pubSubj: "foo.bar",
		},
		{
			name: "export full wildcard, import sublevel full wildcard",
			exp:  "foo.>", imp: "foo.bar.>",
			pubSubj: "foo.bar.whizz",
		},
		{
			name: "export full wildcard, import full wildcard",
			exp:  "foo.>", imp: "foo.>",
			pubSubj: "foo.bar",
		},
		{
			name: "export partial wildcard, import partial wildcard",
			exp:  "foo.*", imp: "foo.*",
			pubSubj: "foo.bar",
		},
		{
			name: "export mid partial wildcard, import mid partial wildcard",
			exp:  "foo.*.bar", imp: "foo.*.bar",
			pubSubj: "foo.whizz.bar",
		},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s jwt", c.name), func(t *testing.T) {
			// Setup NATS server.
			s := opTrustBasicSetup()
			defer s.Shutdown()
			s.Start()
			if err := s.readyForConnections(5 * time.Second); err != nil {
				t.Fatal(err)
			}
			buildMemAccResolver(s)

			// Setup exporter account.
			accExpPair, accExpPub := createKey(t)
			accExpClaims := jwt.NewAccountClaims(accExpPub)
			if c.exp != "" {
				accExpClaims.Limits.WildcardExports = true
				accExpClaims.Exports.Add(&jwt.Export{
					Name:    fmt.Sprintf("%s-stream-export", c.exp),
					Subject: jwt.Subject(c.exp),
					Type:    jwt.Stream,
				})
			}
			accExpJWT, err := accExpClaims.Encode(oKp)
			require_NoError(t, err)
			addAccountToMemResolver(s, accExpPub, accExpJWT)

			// Setup importer account.
			accImpPair, accImpPub := createKey(t)
			accImpClaims := jwt.NewAccountClaims(accImpPub)
			if c.imp != "" {
				accImpClaims.Imports.Add(&jwt.Import{
					Name:    fmt.Sprintf("%s-stream-import", c.imp),
					Subject: jwt.Subject(c.imp),
					Account: accExpPub,
					Type:    jwt.Stream,
				})
			}
			accImpJWT, err := accImpClaims.Encode(oKp)
			require_NoError(t, err)
			addAccountToMemResolver(s, accImpPub, accImpJWT)

			// Connect with different accounts.
			ncExp := natsConnect(t, s.ClientURL(), createUserCreds(t, nil, accExpPair),
				nats.Name(fmt.Sprintf("nc-exporter-%s", c.exp)))
			defer ncExp.Close()
			ncImp := natsConnect(t, s.ClientURL(), createUserCreds(t, nil, accImpPair),
				nats.Name(fmt.Sprintf("nc-importer-%s", c.imp)))
			defer ncImp.Close()

			checkIsolation(t, c.pubSubj, ncExp, ncImp)
			if t.Failed() {
				t.Logf("exported=%q; imported=%q", c.exp, c.imp)
			}
		})

		t.Run(fmt.Sprintf("%s conf", c.name), func(t *testing.T) {
			// Setup NATS server.
			cf := createConfFile(t, []byte(fmt.Sprintf(`
				port: -1

				accounts: {
					accExp: {
						users: [{user: accExp, password: accExp}]
						exports: [{stream: %q}]
					}
					accImp: {
						users: [{user: accImp, password: accImp}]
						imports: [{stream: {account: accExp, subject: %q}}]
					}
				}
			`,
				c.exp, c.imp,
			)))
			s, _ := RunServerWithConfig(cf)
			defer s.Shutdown()

			// Connect with different accounts.
			ncExp := natsConnect(t, s.ClientURL(), nats.UserInfo("accExp", "accExp"),
				nats.Name(fmt.Sprintf("nc-exporter-%s", c.exp)))
			defer ncExp.Close()
			ncImp := natsConnect(t, s.ClientURL(), nats.UserInfo("accImp", "accImp"),
				nats.Name(fmt.Sprintf("nc-importer-%s", c.imp)))
			defer ncImp.Close()

			checkIsolation(t, c.pubSubj, ncExp, ncImp)
			if t.Failed() {
				t.Logf("exported=%q; imported=%q", c.exp, c.imp)
			}
		})
	}
}

func TestMultiAccountsIsolation(t *testing.T) {
	conf := createConfFile(t, []byte(`
	listen: 127.0.0.1:-1
	accounts: {
		PUBLIC: {
			users:[{user: public, password: public}]
			exports: [
			  { stream: orders.client.stream.> }
			  { stream: orders.client2.stream.> }
			]
		}
		CLIENT: {
			users:[{user: client, password: client}]
			imports: [
			  { stream: { account: PUBLIC, subject: orders.client.stream.> }}
			]
		}
		CLIENT2: {
			users:[{user: client2, password: client2}]
			imports: [
			  { stream: { account: PUBLIC, subject: orders.client2.stream.> }}
			]
		}
	}`))

	s, _ := RunServerWithConfig(conf)
	if config := s.JetStreamConfig(); config != nil {
		defer removeDir(t, config.StoreDir)
	}
	defer s.Shutdown()

	// Create a connection for CLIENT and subscribe on orders.>
	clientnc := natsConnect(t, s.ClientURL(), nats.UserInfo("client", "client"))
	defer clientnc.Close()

	clientsub := natsSubSync(t, clientnc, "orders.>")
	natsFlush(t, clientnc)

	// Now same for CLIENT2.
	client2nc := natsConnect(t, s.ClientURL(), nats.UserInfo("client2", "client2"))
	defer client2nc.Close()

	client2sub := natsSubSync(t, client2nc, "orders.>")
	natsFlush(t, client2nc)

	// Now create a connection for PUBLIC
	publicnc := natsConnect(t, s.ClientURL(), nats.UserInfo("public", "public"))
	defer publicnc.Close()
	// Publish on 'orders.client.stream.entry', so only CLIENT should receive it.
	natsPub(t, publicnc, "orders.client.stream.entry", []byte("test1"))

	// Verify that clientsub gets it.
	msg := natsNexMsg(t, clientsub, time.Second)
	require_Equal(t, string(msg.Data), "test1")

	// And also verify that client2sub does NOT get it.
	_, err := client2sub.NextMsg(100 * time.Microsecond)
	require_Error(t, err, nats.ErrTimeout)

	clientsub.Unsubscribe()
	natsFlush(t, clientnc)
	client2sub.Unsubscribe()
	natsFlush(t, client2nc)

	// Now have both accounts subscribe to "orders.*.stream.entry"
	clientsub = natsSubSync(t, clientnc, "orders.*.stream.entry")
	natsFlush(t, clientnc)

	client2sub = natsSubSync(t, client2nc, "orders.*.stream.entry")
	natsFlush(t, client2nc)

	// Using the PUBLIC account, publish on the "CLIENT" subject
	natsPub(t, publicnc, "orders.client.stream.entry", []byte("test2"))
	natsFlush(t, publicnc)

	msg = natsNexMsg(t, clientsub, time.Second)
	require_Equal(t, string(msg.Data), "test2")

	_, err = client2sub.NextMsg(100 * time.Microsecond)
	require_Error(t, err, nats.ErrTimeout)
}

func TestAccountFromOptions(t *testing.T) {
	opts := defaultServerOptions
	opts.Accounts = []*Account{NewAccount("foo"), NewAccount("bar")}
	s := New(&opts)
	defer s.Shutdown()

	ta := s.numReservedAccounts() + 2
	if la := s.numAccounts(); la != ta {
		t.Fatalf("Expected to have a server with %d active accounts, got %v", ta, la)
	}
	// Check that sl is filled in.
	fooAcc, _ := s.LookupAccount("foo")
	barAcc, _ := s.LookupAccount("bar")
	if fooAcc == nil || barAcc == nil {
		t.Fatalf("Error retrieving accounts for 'foo' and 'bar'")
	}
	if fooAcc.sl == nil || barAcc.sl == nil {
		t.Fatal("Expected Sublists to be filled in on Opts.Accounts")
	}
}

// Clients used to be able to ask that the account be forced to be new.
// This was for dynamic sandboxes for demo environments but was never really used.
// Make sure it always errors if set.
func TestNewAccountAndRequireNewAlwaysError(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		accounts: {
			A: { users: [ {user: ua, password: pa} ] },
			B: { users: [ {user: ub, password: pb} ] },
		}
	`))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// Success case
	c, _, _ := newClientForServer(s)
	connectOp := "CONNECT {\"user\":\"ua\", \"pass\":\"pa\"}\r\n"
	err := c.parse([]byte(connectOp))
	require_NoError(t, err)
	c.close()

	// Simple cases, any setting of account or new_account always errors.
	// Even with proper auth.
	c, cr, _ := newClientForServer(s)
	connectOp = "CONNECT {\"user\":\"ua\", \"pass\":\"pa\", \"account\":\"ANY\"}\r\n"
	c.parseAsync(connectOp)
	l, _ := cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR 'Authorization Violation'") {
		t.Fatalf("Expected an error, got %q", l)
	}
	c.close()

	// new_account with proper credentials.
	c, cr, _ = newClientForServer(s)
	connectOp = "CONNECT {\"user\":\"ua\", \"pass\":\"pa\", \"new_account\":true}\r\n"
	c.parseAsync(connectOp)
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR 'Authorization Violation'") {
		t.Fatalf("Expected an error, got %q", l)
	}
	c.close()

	// switch acccounts with proper credentials.
	c, cr, _ = newClientForServer(s)
	connectOp = "CONNECT {\"user\":\"ua\", \"pass\":\"pa\", \"account\":\"B\"}\r\n"
	c.parseAsync(connectOp)
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR 'Authorization Violation'") {
		t.Fatalf("Expected an error, got %q", l)
	}
	c.close()

	// Even if correct account designation, still make sure we error.
	c, cr, _ = newClientForServer(s)
	connectOp = "CONNECT {\"user\":\"ua\", \"pass\":\"pa\", \"account\":\"A\"}\r\n"
	c.parseAsync(connectOp)
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "-ERR 'Authorization Violation'") {
		t.Fatalf("Expected an error, got %q", l)
	}
	c.close()
}

func accountNameExists(name string, accounts []*Account) bool {
	for _, acc := range accounts {
		if strings.Compare(acc.Name, name) == 0 {
			return true
		}
	}
	return false
}

func TestAccountSimpleConfig(t *testing.T) {
	cfg1 := `
		accounts = [foo, bar]
	`

	confFileName := createConfFile(t, []byte(cfg1))
	opts, err := ProcessConfigFile(confFileName)
	if err != nil {
		t.Fatalf("Received an error processing config file: %v", err)
	}
	if la := len(opts.Accounts); la != 2 {
		t.Fatalf("Expected to see 2 accounts in opts, got %d", la)
	}
	if !accountNameExists("foo", opts.Accounts) {
		t.Fatal("Expected a 'foo' account")
	}
	if !accountNameExists("bar", opts.Accounts) {
		t.Fatal("Expected a 'bar' account")
	}

	cfg2 := `
		accounts = [foo, foo]
	`

	// Make sure double entries is an error.
	confFileName = createConfFile(t, []byte(cfg2))
	_, err = ProcessConfigFile(confFileName)
	if err == nil {
		t.Fatalf("Expected an error with double account entries")
	}
}

func TestAccountParseConfig(t *testing.T) {
	traceDest := "my.trace.dest"
	traceSampling := 50
	confFileName := createConfFile(t, []byte(fmt.Sprintf(`
    accounts {
      synadia {
        users = [
          {user: alice, password: foo}
          {user: bob, password: bar}
        ]
      }
      nats.io {
		msg_trace: {dest: %q, sampling: %d%%}
        users = [
          {user: derek, password: foo}
          {user: ivan, password: bar}
        ]
      }
    }
    `, traceDest, traceSampling)))
	opts, err := ProcessConfigFile(confFileName)
	if err != nil {
		t.Fatalf("Received an error processing config file: %v", err)
	}

	if la := len(opts.Accounts); la != 2 {
		t.Fatalf("Expected to see 2 accounts in opts, got %d", la)
	}

	if lu := len(opts.Users); lu != 4 {
		t.Fatalf("Expected 4 total Users, got %d", lu)
	}

	var natsAcc *Account
	for _, acc := range opts.Accounts {
		if acc.Name == "nats.io" {
			natsAcc = acc
			break
		}
	}
	if natsAcc == nil {
		t.Fatalf("Error retrieving account for 'nats.io'")
	}
	td, tds := natsAcc.getTraceDestAndSampling()
	require_Equal[string](t, td, traceDest)
	require_Equal[int](t, tds, traceSampling)

	for _, u := range opts.Users {
		if u.Username == "derek" {
			if u.Account != natsAcc {
				t.Fatalf("Expected to see the 'nats.io' account, but received %+v", u.Account)
			}
		}
	}
}

func TestAccountParseConfigDuplicateUsers(t *testing.T) {
	confFileName := createConfFile(t, []byte(`
    accounts {
      synadia {
        users = [
          {user: alice, password: foo}
          {user: bob, password: bar}
        ]
      }
      nats.io {
        users = [
          {user: alice, password: bar}
        ]
      }
    }
    `))
	_, err := ProcessConfigFile(confFileName)
	if err == nil {
		t.Fatalf("Expected an error with double user entries")
	}
}

func TestAccountParseConfigImportsExports(t *testing.T) {
	opts, err := ProcessConfigFile("./configs/accounts.conf")
	if err != nil {
		t.Fatal("parsing failed: ", err)
	}
	if la := len(opts.Accounts); la != 3 {
		t.Fatalf("Expected to see 3 accounts in opts, got %d", la)
	}
	if lu := len(opts.Nkeys); lu != 4 {
		t.Fatalf("Expected 4 total Nkey users, got %d", lu)
	}
	if lu := len(opts.Users); lu != 0 {
		t.Fatalf("Expected no Users, got %d", lu)
	}
	var natsAcc, synAcc *Account
	for _, acc := range opts.Accounts {
		if acc.Name == "nats.io" {
			natsAcc = acc
		} else if acc.Name == "synadia" {
			synAcc = acc
		}
	}
	if natsAcc == nil {
		t.Fatalf("Error retrieving account for 'nats.io'")
	}
	if natsAcc.Nkey != "AB5UKNPVHDWBP5WODG742274I3OGY5FM3CBIFCYI4OFEH7Y23GNZPXFE" {
		t.Fatalf("Expected nats account to have an nkey, got %q\n", natsAcc.Nkey)
	}
	// Check user assigned to the correct account.
	for _, nk := range opts.Nkeys {
		if nk.Nkey == "UBRYMDSRTC6AVJL6USKKS3FIOE466GMEU67PZDGOWYSYHWA7GSKO42VW" {
			if nk.Account != natsAcc {
				t.Fatalf("Expected user to be associated with natsAcc, got %q\n", nk.Account.Name)
			}
			break
		}
	}

	// Now check for the imports and exports of streams and services.
	if lis := len(natsAcc.imports.streams); lis != 2 {
		t.Fatalf("Expected 2 imported streams, got %d\n", lis)
	}
	for _, si := range natsAcc.imports.streams {
		if si.from == "public.synadia" {
			require_True(t, si.atrc)
		} else {
			require_False(t, si.atrc)
		}
	}
	if lis := len(natsAcc.imports.services); lis != 1 {
		t.Fatalf("Expected 1 imported service, got %d\n", lis)
	}
	if les := len(natsAcc.exports.services); les != 4 {
		t.Fatalf("Expected 4 exported services, got %d\n", les)
	}
	if les := len(natsAcc.exports.streams); les != 0 {
		t.Fatalf("Expected no exported streams, got %d\n", les)
	}

	ea := natsAcc.exports.services["nats.time"]
	if ea == nil {
		t.Fatalf("Expected to get a non-nil exportAuth for service")
	}
	if ea.respType != Streamed {
		t.Fatalf("Expected to get a Streamed response type, got %q", ea.respType)
	}
	require_True(t, ea.atrc)
	ea = natsAcc.exports.services["nats.photo"]
	if ea == nil {
		t.Fatalf("Expected to get a non-nil exportAuth for service")
	}
	if ea.respType != Chunked {
		t.Fatalf("Expected to get a Chunked response type, got %q", ea.respType)
	}
	require_False(t, ea.atrc)
	ea = natsAcc.exports.services["nats.add"]
	if ea == nil {
		t.Fatalf("Expected to get a non-nil exportAuth for service")
	}
	if ea.respType != Singleton {
		t.Fatalf("Expected to get a Singleton response type, got %q", ea.respType)
	}
	require_True(t, ea.atrc)

	if synAcc == nil {
		t.Fatalf("Error retrieving account for 'synadia'")
	}

	if lis := len(synAcc.imports.streams); lis != 0 {
		t.Fatalf("Expected no imported streams, got %d\n", lis)
	}
	if lis := len(synAcc.imports.services); lis != 1 {
		t.Fatalf("Expected 1 imported service, got %d\n", lis)
	}
	if les := len(synAcc.exports.services); les != 2 {
		t.Fatalf("Expected 2 exported service, got %d\n", les)
	}
	if les := len(synAcc.exports.streams); les != 2 {
		t.Fatalf("Expected 2 exported streams, got %d\n", les)
	}
}

func TestImportExportConfigFailures(t *testing.T) {
	// Import from unknow account
	cf := createConfFile(t, []byte(`
    accounts {
      nats.io {
        imports = [{stream: {account: "synadia", subject:"foo"}}]
      }
    }
    `))
	if _, err := ProcessConfigFile(cf); err == nil {
		t.Fatalf("Expected an error with import from unknown account")
	}
	// Import a service with no account.
	cf = createConfFile(t, []byte(`
    accounts {
      nats.io {
        imports = [{service: subject:"foo.*"}]
      }
    }
    `))
	if _, err := ProcessConfigFile(cf); err == nil {
		t.Fatalf("Expected an error with import of a service with no account")
	}
	// Import a service with a wildcard subject.
	cf = createConfFile(t, []byte(`
    accounts {
      nats.io {
        imports = [{service: {account: "nats.io", subject:"foo.*"}]
      }
    }
    `))
	if _, err := ProcessConfigFile(cf); err == nil {
		t.Fatalf("Expected an error with import of a service with wildcard subject")
	}
	// Export with unknown keyword.
	cf = createConfFile(t, []byte(`
    accounts {
      nats.io {
        exports = [{service: "foo.*", wat:true}]
      }
    }
    `))
	if _, err := ProcessConfigFile(cf); err == nil {
		t.Fatalf("Expected an error with export with unknown keyword")
	}
	// Import with unknown keyword.
	cf = createConfFile(t, []byte(`
    accounts {
      nats.io {
        imports = [{stream: {account: nats.io, subject: "foo.*"}, wat:true}]
      }
    }
    `))
	if _, err := ProcessConfigFile(cf); err == nil {
		t.Fatalf("Expected an error with import with unknown keyword")
	}
	// Export with an account.
	cf = createConfFile(t, []byte(`
    accounts {
      nats.io {
        exports = [{service: {account: nats.io, subject:"foo.*"}}]
      }
    }
    `))
	if _, err := ProcessConfigFile(cf); err == nil {
		t.Fatalf("Expected an error with export with account")
	}
}

func TestImportAuthorized(t *testing.T) {
	_, foo, bar := simpleAccountServer(t)

	checkBool(foo.checkStreamImportAuthorized(bar, "foo", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, ">", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.*", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.>", nil), false, t)

	foo.AddStreamExport("foo", IsPublicExport)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "bar", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*", nil), false, t)

	foo.AddStreamExport("*", []*Account{bar})
	checkBool(foo.checkStreamImportAuthorized(bar, "foo", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "bar", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "baz", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.bar", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, ">", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.*", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*.*", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*.>", nil), false, t)

	// Reset and test '>' public export
	_, foo, bar = simpleAccountServer(t)
	foo.AddStreamExport(">", nil)
	// Everything should work.
	checkBool(foo.checkStreamImportAuthorized(bar, "foo", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "bar", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "baz", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.bar", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, ">", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.*", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*.*", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "*.>", nil), true, t)

	_, foo, bar = simpleAccountServer(t)
	foo.addStreamExportWithAccountPos("foo.*", []*Account{}, 2)
	foo.addStreamExportWithAccountPos("bar.*.foo", []*Account{}, 2)
	if err := foo.addStreamExportWithAccountPos("baz.*.>", []*Account{}, 3); err == nil {
		t.Fatal("expected error")
	}
	checkBool(foo.checkStreamImportAuthorized(bar, fmt.Sprintf("foo.%s", bar.Name), nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, fmt.Sprintf("bar.%s.foo", bar.Name), nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, fmt.Sprintf("baz.foo.%s", bar.Name), nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.X", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "bar.X.foo", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "baz.foo.X", nil), false, t)

	foo.addServiceExportWithAccountPos("a.*", []*Account{}, 2)
	foo.addServiceExportWithAccountPos("b.*.a", []*Account{}, 2)
	if err := foo.addServiceExportWithAccountPos("c.*.>", []*Account{}, 3); err == nil {
		t.Fatal("expected error")
	}
	checkBool(foo.checkServiceImportAuthorized(bar, fmt.Sprintf("a.%s", bar.Name), nil), true, t)
	checkBool(foo.checkServiceImportAuthorized(bar, fmt.Sprintf("b.%s.a", bar.Name), nil), true, t)
	checkBool(foo.checkServiceImportAuthorized(bar, fmt.Sprintf("c.a.%s", bar.Name), nil), false, t)
	checkBool(foo.checkServiceImportAuthorized(bar, "a.X", nil), false, t)
	checkBool(foo.checkServiceImportAuthorized(bar, "b.X.a", nil), false, t)
	checkBool(foo.checkServiceImportAuthorized(bar, "c.a.X", nil), false, t)

	// Reset and test pwc and fwc
	s, foo, bar := simpleAccountServer(t)
	foo.AddStreamExport("foo.*.baz.>", []*Account{bar})
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.bar.baz.1", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.bar.baz.*", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.*.baz.1.1", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.22.baz.22", nil), true, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.bar.baz", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bar, "foo.bar.*.*", nil), false, t)

	// Make sure we match the account as well

	fb, _ := s.RegisterAccount("foobar")
	bz, _ := s.RegisterAccount("baz")

	checkBool(foo.checkStreamImportAuthorized(fb, "foo.bar.baz.1", nil), false, t)
	checkBool(foo.checkStreamImportAuthorized(bz, "foo.bar.baz.1", nil), false, t)
}

func TestSimpleMapping(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	// Test first that trying to import with no matching export permission returns an error.
	if err := cbar.acc.AddStreamImport(fooAcc, "foo", "import"); err != ErrStreamImportAuthorization {
		t.Fatalf("Expected error of ErrAccountImportAuthorization but got %v", err)
	}

	// Now map the subject space between foo and bar.
	// Need to do export first.
	if err := cfoo.acc.AddStreamExport("foo", nil); err != nil { // Public with no accounts defined.
		t.Fatalf("Error adding account export to client foo: %v", err)
	}
	if err := cbar.acc.AddStreamImport(fooAcc, "foo", "import"); err != nil {
		t.Fatalf("Error adding account import to client bar: %v", err)
	}

	// Normal and Queue Subscription on bar client.
	if err := cbar.parse([]byte("SUB import.foo 1\r\nSUB import.foo bar 2\r\n")); err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}

	// Now publish our message.
	cfoo.parseAsync("PUB foo 5\r\nhello\r\n")

	checkMsg := func(l, sid string) {
		t.Helper()
		mraw := msgPat.FindAllStringSubmatch(l, -1)
		if len(mraw) == 0 {
			t.Fatalf("No message received")
		}
		matches := mraw[0]
		if matches[SUB_INDEX] != "import.foo" {
			t.Fatalf("Did not get correct subject: wanted %q, got %q", "import.foo", matches[SUB_INDEX])
		}
		if matches[SID_INDEX] != sid {
			t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
		}
	}

	// Now check we got the message from normal subscription.
	l, err := crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	checkMsg(l, "1")
	checkPayload(crBar, []byte("hello\r\n"), t)

	l, err = crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	checkMsg(l, "2")
	checkPayload(crBar, []byte("hello\r\n"), t)

	// We should have 2 subscriptions in both. Normal and Queue Subscriber
	// for barAcc which are local, and 2 that are shadowed in fooAcc.
	// Now make sure that when we unsubscribe we clean up properly for both.
	if bslc := barAcc.sl.Count(); bslc != 2 {
		t.Fatalf("Expected 2 normal subscriptions on barAcc, got %d", bslc)
	}
	if fslc := fooAcc.sl.Count(); fslc != 2 {
		t.Fatalf("Expected 2 shadowed subscriptions on fooAcc, got %d", fslc)
	}

	// Now unsubscribe.
	if err := cbar.parse([]byte("UNSUB 1\r\nUNSUB 2\r\n")); err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}

	// We should have zero on both.
	if bslc := barAcc.sl.Count(); bslc != 0 {
		t.Fatalf("Expected no normal subscriptions on barAcc, got %d", bslc)
	}
	if fslc := fooAcc.sl.Count(); fslc != 0 {
		t.Fatalf("Expected no shadowed subscriptions on fooAcc, got %d", fslc)
	}
}

// https://github.com/nats-io/nats-server/issues/1159
func TestStreamImportLengthBug(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	cbar, _, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	if err := cfoo.acc.AddStreamExport("client.>", nil); err != nil {
		t.Fatalf("Error adding account export to client foo: %v", err)
	}
	if err := cbar.acc.AddStreamImport(fooAcc, "client.>", "events.>"); err == nil {
		t.Fatalf("Expected an error when using a stream import prefix with a wildcard")
	}

	if err := cbar.acc.AddStreamImport(fooAcc, "client.>", "events"); err != nil {
		t.Fatalf("Error adding account import to client bar: %v", err)
	}

	if err := cbar.parse([]byte("SUB events.> 1\r\n")); err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}

	// Also make sure that we will get an error from a config version.
	// JWT will be updated separately.
	cf := createConfFile(t, []byte(`
	accounts {
	  foo {
	    exports = [{stream: "client.>"}]
	  }
	  bar {
	    imports = [{stream: {account: "foo", subject:"client.>"}, prefix:"events.>"}]
	  }
	}
	`))
	if _, err := ProcessConfigFile(cf); err == nil {
		t.Fatalf("Expected an error with import with wildcard prefix")
	}
}

func TestShadowSubsCleanupOnClientClose(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	// Now map the subject space between foo and bar.
	// Need to do export first.
	if err := fooAcc.AddStreamExport("foo", nil); err != nil { // Public with no accounts defined.
		t.Fatalf("Error adding account export to client foo: %v", err)
	}
	if err := barAcc.AddStreamImport(fooAcc, "foo", "import"); err != nil {
		t.Fatalf("Error adding account import to client bar: %v", err)
	}

	cbar, _, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	// Normal and Queue Subscription on bar client.
	if err := cbar.parse([]byte("SUB import.foo 1\r\nSUB import.foo bar 2\r\n")); err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}

	if fslc := fooAcc.sl.Count(); fslc != 2 {
		t.Fatalf("Expected 2 shadowed subscriptions on fooAcc, got %d", fslc)
	}

	// Now close cbar and make sure we remove shadows.
	cbar.closeConnection(ClientClosed)

	checkFor(t, time.Second, 10*time.Millisecond, func() error {
		if fslc := fooAcc.sl.Count(); fslc != 0 {
			return fmt.Errorf("Number of shadow subscriptions is %d", fslc)
		}
		return nil
	})
}

func TestNoPrefixWildcardMapping(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	if err := cfoo.acc.AddStreamExport(">", []*Account{barAcc}); err != nil {
		t.Fatalf("Error adding stream export to client foo: %v", err)
	}
	if err := cbar.acc.AddStreamImport(fooAcc, "*", ""); err != nil {
		t.Fatalf("Error adding stream import to client bar: %v", err)
	}

	// Normal Subscription on bar client for literal "foo".
	cbar.parseAsync("SUB foo 1\r\nPING\r\n")
	_, err := crBar.ReadString('\n') // Make sure subscriptions were processed.
	if err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}

	// Now publish our message.
	cfoo.parseAsync("PUB foo 5\r\nhello\r\n")

	// Now check we got the message from normal subscription.
	l, err := crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw := msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches := mraw[0]
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crBar, []byte("hello\r\n"), t)
}

func TestPrefixWildcardMapping(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	if err := cfoo.acc.AddStreamExport(">", []*Account{barAcc}); err != nil {
		t.Fatalf("Error adding stream export to client foo: %v", err)
	}
	// Checking that trailing '.' is accepted, tested that it is auto added above.
	if err := cbar.acc.AddStreamImport(fooAcc, "*", "pub.imports."); err != nil {
		t.Fatalf("Error adding stream import to client bar: %v", err)
	}

	// Normal Subscription on bar client for wildcard.
	cbar.parseAsync("SUB pub.imports.* 1\r\nPING\r\n")
	_, err := crBar.ReadString('\n') // Make sure subscriptions were processed.
	if err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}

	// Now publish our message.
	cfoo.parseAsync("PUB foo 5\r\nhello\r\n")

	// Now check we got the messages from wildcard subscription.
	l, err := crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw := msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches := mraw[0]
	if matches[SUB_INDEX] != "pub.imports.foo" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crBar, []byte("hello\r\n"), t)
}

func TestPrefixWildcardMappingWithLiteralSub(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	if err := fooAcc.AddStreamExport(">", []*Account{barAcc}); err != nil {
		t.Fatalf("Error adding stream export to client foo: %v", err)
	}
	if err := barAcc.AddStreamImport(fooAcc, "*", "pub.imports."); err != nil {
		t.Fatalf("Error adding stream import to client bar: %v", err)
	}

	// Normal Subscription on bar client for wildcard.
	cbar.parseAsync("SUB pub.imports.foo 1\r\nPING\r\n")
	_, err := crBar.ReadString('\n') // Make sure subscriptions were processed.
	if err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}

	// Now publish our message.
	cfoo.parseAsync("PUB foo 5\r\nhello\r\n")

	// Now check we got the messages from wildcard subscription.
	l, err := crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw := msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches := mraw[0]
	if matches[SUB_INDEX] != "pub.imports.foo" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crBar, []byte("hello\r\n"), t)
}

func TestMultipleImportsAndSingleWCSub(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	if err := fooAcc.AddStreamExport("foo", []*Account{barAcc}); err != nil {
		t.Fatalf("Error adding stream export to account foo: %v", err)
	}
	if err := fooAcc.AddStreamExport("bar", []*Account{barAcc}); err != nil {
		t.Fatalf("Error adding stream export to account foo: %v", err)
	}

	if err := barAcc.AddStreamImport(fooAcc, "foo", "pub."); err != nil {
		t.Fatalf("Error adding stream import to account bar: %v", err)
	}
	if err := barAcc.AddStreamImport(fooAcc, "bar", "pub."); err != nil {
		t.Fatalf("Error adding stream import to account bar: %v", err)
	}

	// Wildcard Subscription on bar client for both imports.
	cbar.parse([]byte("SUB pub.* 1\r\n"))

	// Now publish a message on 'foo' and 'bar'
	cfoo.parseAsync("PUB foo 5\r\nhello\r\nPUB bar 5\r\nworld\r\n")

	// Now check we got the messages from the wildcard subscription.
	l, err := crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw := msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches := mraw[0]
	if matches[SUB_INDEX] != "pub.foo" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crBar, []byte("hello\r\n"), t)

	l, err = crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw = msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches = mraw[0]
	if matches[SUB_INDEX] != "pub.bar" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crBar, []byte("world\r\n"), t)

	// Check subscription count.
	if fslc := fooAcc.sl.Count(); fslc != 2 {
		t.Fatalf("Expected 2 shadowed subscriptions on fooAcc, got %d", fslc)
	}
	if bslc := barAcc.sl.Count(); bslc != 1 {
		t.Fatalf("Expected 1 normal subscriptions on barAcc, got %d", bslc)
	}

	// Now unsubscribe.
	if err := cbar.parse([]byte("UNSUB 1\r\n")); err != nil {
		t.Fatalf("Error for client 'bar' from server: %v", err)
	}
	// We should have zero on both.
	if bslc := barAcc.sl.Count(); bslc != 0 {
		t.Fatalf("Expected no normal subscriptions on barAcc, got %d", bslc)
	}
	if fslc := fooAcc.sl.Count(); fslc != 0 {
		t.Fatalf("Expected no shadowed subscriptions on fooAcc, got %d", fslc)
	}
}

// Make sure the AddServiceExport function is additive if called multiple times.
func TestAddServiceExport(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	bazAcc, err := s.RegisterAccount("$baz")
	if err != nil {
		t.Fatalf("Error creating account 'baz': %v", err)
	}
	defer s.Shutdown()

	if err := fooAcc.AddServiceExport("test.request", nil); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	tr := fooAcc.exports.services["test.request"]
	if len(tr.approved) != 0 {
		t.Fatalf("Expected no authorized accounts, got %d", len(tr.approved))
	}
	if err := fooAcc.AddServiceExport("test.request", []*Account{barAcc}); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	tr = fooAcc.exports.services["test.request"]
	if tr == nil {
		t.Fatalf("Expected authorized accounts, got nil")
	}
	if ls := len(tr.approved); ls != 1 {
		t.Fatalf("Expected 1 authorized accounts, got %d", ls)
	}
	if err := fooAcc.AddServiceExport("test.request", []*Account{bazAcc}); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	tr = fooAcc.exports.services["test.request"]
	if tr == nil {
		t.Fatalf("Expected authorized accounts, got nil")
	}
	if ls := len(tr.approved); ls != 2 {
		t.Fatalf("Expected 2 authorized accounts, got %d", ls)
	}
}

func TestServiceExportWithWildcards(t *testing.T) {
	for _, test := range []struct {
		name   string
		public bool
	}{
		{
			name:   "public",
			public: true,
		},
		{
			name:   "private",
			public: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, fooAcc, barAcc := simpleAccountServer(t)
			defer s.Shutdown()

			var accs []*Account
			if !test.public {
				accs = []*Account{barAcc}
			}
			// Add service export with a wildcard
			if err := fooAcc.AddServiceExport("ngs.update.*", accs); err != nil {
				t.Fatalf("Error adding account service export: %v", err)
			}
			// Import on bar account
			if err := barAcc.AddServiceImport(fooAcc, "ngs.update", "ngs.update.$bar"); err != nil {
				t.Fatalf("Error adding account service import: %v", err)
			}

			cfoo, crFoo, _ := newClientForServer(s)
			defer cfoo.close()

			if err := cfoo.registerWithAccount(fooAcc); err != nil {
				t.Fatalf("Error registering client with 'foo' account: %v", err)
			}
			cbar, crBar, _ := newClientForServer(s)
			defer cbar.close()

			if err := cbar.registerWithAccount(barAcc); err != nil {
				t.Fatalf("Error registering client with 'bar' account: %v", err)
			}

			// Now setup the responder under cfoo
			cfoo.parse([]byte("SUB ngs.update.* 1\r\n"))

			// Now send the request. Remember we expect the request on our local ngs.update.
			// We added the route with that "from" and will map it to "ngs.update.$bar"
			cbar.parseAsync("SUB reply 11\r\nPUB ngs.update reply 4\r\nhelp\r\n")

			// Now read the request from crFoo
			l, err := crFoo.ReadString('\n')
			if err != nil {
				t.Fatalf("Error reading from client 'bar': %v", err)
			}

			mraw := msgPat.FindAllStringSubmatch(l, -1)
			if len(mraw) == 0 {
				t.Fatalf("No message received")
			}
			matches := mraw[0]
			if matches[SUB_INDEX] != "ngs.update.$bar" {
				t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
			}
			if matches[SID_INDEX] != "1" {
				t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
			}
			// Make sure this looks like _INBOX
			if !strings.HasPrefix(matches[REPLY_INDEX], "_R_.") {
				t.Fatalf("Expected an _R_.* like reply, got '%s'", matches[REPLY_INDEX])
			}
			checkPayload(crFoo, []byte("help\r\n"), t)

			replyOp := fmt.Sprintf("PUB %s 2\r\n22\r\n", matches[REPLY_INDEX])
			cfoo.parseAsync(replyOp)

			// Now read the response from crBar
			l, err = crBar.ReadString('\n')
			if err != nil {
				t.Fatalf("Error reading from client 'bar': %v", err)
			}
			mraw = msgPat.FindAllStringSubmatch(l, -1)
			if len(mraw) == 0 {
				t.Fatalf("No message received")
			}
			matches = mraw[0]
			if matches[SUB_INDEX] != "reply" {
				t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
			}
			if matches[SID_INDEX] != "11" {
				t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
			}
			if matches[REPLY_INDEX] != "" {
				t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
			}
			checkPayload(crBar, []byte("22\r\n"), t)

			if nr := barAcc.NumPendingAllResponses(); nr != 0 {
				t.Fatalf("Expected no responses on barAcc, got %d", nr)
			}
		})
	}
}

func TestAccountAddServiceImportRace(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	if err := fooAcc.AddServiceExport("foo.*", nil); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}

	total := 100
	errCh := make(chan error, total)
	for i := 0; i < 100; i++ {
		go func(i int) {
			err := barAcc.AddServiceImport(fooAcc, fmt.Sprintf("foo.%d", i), "")
			errCh <- err // nil is a valid value.
		}(i)
	}

	for i := 0; i < 100; i++ {
		err := <-errCh
		if err != nil {
			t.Fatalf("Error adding account service import: %v", err)
		}
	}

	barAcc.mu.Lock()
	lens := len(barAcc.imports.services)
	c := barAcc.internalClient()
	barAcc.mu.Unlock()
	if lens != total {
		t.Fatalf("Expected %d imported services, got %d", total, lens)
	}
	c.mu.Lock()
	lens = len(c.subs)
	c.mu.Unlock()
	if lens != total {
		t.Fatalf("Expected %d subscriptions in internal client, got %d", total, lens)
	}
}

func TestServiceImportWithWildcards(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	if err := fooAcc.AddServiceExport("test.*", nil); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	// We can not map wildcards atm, so if we supply a to mapping and a wildcard we should fail.
	if err := barAcc.AddServiceImport(fooAcc, "test.*", "foo"); err == nil {
		t.Fatalf("Expected error adding account service import with wildcard and mapping, got none")
	}
	if err := barAcc.AddServiceImport(fooAcc, "test.>", ""); err == nil {
		t.Fatalf("Expected error adding account service import with broader wildcard, got none")
	}
	// This should work.
	if err := barAcc.AddServiceImport(fooAcc, "test.*", ""); err != nil {
		t.Fatalf("Error adding account service import: %v", err)
	}
	// Make sure we can send and receive.
	cfoo, crFoo, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}

	// Now setup the resonder under cfoo
	cfoo.parse([]byte("SUB test.* 1\r\n"))

	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	// Now send the request.
	go cbar.parse([]byte("SUB bar 11\r\nPUB test.22 bar 4\r\nhelp\r\n"))

	// Now read the request from crFoo
	l, err := crFoo.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}

	mraw := msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches := mraw[0]
	if matches[SUB_INDEX] != "test.22" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	// Make sure this looks like _INBOX
	if !strings.HasPrefix(matches[REPLY_INDEX], "_R_.") {
		t.Fatalf("Expected an _R_.* like reply, got '%s'", matches[REPLY_INDEX])
	}
	checkPayload(crFoo, []byte("help\r\n"), t)

	replyOp := fmt.Sprintf("PUB %s 2\r\n22\r\n", matches[REPLY_INDEX])
	go cfoo.parse([]byte(replyOp))

	// Now read the response from crBar
	l, err = crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw = msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches = mraw[0]
	if matches[SUB_INDEX] != "bar" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "11" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	if matches[REPLY_INDEX] != "" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crBar, []byte("22\r\n"), t)

	// Remove the service import with the wildcard and make sure hasWC is cleared.
	barAcc.removeServiceImport(fooAcc.Name, "test.*")

	barAcc.mu.Lock()
	defer barAcc.mu.Unlock()
	if len(barAcc.imports.services) != 0 {
		t.Fatalf("Expected no imported services, got %d", len(barAcc.imports.services))
	}
}

// Make sure the AddStreamExport function is additive if called multiple times.
func TestAddStreamExport(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	bazAcc, err := s.RegisterAccount("$baz")
	if err != nil {
		t.Fatalf("Error creating account 'baz': %v", err)
	}
	defer s.Shutdown()

	if err := fooAcc.AddStreamExport("test.request", nil); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	tr := fooAcc.exports.streams["test.request"]
	if tr != nil {
		t.Fatalf("Expected no authorized accounts, got %d", len(tr.approved))
	}
	if err := fooAcc.AddStreamExport("test.request", []*Account{barAcc}); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	tr = fooAcc.exports.streams["test.request"]
	if tr == nil {
		t.Fatalf("Expected authorized accounts, got nil")
	}
	if ls := len(tr.approved); ls != 1 {
		t.Fatalf("Expected 1 authorized accounts, got %d", ls)
	}
	if err := fooAcc.AddStreamExport("test.request", []*Account{bazAcc}); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	tr = fooAcc.exports.streams["test.request"]
	if tr == nil {
		t.Fatalf("Expected authorized accounts, got nil")
	}
	if ls := len(tr.approved); ls != 2 {
		t.Fatalf("Expected 2 authorized accounts, got %d", ls)
	}
}

func TestCrossAccountRequestReply(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, crFoo, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}

	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	// Add in the service export for the requests. Make it public.
	if err := cfoo.acc.AddServiceExport("test.request", nil); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}

	// Test addServiceImport to make sure it requires accounts.
	if err := cbar.acc.AddServiceImport(nil, "foo", "test.request"); err != ErrMissingAccount {
		t.Fatalf("Expected ErrMissingAccount but received %v.", err)
	}
	if err := cbar.acc.AddServiceImport(fooAcc, "foo", "test..request."); err != ErrInvalidSubject {
		t.Fatalf("Expected ErrInvalidSubject but received %v.", err)
	}

	// Now add in the route mapping for request to be routed to the foo account.
	if err := cbar.acc.AddServiceImport(fooAcc, "foo", "test.request"); err != nil {
		t.Fatalf("Error adding account service import to client bar: %v", err)
	}

	// Now setup the resonder under cfoo
	cfoo.parse([]byte("SUB test.request 1\r\n"))

	// Now send the request. Remember we expect the request on our local foo. We added the route
	// with that "from" and will map it to "test.request"
	cbar.parseAsync("SUB bar 11\r\nPUB foo bar 4\r\nhelp\r\n")

	// Now read the request from crFoo
	l, err := crFoo.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}

	mraw := msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches := mraw[0]
	if matches[SUB_INDEX] != "test.request" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	// Make sure this looks like _INBOX
	if !strings.HasPrefix(matches[REPLY_INDEX], "_R_.") {
		t.Fatalf("Expected an _R_.* like reply, got '%s'", matches[REPLY_INDEX])
	}
	checkPayload(crFoo, []byte("help\r\n"), t)

	replyOp := fmt.Sprintf("PUB %s 2\r\n22\r\n", matches[REPLY_INDEX])
	cfoo.parseAsync(replyOp)

	// Now read the response from crBar
	l, err = crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw = msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches = mraw[0]
	if matches[SUB_INDEX] != "bar" {
		t.Fatalf("Did not get correct subject: '%s'", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "11" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	if matches[REPLY_INDEX] != "" {
		t.Fatalf("Did not get correct sid: '%s'", matches[SID_INDEX])
	}
	checkPayload(crBar, []byte("22\r\n"), t)

	if nr := barAcc.NumPendingAllResponses(); nr != 0 {
		t.Fatalf("Expected no responses on barAcc, got %d", nr)
	}
}

func TestAccountRequestReplyTrackLatency(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	// Run server in Go routine. We need this one running for internal sending of msgs.
	s.Start()
	// Wait for accept loop(s) to be started
	if err := s.readyForConnections(10 * time.Second); err != nil {
		t.Fatal(err)
	}

	cfoo, crFoo, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}

	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	// Add in the service export for the requests. Make it public.
	if err := fooAcc.AddServiceExport("track.service", nil); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}

	// Now let's add in tracking

	// First check we get an error if service does not exist.
	if err := fooAcc.TrackServiceExport("track.wrong", "results"); err != ErrMissingService {
		t.Fatalf("Expected error enabling tracking latency for wrong service")
	}
	// Check results should be a valid subject
	if err := fooAcc.TrackServiceExport("track.service", "results.*"); err != ErrBadPublishSubject {
		t.Fatalf("Expected error enabling tracking latency for bad results subject")
	}
	// Make sure we can not loop around on ourselves..
	if err := fooAcc.TrackServiceExport("track.service", "track.service"); err != ErrBadPublishSubject {
		t.Fatalf("Expected error enabling tracking latency for same subject")
	}
	// Check bad sampling
	if err := fooAcc.TrackServiceExportWithSampling("track.service", "results", -1); err != ErrBadSampling {
		t.Fatalf("Expected error enabling tracking latency for bad sampling")
	}
	if err := fooAcc.TrackServiceExportWithSampling("track.service", "results", 101); err != ErrBadSampling {
		t.Fatalf("Expected error enabling tracking latency for bad sampling")
	}

	// Now let's add in tracking for real. This will be 100%
	if err := fooAcc.TrackServiceExport("track.service", "results"); err != nil {
		t.Fatalf("Error enabling tracking latency: %v", err)
	}

	// Now add in the route mapping for request to be routed to the foo account.
	if err := barAcc.AddServiceImport(fooAcc, "req", "track.service"); err != nil {
		t.Fatalf("Error adding account service import to client bar: %v", err)
	}

	// Now setup the responder under cfoo and the listener for the results
	cfoo.parse([]byte("SUB track.service 1\r\nSUB results 2\r\n"))

	readFooMsg := func() ([]byte, string) {
		t.Helper()
		l, err := crFoo.ReadString('\n')
		if err != nil {
			t.Fatalf("Error reading from client 'foo': %v", err)
		}
		mraw := msgPat.FindAllStringSubmatch(l, -1)
		if len(mraw) == 0 {
			t.Fatalf("No message received")
		}
		msg := mraw[0]
		msgSize, _ := strconv.Atoi(msg[LEN_INDEX])
		return grabPayload(crFoo, msgSize), msg[REPLY_INDEX]
	}

	start := time.Now()

	// Now send the request. Remember we expect the request on our local foo. We added the route
	// with that "from" and will map it to "test.request"
	cbar.parseAsync("SUB resp 11\r\nPUB req resp 4\r\nhelp\r\n")

	// Now read the request from crFoo
	_, reply := readFooMsg()
	replyOp := fmt.Sprintf("PUB %s 2\r\n22\r\n", reply)

	serviceTime := 25 * time.Millisecond

	// We will wait a bit to check latency results
	go func() {
		time.Sleep(serviceTime)
		cfoo.parseAsync(replyOp)
	}()

	// Now read the response from crBar
	_, err := crBar.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}

	// Now let's check that we got the sampling results
	rMsg, _ := readFooMsg()

	// Unmarshal and check it.
	var sl ServiceLatency
	err = json.Unmarshal(rMsg, &sl)
	if err != nil {
		t.Fatalf("Could not parse latency json: %v\n", err)
	}
	startDelta := sl.RequestStart.Sub(start)
	if startDelta > 5*time.Millisecond {
		t.Fatalf("Bad start delta %v", startDelta)
	}
	if sl.ServiceLatency < serviceTime {
		t.Fatalf("Bad service latency: %v", sl.ServiceLatency)
	}
	if sl.TotalLatency < sl.ServiceLatency {
		t.Fatalf("Bad total latency: %v", sl.ServiceLatency)
	}
}

// This will test for leaks in the remote latency tracking via client.rrTracking
func TestAccountTrackLatencyRemoteLeaks(t *testing.T) {
	optsA, err := ProcessConfigFile("./configs/seed.conf")
	require_NoError(t, err)
	optsA.NoSigs, optsA.NoLog = true, true
	optsA.ServerName = "A"
	srvA := RunServer(optsA)
	defer srvA.Shutdown()
	optsB := nextServerOpts(optsA)
	optsB.Routes = RoutesFromStr(fmt.Sprintf("nats://%s:%d", optsA.Cluster.Host, optsA.Cluster.Port))
	optsB.ServerName = "B"
	srvB := RunServer(optsB)
	defer srvB.Shutdown()

	checkClusterFormed(t, srvA, srvB)
	srvs := []*Server{srvA, srvB}

	// Now add in the accounts and setup tracking.
	for _, s := range srvs {
		s.SetSystemAccount(globalAccountName)
		fooAcc, _ := s.RegisterAccount("$foo")
		fooAcc.AddServiceExport("track.service", nil)
		fooAcc.TrackServiceExport("track.service", "results")
		barAcc, _ := s.RegisterAccount("$bar")
		if err := barAcc.AddServiceImport(fooAcc, "req", "track.service"); err != nil {
			t.Fatalf("Failed to import: %v", err)
		}
	}

	getClient := func(s *Server, name string) *client {
		t.Helper()
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, c := range s.clients {
			c.mu.Lock()
			n := c.opts.Name
			c.mu.Unlock()
			if n == name {
				return c
			}
		}
		t.Fatalf("Did not find client %q on server %q", name, s.info.ID)
		return nil
	}

	// Test with a responder on second server, srvB. but they will not respond.
	cfooNC := natsConnect(t, srvB.ClientURL(), nats.Name("foo"))
	defer cfooNC.Close()
	cfoo := getClient(srvB, "foo")
	fooAcc, _ := srvB.LookupAccount("$foo")
	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}

	// Set new limits
	for _, srv := range srvs {
		fooAcc, _ := srv.LookupAccount("$foo")
		err := fooAcc.SetServiceExportResponseThreshold("track.service", 5*time.Millisecond)
		if err != nil {
			t.Fatalf("Error setting response threshold: %v", err)
		}
	}

	// Now setup the responder under cfoo and the listener for the results
	time.Sleep(50 * time.Millisecond)
	baseSubs := int(srvA.NumSubscriptions())
	fooSub := natsSubSync(t, cfooNC, "track.service")
	natsFlush(t, cfooNC)
	// Wait for it to propagate.
	checkExpectedSubs(t, baseSubs+1, srvA)

	cbarNC := natsConnect(t, srvA.ClientURL(), nats.Name("bar"))
	defer cbarNC.Close()
	cbar := getClient(srvA, "bar")

	barAcc, _ := srvA.LookupAccount("$bar")
	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	readFooMsg := func() {
		t.Helper()
		if _, err := fooSub.NextMsg(time.Second); err != nil {
			t.Fatalf("Did not receive foo msg: %v", err)
		}
	}

	// Send 2 requests
	natsSubSync(t, cbarNC, "resp")

	natsPubReq(t, cbarNC, "req", "resp", []byte("help"))
	natsPubReq(t, cbarNC, "req", "resp", []byte("help"))

	readFooMsg()
	readFooMsg()

	var rc *client
	// Pull out first client
	srvB.mu.Lock()
	for _, rc = range srvB.clients {
		if rc != nil {
			break
		}
	}
	srvB.mu.Unlock()

	tracking := func() int {
		rc.mu.Lock()
		var nt int
		if rc.rrTracking != nil {
			nt = len(rc.rrTracking.rmap)
		}
		rc.mu.Unlock()
		return nt
	}

	expectTracking := func(expected int) {
		t.Helper()
		checkFor(t, time.Second, 10*time.Millisecond, func() error {
			if numTracking := tracking(); numTracking != expected {
				return fmt.Errorf("Expected to have %d tracking replies, got %d", expected, numTracking)
			}
			return nil
		})
	}

	expectTracking(2)
	// Make sure these remote tracking replies honor the current respThresh for a service export.
	time.Sleep(10 * time.Millisecond)
	expectTracking(0)
	// Also make sure tracking is removed
	rc.mu.Lock()
	removed := rc.rrTracking == nil
	rc.mu.Unlock()
	if !removed {
		t.Fatalf("Expected the rrTracking to be removed")
	}

	// Now let's test that a lower response threshold is picked up.
	fSub := natsSubSync(t, cfooNC, "foo")
	natsFlush(t, cfooNC)

	// Wait for it to propagate.
	checkExpectedSubs(t, baseSubs+4, srvA)

	// queue up some first. We want to test changing when rrTracking exists.
	natsPubReq(t, cbarNC, "req", "resp", []byte("help"))
	readFooMsg()
	expectTracking(1)

	for _, s := range srvs {
		fooAcc, _ := s.LookupAccount("$foo")
		barAcc, _ := s.LookupAccount("$bar")
		fooAcc.AddServiceExport("foo", nil)
		fooAcc.TrackServiceExport("foo", "foo.results")
		fooAcc.SetServiceExportResponseThreshold("foo", time.Millisecond)
		barAcc.AddServiceImport(fooAcc, "foo", "foo")
	}

	natsSubSync(t, cbarNC, "reply")
	natsPubReq(t, cbarNC, "foo", "reply", []byte("help"))
	if _, err := fSub.NextMsg(time.Second); err != nil {
		t.Fatalf("Did not receive foo msg: %v", err)
	}
	expectTracking(2)

	rc.mu.Lock()
	lrt := rc.rrTracking.lrt
	rc.mu.Unlock()
	if lrt != time.Millisecond {
		t.Fatalf("Expected lrt of %v, got %v", time.Millisecond, lrt)
	}

	// Now make sure we clear on close.
	rc.closeConnection(ClientClosed)

	// Actual tear down will be not inline.
	checkFor(t, time.Second, 5*time.Millisecond, func() error {
		rc.mu.Lock()
		removed = rc.rrTracking == nil
		rc.mu.Unlock()
		if !removed {
			return fmt.Errorf("Expected the rrTracking to be removed after client close")
		}
		return nil
	})
}

func TestCrossAccountServiceResponseTypes(t *testing.T) {
	s, fooAcc, barAcc := simpleAccountServer(t)
	defer s.Shutdown()

	cfoo, crFoo, _ := newClientForServer(s)
	defer cfoo.close()

	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	cbar, crBar, _ := newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	// Add in the service export for the requests. Make it public.
	if err := fooAcc.AddServiceExportWithResponse("test.request", Streamed, nil); err != nil {
		t.Fatalf("Error adding account service export to client foo: %v", err)
	}
	// Now add in the route mapping for request to be routed to the foo account.
	if err := barAcc.AddServiceImport(fooAcc, "foo", "test.request"); err != nil {
		t.Fatalf("Error adding account service import to client bar: %v", err)
	}

	// Now setup the resonder under cfoo
	cfoo.parse([]byte("SUB test.request 1\r\n"))

	// Now send the request. Remember we expect the request on our local foo. We added the route
	// with that "from" and will map it to "test.request"
	cbar.parseAsync("SUB bar 11\r\nPUB foo bar 4\r\nhelp\r\n")

	// Now read the request from crFoo
	l, err := crFoo.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}

	mraw := msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches := mraw[0]
	reply := matches[REPLY_INDEX]
	if !strings.HasPrefix(reply, "_R_.") {
		t.Fatalf("Expected an _R_.* like reply, got '%s'", reply)
	}
	crFoo.ReadString('\n')

	replyOp := fmt.Sprintf("PUB %s 2\r\n22\r\n", matches[REPLY_INDEX])
	var mReply []byte
	for i := 0; i < 10; i++ {
		mReply = append(mReply, replyOp...)
	}

	cfoo.parseAsync(string(mReply))

	var buf []byte
	for i := 0; i < 20; i++ {
		b, err := crBar.ReadBytes('\n')
		if err != nil {
			t.Fatalf("Error reading response: %v", err)
		}
		buf = append(buf[:], b...)
		if mraw = msgPat.FindAllStringSubmatch(string(buf), -1); len(mraw) == 10 {
			break
		}
	}
	if len(mraw) != 10 {
		t.Fatalf("Expected a response but got %d", len(mraw))
	}

	// Also make sure the response map gets cleaned up when interest goes away.
	cbar.closeConnection(ClientClosed)

	checkFor(t, time.Second, 10*time.Millisecond, func() error {
		if nr := barAcc.NumPendingAllResponses(); nr != 0 {
			return fmt.Errorf("Number of responses is %d", nr)
		}
		return nil
	})

	// Now test bogus reply subjects are handled and do not accumulate the response maps.
	cbar, _, _ = newClientForServer(s)
	defer cbar.close()

	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	// Do not create any interest in the reply subject 'bar'. Just send a request.
	cbar.parseAsync("PUB foo bar 4\r\nhelp\r\n")

	// Now read the request from crFoo
	l, err = crFoo.ReadString('\n')
	if err != nil {
		t.Fatalf("Error reading from client 'bar': %v", err)
	}
	mraw = msgPat.FindAllStringSubmatch(l, -1)
	if len(mraw) == 0 {
		t.Fatalf("No message received")
	}
	matches = mraw[0]
	reply = matches[REPLY_INDEX]
	if !strings.HasPrefix(reply, "_R_.") {
		t.Fatalf("Expected an _R_.* like reply, got '%s'", reply)
	}
	crFoo.ReadString('\n')

	replyOp = fmt.Sprintf("PUB %s 2\r\n22\r\n", matches[REPLY_INDEX])

	cfoo.parseAsync(replyOp)

	// Now wait for a bit, the reply should trip a no interest condition
	// which should clean this up.
	checkFor(t, time.Second, 10*time.Millisecond, func() error {
		if nr := fooAcc.NumPendingAllResponses(); nr != 0 {
			return fmt.Errorf("Number of responses is %d", nr)
		}
		return nil
	})

	// Also make sure the response map entry is gone as well.
	fooAcc.mu.RLock()
	lrm := len(fooAcc.exports.responses)
	fooAcc.mu.RUnlock()

	if lrm != 0 {
		t.Fatalf("Expected the responses to be cleared, got %d entries", lrm)
	}
}

func TestAccountMapsUsers(t *testing.T) {
	// Used for the nkey users to properly sign.
	seed1 := "SUAPM67TC4RHQLKBX55NIQXSMATZDOZK6FNEOSS36CAYA7F7TY66LP4BOM"
	seed2 := "SUAIS5JPX4X4GJ7EIIJEQ56DH2GWPYJRPWN5XJEDENJOZHCBLI7SEPUQDE"

	confFileName := createConfFile(t, []byte(`
    accounts {
      synadia {
        users = [
          {user: derek, password: foo},
          {nkey: UCNGL4W5QX66CFX6A6DCBVDH5VOHMI7B2UZZU7TXAUQQSI2JPHULCKBR}
        ]
      }
      nats {
        users = [
          {user: ivan, password: bar},
          {nkey: UDPGQVFIWZ7Q5UH4I5E6DBCZULQS6VTVBG6CYBD7JV3G3N2GMQOMNAUH}
        ]
      }
    }
    `))
	opts, err := ProcessConfigFile(confFileName)
	if err != nil {
		t.Fatalf("Unexpected error parsing config file: %v", err)
	}
	opts.NoSigs = true
	s := New(opts)
	defer s.Shutdown()
	synadia, _ := s.LookupAccount("synadia")
	nats, _ := s.LookupAccount("nats")

	if synadia == nil || nats == nil {
		t.Fatalf("Expected non nil accounts during lookup")
	}

	// Make sure a normal log in maps the accounts correctly.
	c, _, _ := newClientForServer(s)
	defer c.close()
	connectOp := []byte("CONNECT {\"user\":\"derek\",\"pass\":\"foo\"}\r\n")
	c.parse(connectOp)
	if c.acc != synadia {
		t.Fatalf("Expected the client's account to match 'synadia', got %v", c.acc)
	}

	c, _, _ = newClientForServer(s)
	defer c.close()
	connectOp = []byte("CONNECT {\"user\":\"ivan\",\"pass\":\"bar\"}\r\n")
	c.parse(connectOp)
	if c.acc != nats {
		t.Fatalf("Expected the client's account to match 'nats', got %v", c.acc)
	}

	// Now test nkeys as well.
	kp, _ := nkeys.FromSeed([]byte(seed1))
	pubKey, _ := kp.PublicKey()

	c, cr, l := newClientForServer(s)
	defer c.close()
	// Check for Nonce
	var info nonceInfo
	err = json.Unmarshal([]byte(l[5:]), &info)
	if err != nil {
		t.Fatalf("Could not parse INFO json: %v\n", err)
	}
	if info.Nonce == "" {
		t.Fatalf("Expected a non-empty nonce with nkeys defined")
	}
	sigraw, err := kp.Sign([]byte(info.Nonce))
	if err != nil {
		t.Fatalf("Failed signing nonce: %v", err)
	}
	sig := base64.RawURLEncoding.EncodeToString(sigraw)

	// PING needed to flush the +OK to us.
	cs := fmt.Sprintf("CONNECT {\"nkey\":%q,\"sig\":\"%s\",\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", pubKey, sig)
	c.parseAsync(cs)
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "+OK") {
		t.Fatalf("Expected an OK, got: %v", l)
	}
	if c.acc != synadia {
		t.Fatalf("Expected the nkey client's account to match 'synadia', got %v", c.acc)
	}

	// Now nats account nkey user.
	kp, _ = nkeys.FromSeed([]byte(seed2))
	pubKey, _ = kp.PublicKey()

	c, cr, l = newClientForServer(s)
	defer c.close()
	// Check for Nonce
	err = json.Unmarshal([]byte(l[5:]), &info)
	if err != nil {
		t.Fatalf("Could not parse INFO json: %v\n", err)
	}
	if info.Nonce == "" {
		t.Fatalf("Expected a non-empty nonce with nkeys defined")
	}
	sigraw, err = kp.Sign([]byte(info.Nonce))
	if err != nil {
		t.Fatalf("Failed signing nonce: %v", err)
	}
	sig = base64.RawURLEncoding.EncodeToString(sigraw)

	// PING needed to flush the +OK to us.
	cs = fmt.Sprintf("CONNECT {\"nkey\":%q,\"sig\":\"%s\",\"verbose\":true,\"pedantic\":true}\r\nPING\r\n", pubKey, sig)
	c.parseAsync(cs)
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "+OK") {
		t.Fatalf("Expected an OK, got: %v", l)
	}
	if c.acc != nats {
		t.Fatalf("Expected the nkey client's account to match 'nats', got %v", c.acc)
	}
}

func TestAccountGlobalDefault(t *testing.T) {
	opts := defaultServerOptions
	s := New(&opts)

	if acc, _ := s.LookupAccount(globalAccountName); acc == nil {
		t.Fatalf("Expected a global default account on a new server, got none.")
	}
	// Make sure we can not create one with same name..
	if _, err := s.RegisterAccount(globalAccountName); err == nil {
		t.Fatalf("Expected error trying to create a new reserved account")
	}

	// Make sure we can not define one in a config file either.
	confFileName := createConfFile(t, []byte(`accounts { $G {} }`))

	if _, err := ProcessConfigFile(confFileName); err == nil {
		t.Fatalf("Expected an error parsing config file with reserved account")
	}
}

func TestAccountCheckStreamImportsEqual(t *testing.T) {
	// Create bare accounts for this test
	fooAcc := NewAccount("foo")
	if err := fooAcc.AddStreamExport(">", nil); err != nil {
		t.Fatalf("Error adding stream export: %v", err)
	}

	barAcc := NewAccount("bar")
	if err := barAcc.AddStreamImport(fooAcc, "foo", "myPrefix"); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	bazAcc := NewAccount("baz")
	if err := bazAcc.AddStreamImport(fooAcc, "foo", "myPrefix"); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if !barAcc.checkStreamImportsEqual(bazAcc) {
		t.Fatal("Expected stream imports to be the same")
	}

	if err := bazAcc.AddStreamImport(fooAcc, "foo.>", ""); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if barAcc.checkStreamImportsEqual(bazAcc) {
		t.Fatal("Expected stream imports to be different")
	}
	if err := barAcc.AddStreamImport(fooAcc, "foo.>", ""); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if !barAcc.checkStreamImportsEqual(bazAcc) {
		t.Fatal("Expected stream imports to be the same")
	}

	// Create another account that is named "foo". We want to make sure
	// that the comparison still works (based on account name, not pointer)
	newFooAcc := NewAccount("foo")
	if err := newFooAcc.AddStreamExport(">", nil); err != nil {
		t.Fatalf("Error adding stream export: %v", err)
	}
	batAcc := NewAccount("bat")
	if err := batAcc.AddStreamImport(newFooAcc, "foo", "myPrefix"); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if err := batAcc.AddStreamImport(newFooAcc, "foo.>", ""); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if !batAcc.checkStreamImportsEqual(barAcc) {
		t.Fatal("Expected stream imports to be the same")
	}
	if !batAcc.checkStreamImportsEqual(bazAcc) {
		t.Fatal("Expected stream imports to be the same")
	}

	// Test with account with different "from"
	expAcc := NewAccount("new_acc")
	if err := expAcc.AddStreamExport(">", nil); err != nil {
		t.Fatalf("Error adding stream export: %v", err)
	}
	aAcc := NewAccount("a")
	if err := aAcc.AddStreamImport(expAcc, "bar", ""); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	bAcc := NewAccount("b")
	if err := bAcc.AddStreamImport(expAcc, "baz", ""); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if aAcc.checkStreamImportsEqual(bAcc) {
		t.Fatal("Expected stream imports to be different")
	}

	// Test with account with different "prefix"
	aAcc = NewAccount("a")
	if err := aAcc.AddStreamImport(expAcc, "bar", "prefix"); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	bAcc = NewAccount("b")
	if err := bAcc.AddStreamImport(expAcc, "bar", "diff_prefix"); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if aAcc.checkStreamImportsEqual(bAcc) {
		t.Fatal("Expected stream imports to be different")
	}

	// Test with account with different "name"
	expAcc = NewAccount("diff_name")
	if err := expAcc.AddStreamExport(">", nil); err != nil {
		t.Fatalf("Error adding stream export: %v", err)
	}
	bAcc = NewAccount("b")
	if err := bAcc.AddStreamImport(expAcc, "bar", "prefix"); err != nil {
		t.Fatalf("Error adding stream import: %v", err)
	}
	if aAcc.checkStreamImportsEqual(bAcc) {
		t.Fatal("Expected stream imports to be different")
	}
}

func TestAccountNoDeadlockOnQueueSubRouteMapUpdate(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port))
	if err != nil {
		t.Fatalf("Error on connect: %v", err)
	}
	defer nc.Close()

	nc.QueueSubscribeSync("foo", "bar")

	var accs []*Account
	for i := 0; i < 10; i++ {
		acc, _ := s.RegisterAccount(fmt.Sprintf("acc%d", i))
		acc.mu.Lock()
		accs = append(accs, acc)
	}

	opts2 := DefaultOptions()
	opts2.Routes = RoutesFromStr(fmt.Sprintf("nats://%s:%d", opts.Cluster.Host, opts.Cluster.Port))
	s2 := RunServer(opts2)
	defer s2.Shutdown()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		for _, acc := range accs {
			acc.mu.Unlock()
		}
		wg.Done()
	}()

	nc.QueueSubscribeSync("foo", "bar")
	nc.Flush()

	wg.Wait()
}

func TestAccountDuplicateServiceImportSubject(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	fooAcc, _ := s.RegisterAccount("foo")
	fooAcc.AddServiceExport("remote1", nil)
	fooAcc.AddServiceExport("remote2", nil)

	barAcc, _ := s.RegisterAccount("bar")
	if err := barAcc.AddServiceImport(fooAcc, "foo", "remote1"); err != nil {
		t.Fatalf("Error adding service import: %v", err)
	}
	if err := barAcc.AddServiceImport(fooAcc, "foo", "remote2"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("Expected an error about duplicate service import subject, got %q", err)
	}

	// However, it is allowed to add more than one service import
	// on the same subject for different exporting accounts
	bazAcc, _ := s.RegisterAccount("baz")
	bazAcc.AddServiceExport("remote1", nil)
	if err := barAcc.AddServiceImport(bazAcc, "foo", "remote1"); err != nil {
		t.Fatalf("Error adding service import: %v", err)
	}
	batAcc, _ := s.RegisterAccount("bat")
	batAcc.AddServiceExport("remote1", nil)
	if err := barAcc.AddServiceImport(batAcc, "foo", "remote1"); err != nil {
		t.Fatalf("Error adding service import: %v", err)
	}

	// But again, can't add for one that has been already added, say bazAcc.
	if err := barAcc.AddServiceImport(bazAcc, "foo", "remote1"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("Expected an error about duplicate service import subject, got %q", err)
	}
}

func TestAccountRemoveServiceImport(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	fooAcc, _ := s.RegisterAccount("foo")
	fooAcc.AddServiceExport("remote1", nil)

	barAcc, _ := s.RegisterAccount("bar")
	err := barAcc.AddServiceImport(fooAcc, "foo", "remote1")
	require_NoError(t, err)

	bazAcc, _ := s.RegisterAccount("baz")
	bazAcc.AddServiceExport("remote1", nil)
	err = barAcc.AddServiceImport(bazAcc, "foo", "remote1")
	require_NoError(t, err)

	batAcc, _ := s.RegisterAccount("bat")
	batAcc.AddServiceExport("remote1", nil)
	err = barAcc.AddServiceImport(batAcc, "foo", "remote1")
	require_NoError(t, err)

	// Check that we can get the service import we expect
	checkGetSI := func(acc, subj string) bool {
		barAcc.mu.RLock()
		defer barAcc.mu.RUnlock()
		si := barAcc.getServiceImportForAccountLocked(acc, subj)
		if si == nil {
			return false
		}
		return si.acc.Name == acc
	}
	require_False(t, checkGetSI("nonsense", "foo"))
	require_False(t, checkGetSI("foo", "nonsense"))
	require_True(t, checkGetSI("foo", "foo"))
	require_True(t, checkGetSI("baz", "foo"))
	require_True(t, checkGetSI("bat", "foo"))

	// Remove service imports one by one and check expected map content.

	// Try first to remove one that does not exists, because of subject
	// or because of account.
	barAcc.removeServiceImport("nonsense", "foo")
	require_True(t, checkGetSI("foo", "foo"))
	require_True(t, checkGetSI("baz", "foo"))
	require_True(t, checkGetSI("bat", "foo"))
	barAcc.removeServiceImport("baz", "nonsense")
	require_True(t, checkGetSI("foo", "foo"))
	require_True(t, checkGetSI("baz", "foo"))
	require_True(t, checkGetSI("bat", "foo"))

	// Remove the 2nd account that was added
	barAcc.removeServiceImport("baz", "foo")
	require_False(t, checkGetSI("baz", "foo"))
	require_True(t, checkGetSI("foo", "foo"))
	require_True(t, checkGetSI("bat", "foo"))

	// Remove the last account that was added
	barAcc.removeServiceImport("bat", "foo")
	require_False(t, checkGetSI("baz", "foo"))
	require_False(t, checkGetSI("bat", "foo"))
	require_True(t, checkGetSI("foo", "foo"))

	// There is only one left, make sure that we still properly check
	// for appropriate subject and account name.
	barAcc.removeServiceImport("nonsense", "foo")
	require_False(t, checkGetSI("baz", "foo"))
	require_False(t, checkGetSI("bat", "foo"))
	require_True(t, checkGetSI("foo", "foo"))
	barAcc.removeServiceImport("foo", "nonsense")
	require_False(t, checkGetSI("baz", "foo"))
	require_False(t, checkGetSI("bat", "foo"))
	require_True(t, checkGetSI("foo", "foo"))

	// Remove the first account that was added
	barAcc.removeServiceImport("foo", "foo")
	require_False(t, checkGetSI("baz", "foo"))
	require_False(t, checkGetSI("bat", "foo"))
	require_False(t, checkGetSI("foo", "foo"))

	// Make sure that the service import map is cleared
	barAcc.mu.RLock()
	sis, ok := barAcc.imports.services["foo"]
	barAcc.mu.RUnlock()
	require_False(t, ok)
	require_Len(t, len(sis), 0)
}

func TestAccountMultipleServiceImportsWithSameSubjectFromDifferentAccounts(t *testing.T) {
	conf := createConfFile(t, []byte(`
		accounts: {
			SVC-E: {
				users: [ { user:svc-e, password:svc-e } ]
				exports: [ { accounts: [CLIENTS], service: "SvcReq.>", response_type: singleton } ]
			}

			SVC-W: {
				users: [ { user:svc-w, password:svc-w } ]
				exports: [ { accounts: [CLIENTS], service: "SvcReq.>", response_type: singleton } ]
			}

			CLIENTS: {
				users: [ { user:cl, password:cl } ]
				imports: [
					{ service: { account: SVC-E, subject: "SvcReq.>" } }
					{ service: { account: SVC-W, subject: "SvcReq.>" } }
				]
			}
		}
		listen: "127.0.0.1:-1"
	`))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	ncE := natsConnect(t, s.ClientURL(), nats.UserInfo("svc-e", "svc-e"))
	defer ncE.Close()
	natsSub(t, ncE, "SvcReq.>", func(m *nats.Msg) {
		m.Respond([]byte("From SVC-E"))
	})
	natsFlush(t, ncE)

	ncW := natsConnect(t, s.ClientURL(), nats.UserInfo("svc-w", "svc-w"))
	defer ncW.Close()
	natsSub(t, ncW, "SvcReq.>", func(m *nats.Msg) {
		m.Respond([]byte("From SVC-W"))
	})
	natsFlush(t, ncW)

	nc := natsConnect(t, s.ClientURL(), nats.UserInfo("cl", "cl"))
	defer nc.Close()
	sub := natsSubSync(t, nc, nats.NewInbox())
	natsPubReq(t, nc, "SvcReq.Test", sub.Subject, []byte("test"))
	msg1 := natsNexMsg(t, sub, time.Second)
	msg2 := natsNexMsg(t, sub, time.Second)
	m1 := string(msg1.Data)
	m2 := string(msg2.Data)
	if (m1 == "From SVC-E" && m2 == "From SVC-W") || (m1 == "From SVC-W" && m2 == "From SVC-E") {
		// Ok
		return
	}
	t.Fatalf("Unexpected responses: m1=%s m2=%s", m1, m2)
}

func TestMultipleStreamImportsWithSameSubjectDifferentPrefix(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	fooAcc, _ := s.RegisterAccount("foo")
	fooAcc.AddStreamExport("test", nil)

	barAcc, _ := s.RegisterAccount("bar")
	barAcc.AddStreamExport("test", nil)

	importAcc, _ := s.RegisterAccount("import")

	if err := importAcc.AddStreamImport(fooAcc, "test", "foo"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if err := importAcc.AddStreamImport(barAcc, "test", "bar"); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now make sure we can see messages from both.
	cimport, crImport, _ := newClientForServer(s)
	defer cimport.close()
	if err := cimport.registerWithAccount(importAcc); err != nil {
		t.Fatalf("Error registering client with 'import' account: %v", err)
	}
	if err := cimport.parse([]byte("SUB *.test 1\r\n")); err != nil {
		t.Fatalf("Error for client 'import' from server: %v", err)
	}

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()
	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}

	cbar, _, _ := newClientForServer(s)
	defer cbar.close()
	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	readMsg := func() {
		t.Helper()
		l, err := crImport.ReadString('\n')
		if err != nil {
			t.Fatalf("Error reading msg header from client 'import': %v", err)
		}
		mraw := msgPat.FindAllStringSubmatch(l, -1)
		if len(mraw) == 0 {
			t.Fatalf("No message received")
		}
		// Consume msg body too.
		if _, err = crImport.ReadString('\n'); err != nil {
			t.Fatalf("Error reading msg body from client 'import': %v", err)
		}
	}

	cbar.parseAsync("PUB test 9\r\nhello-bar\r\n")
	readMsg()

	cfoo.parseAsync("PUB test 9\r\nhello-foo\r\n")
	readMsg()
}

// This should work with prefixes that are different but we also want it to just work with same subject
// being imported from multiple accounts.
func TestMultipleStreamImportsWithSameSubject(t *testing.T) {
	opts := DefaultOptions()
	s := RunServer(opts)
	defer s.Shutdown()

	fooAcc, _ := s.RegisterAccount("foo")
	fooAcc.AddStreamExport("test", nil)

	barAcc, _ := s.RegisterAccount("bar")
	barAcc.AddStreamExport("test", nil)

	importAcc, _ := s.RegisterAccount("import")

	if err := importAcc.AddStreamImport(fooAcc, "test", ""); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Since we allow this now, make sure we do detect a duplicate import from same account etc.
	// That should be not allowed.
	if err := importAcc.AddStreamImport(fooAcc, "test", ""); err != ErrStreamImportDuplicate {
		t.Fatalf("Expected ErrStreamImportDuplicate but got %v", err)
	}

	if err := importAcc.AddStreamImport(barAcc, "test", ""); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Now make sure we can see messages from both.
	cimport, crImport, _ := newClientForServer(s)
	defer cimport.close()
	if err := cimport.registerWithAccount(importAcc); err != nil {
		t.Fatalf("Error registering client with 'import' account: %v", err)
	}
	if err := cimport.parse([]byte("SUB test 1\r\n")); err != nil {
		t.Fatalf("Error for client 'import' from server: %v", err)
	}

	cfoo, _, _ := newClientForServer(s)
	defer cfoo.close()
	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}

	cbar, _, _ := newClientForServer(s)
	defer cbar.close()
	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	readMsg := func() {
		t.Helper()
		l, err := crImport.ReadString('\n')
		if err != nil {
			t.Fatalf("Error reading msg header from client 'import': %v", err)
		}
		mraw := msgPat.FindAllStringSubmatch(l, -1)
		if len(mraw) == 0 {
			t.Fatalf("No message received")
		}
		// Consume msg body too.
		if _, err = crImport.ReadString('\n'); err != nil {
			t.Fatalf("Error reading msg body from client 'import': %v", err)
		}
	}

	cbar.parseAsync("PUB test 9\r\nhello-bar\r\n")
	readMsg()

	cfoo.parseAsync("PUB test 9\r\nhello-foo\r\n")
	readMsg()
}

func TestAccountBasicRouteMapping(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = -1
	s := RunServer(opts)
	defer s.Shutdown()

	acc, _ := s.LookupAccount(DEFAULT_GLOBAL_ACCOUNT)
	acc.AddMapping("foo", "bar")

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	fsub, _ := nc.SubscribeSync("foo")
	bsub, _ := nc.SubscribeSync("bar")
	nc.Publish("foo", nil)
	nc.Flush()

	checkPending := func(sub *nats.Subscription, expected int) {
		t.Helper()
		if n, _, _ := sub.Pending(); n != expected {
			t.Fatalf("Expected %d msgs for %q, but got %d", expected, sub.Subject, n)
		}
	}

	checkPending(fsub, 0)
	checkPending(bsub, 1)

	acc.RemoveMapping("foo")

	nc.Publish("foo", nil)
	nc.Flush()

	checkPending(fsub, 1)
	checkPending(bsub, 1)
}

func TestAccountLeftRightMapping(t *testing.T) {
	// left and right are supported by the subject transform since 2.10.16,
	// so account mappings must accept them like the other functions.
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		accounts {
			A {
				users = [{user: a, password: p}]
				mappings = {
					"foo.*": "bar.{{right(1,2)}}"
					"baz.*": "qux.{{left(1,3)}}"
				}
			}
		}
	`))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	nc := natsConnect(t, s.ClientURL(), nats.UserInfo("a", "p"))
	defer nc.Close()

	sub, err := nc.SubscribeSync("bar.>")
	require_NoError(t, err)
	sub2, err := nc.SubscribeSync("qux.>")
	require_NoError(t, err)
	require_NoError(t, nc.Flush())

	require_NoError(t, nc.Publish("foo.1234", nil))
	require_NoError(t, nc.Publish("baz.1234", nil))
	require_NoError(t, nc.Flush())

	msg, err := sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, msg.Subject, "bar.34")

	msg, err = sub2.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, msg.Subject, "qux.123")
}

func TestAccountWildcardRouteMapping(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = -1
	s := RunServer(opts)
	defer s.Shutdown()

	acc, _ := s.LookupAccount(DEFAULT_GLOBAL_ACCOUNT)

	addMap := func(src, dest string) {
		t.Helper()
		if err := acc.AddMapping(src, dest); err != nil {
			t.Fatalf("Error adding mapping: %v", err)
		}
	}

	addMap("foo.*.*", "bar.$2.$1")
	addMap("bar.*.>", "baz.$1.>")

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	pub := func(subj string) {
		t.Helper()
		err := nc.Publish(subj, nil)
		if err == nil {
			err = nc.Flush()
		}
		if err != nil {
			t.Fatalf("Error publishing: %v", err)
		}
	}

	fsub, _ := nc.SubscribeSync("foo.>")
	bsub, _ := nc.SubscribeSync("bar.>")
	zsub, _ := nc.SubscribeSync("baz.>")

	checkPending := func(sub *nats.Subscription, expected int) {
		t.Helper()
		if n, _, _ := sub.Pending(); n != expected {
			t.Fatalf("Expected %d msgs for %q, but got %d", expected, sub.Subject, n)
		}
	}

	pub("foo.1.2")

	checkPending(fsub, 0)
	checkPending(bsub, 1)
	checkPending(zsub, 0)
}

func TestAccountRouteMappingChangesAfterClientStart(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = -1
	s := RunServer(opts)
	defer s.Shutdown()

	// Create the client first then add in mapping.
	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	nc.Flush()

	acc, _ := s.LookupAccount(DEFAULT_GLOBAL_ACCOUNT)
	acc.AddMapping("foo", "bar")

	fsub, _ := nc.SubscribeSync("foo")
	bsub, _ := nc.SubscribeSync("bar")
	nc.Publish("foo", nil)
	nc.Flush()

	checkPending := func(sub *nats.Subscription, expected int) {
		t.Helper()
		if n, _, _ := sub.Pending(); n != expected {
			t.Fatalf("Expected %d msgs for %q, but got %d", expected, sub.Subject, n)
		}
	}

	checkPending(fsub, 0)
	checkPending(bsub, 1)

	acc.RemoveMapping("foo")

	nc.Publish("foo", nil)
	nc.Flush()

	checkPending(fsub, 1)
	checkPending(bsub, 1)
}

func TestAccountSimpleWeightedRouteMapping(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = -1
	s := RunServer(opts)
	defer s.Shutdown()

	acc, _ := s.LookupAccount(DEFAULT_GLOBAL_ACCOUNT)
	acc.AddWeightedMappings("foo", NewMapDest("bar", 50))

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	fsub, _ := nc.SubscribeSync("foo")
	bsub, _ := nc.SubscribeSync("bar")

	total := 500
	for i := 0; i < total; i++ {
		nc.Publish("foo", nil)
	}
	nc.Flush()

	fpending, _, _ := fsub.Pending()
	bpending, _, _ := bsub.Pending()

	h := total / 2
	tp := h / 5
	min, max := h-tp, h+tp
	if fpending < min || fpending > max {
		t.Fatalf("Expected about %d msgs, got %d and %d", h, fpending, bpending)
	}
}

func TestAccountMultiWeightedRouteMappings(t *testing.T) {
	opts := DefaultOptions()
	opts.Port = -1
	s := RunServer(opts)
	defer s.Shutdown()

	acc, _ := s.LookupAccount(DEFAULT_GLOBAL_ACCOUNT)

	// Check failures for bad weights.
	shouldErr := func(rds ...*MapDest) {
		t.Helper()
		if acc.AddWeightedMappings("foo", rds...) == nil {
			t.Fatalf("Expected an error, got none")
		}
	}
	shouldNotErr := func(rds ...*MapDest) {
		t.Helper()
		if err := acc.AddWeightedMappings("foo", rds...); err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	}

	shouldErr(NewMapDest("bar", 150))
	shouldNotErr(NewMapDest("bar", 50))
	shouldNotErr(NewMapDest("bar", 50), NewMapDest("baz", 50))
	// Same dest duplicated should error.
	shouldErr(NewMapDest("bar", 50), NewMapDest("bar", 50))
	// total over 100
	shouldErr(NewMapDest("bar", 50), NewMapDest("baz", 60))

	acc.RemoveMapping("foo")

	// 20 for original, you can leave it off will be auto-added.
	shouldNotErr(NewMapDest("bar", 50), NewMapDest("baz", 30))

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	fsub, _ := nc.SubscribeSync("foo")
	bsub, _ := nc.SubscribeSync("bar")
	zsub, _ := nc.SubscribeSync("baz")

	// For checking later.
	rds := []struct {
		sub *nats.Subscription
		w   uint8
	}{
		{fsub, 20},
		{bsub, 50},
		{zsub, 30},
	}

	total := 5000
	for i := 0; i < total; i++ {
		nc.Publish("foo", nil)
	}
	nc.Flush()

	for _, rd := range rds {
		pending, _, _ := rd.sub.Pending()
		expected := total / int(100/rd.w)
		tp := expected / 5 // 20%
		min, max := expected-tp, expected+tp
		if pending < min || pending > max {
			t.Fatalf("Expected about %d msgs for %q, got %d", expected, rd.sub.Subject, pending)
		}
	}
}

func TestGlobalAccountRouteMappingsConfiguration(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
	mappings = {
		foo: bar
		foo.*: [ { dest: bar.v1.$1, weight: 40% }, { destination: baz.v2.$1, weight: 20 } ]
		bar.*.*: RAB.$2.$1
    }
    `))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	bsub, _ := nc.SubscribeSync("bar")
	fsub1, _ := nc.SubscribeSync("bar.v1.>")
	fsub2, _ := nc.SubscribeSync("baz.v2.>")
	zsub, _ := nc.SubscribeSync("RAB.>")
	f22sub, _ := nc.SubscribeSync("foo.*")

	checkPending := func(sub *nats.Subscription, expected int) {
		t.Helper()
		if n, _, _ := sub.Pending(); n != expected {
			t.Fatalf("Expected %d msgs for %q, but got %d", expected, sub.Subject, n)
		}
	}

	nc.Publish("foo", nil)
	nc.Publish("bar.11.22", nil)

	total := 500
	for i := 0; i < total; i++ {
		nc.Publish("foo.22", nil)
	}
	nc.Flush()

	checkPending(bsub, 1)
	checkPending(zsub, 1)

	fpending, _, _ := f22sub.Pending()
	fpending1, _, _ := fsub1.Pending()
	fpending2, _, _ := fsub2.Pending()

	if fpending1 < fpending2 || fpending < fpending2 {
		t.Fatalf("Loadbalancing seems off for the foo.* mappings: %d and %d and %d", fpending, fpending1, fpending2)
	}
}

func TestAccountRouteMappingsConfiguration(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
	accounts {
		synadia {
			users = [{user: derek, password: foo}]
			mappings = {
				foo: bar
				foo.*: [ { dest: bar.v1.$1, weight: 40% }, { destination: baz.v2.$1, weight: 20 } ]
				bar.*.*: RAB.$2.$1
		    }
		}
	}
    `))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	// We test functionality above, so for this one just make sure we have mappings for the account.
	acc, _ := s.LookupAccount("synadia")
	if !acc.hasMappings() {
		t.Fatalf("Account %q does not have mappings", "synadia")
	}

	az, err := s.Accountz(&AccountzOptions{"synadia"})
	if err != nil {
		t.Fatalf("Error getting Accountz: %v", err)
	}
	if az.Account == nil {
		t.Fatalf("Expected an Account")
	}
	if len(az.Account.Mappings) != 3 {
		t.Fatalf("Expected %d mappings, saw %d", 3, len(az.Account.Mappings))
	}
}

func TestAccountRouteMappingsWithLossInjection(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
	mappings = {
		foo: { dest: foo, weight: 80% }
		bar: { dest: bar, weight: 0% }
    }
    `))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	sub, _ := nc.SubscribeSync("foo")

	total := 1000
	for i := 0; i < total; i++ {
		nc.Publish("foo", nil)
	}
	nc.Flush()

	if pending, _, _ := sub.Pending(); pending == total {
		t.Fatalf("Expected some loss and pending to not be same as sent")
	}

	sub, _ = nc.SubscribeSync("bar")
	for i := 0; i < total; i++ {
		nc.Publish("bar", nil)
	}
	nc.Flush()

	if pending, _, _ := sub.Pending(); pending != 0 {
		t.Fatalf("Expected all messages to be dropped and pending to be 0, got %d", pending)
	}
}

func TestAccountRouteMappingsWithOriginClusterFilter(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
	mappings = {
		foo: { dest: bar, cluster: SYN, weight: 100% }
    }
    `))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()

	sub, _ := nc.SubscribeSync("foo")

	total := 1000
	for i := 0; i < total; i++ {
		nc.Publish("foo", nil)
	}
	nc.Flush()

	if pending, _, _ := sub.Pending(); pending != total {
		t.Fatalf("Expected pending to be %d, got %d", total, pending)
	}

	s.setClusterName("SYN")
	sub, _ = nc.SubscribeSync("bar")
	for i := 0; i < total; i++ {
		nc.Publish("foo", nil)
	}
	nc.Flush()

	if pending, _, _ := sub.Pending(); pending != total {
		t.Fatalf("Expected pending to be %d, got %d", total, pending)
	}
}

func TestAccountServiceImportWithRouteMappings(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
    accounts {
      foo {
        users = [{user: derek, password: foo}]
        exports = [{service: "request"}]
      }
      bar {
        users = [{user: ivan, password: bar}]
        imports = [{service: {account: "foo", subject:"request"}}]
      }
    }
    `))

	s, opts := RunServerWithConfig(cf)
	defer s.Shutdown()

	acc, _ := s.LookupAccount("foo")
	acc.AddMapping("request", "request.v2")

	// Create the service client first.
	ncFoo := natsConnect(t, fmt.Sprintf("nats://derek:foo@%s:%d", opts.Host, opts.Port))
	defer ncFoo.Close()

	fooSub := natsSubSync(t, ncFoo, "request.v2")
	ncFoo.Flush()

	// Requestor
	ncBar := natsConnect(t, fmt.Sprintf("nats://ivan:bar@%s:%d", opts.Host, opts.Port))
	defer ncBar.Close()

	ncBar.Publish("request", nil)
	ncBar.Flush()

	checkFor(t, time.Second, 10*time.Millisecond, func() error {
		if n, _, _ := fooSub.Pending(); n != 1 {
			return fmt.Errorf("Expected a request for %q, but got %d", fooSub.Subject, n)
		}
		return nil
	})
}

func TestAccountImportsWithWildcardSupport(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
    accounts {
      foo {
        users = [{user: derek, password: foo}]
        exports = [
          { service: "request.*" }
          { stream: "events.>" }
          { stream: "info.*.*.>" }
        ]
      }
      bar {
        users = [{user: ivan, password: bar}]
        imports = [
          { service: {account: "foo", subject:"request.*"}, to:"my.request.*"}
          { stream:  {account: "foo", subject:"events.>"}, to:"foo.events.>"}
          { stream:  {account: "foo", subject:"info.*.*.>"}, to:"foo.info.$2.$1.>"}
        ]
      }
    }
    `))

	s, opts := RunServerWithConfig(cf)
	defer s.Shutdown()

	ncFoo := natsConnect(t, fmt.Sprintf("nats://derek:foo@%s:%d", opts.Host, opts.Port))
	defer ncFoo.Close()

	ncBar := natsConnect(t, fmt.Sprintf("nats://ivan:bar@%s:%d", opts.Host, opts.Port))
	defer ncBar.Close()

	// Create subscriber for the service endpoint in foo.
	_, err := ncFoo.QueueSubscribe("request.*", "t22", func(m *nats.Msg) {
		if m.Subject != "request.22" {
			t.Fatalf("Expected literal subject for request, got %q", m.Subject)
		}
		m.Respond([]byte("yes!"))
	})
	if err != nil {
		t.Fatalf("Error on subscribe: %v", err)
	}
	ncFoo.Flush()

	// Now test service import.
	resp, err := ncBar.Request("my.request.22", []byte("yes?"), time.Second)
	if err != nil {
		t.Fatalf("Expected a response")
	}
	if string(resp.Data) != "yes!" {
		t.Fatalf("Expected a response of %q, got %q", "yes!", resp.Data)
	}

	// Now test stream imports.
	esub, _ := ncBar.SubscribeSync("foo.events.*") // subset
	isub, _ := ncBar.SubscribeSync("foo.info.>")
	ncBar.Flush()

	// Now publish some stream events.
	ncFoo.Publish("events.22", nil)
	ncFoo.Publish("info.11.22.bar", nil)
	ncFoo.Flush()

	checkPending := func(sub *nats.Subscription, expected int) {
		t.Helper()
		checkFor(t, time.Second, 10*time.Millisecond, func() error {
			if n, _, _ := sub.Pending(); n != expected {
				return fmt.Errorf("Expected %d msgs for %q, but got %d", expected, sub.Subject, n)
			}
			return nil
		})
	}

	checkPending(esub, 1)
	checkPending(isub, 1)

	// Now check to make sure the subjects are correct etc.
	m, err := esub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if m.Subject != "foo.events.22" {
		t.Fatalf("Incorrect subject for stream import, expected %q, got %q", "foo.events.22", m.Subject)
	}

	m, err = isub.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if m.Subject != "foo.info.22.11.bar" {
		t.Fatalf("Incorrect subject for stream import, expected %q, got %q", "foo.info.22.11.bar", m.Subject)
	}
}

// duplicates TestJWTAccountImportsWithWildcardSupport (jwt_test.go) in config
func TestAccountImportsWithWildcardSupportStreamAndService(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
    accounts {
      foo {
        users = [{user: derek, password: foo}]
        exports = [
          { service: "$request.*.$in.*.>" }
          { stream: "$events.*.$in.*.>" }
        ]
      }
      bar {
        users = [{user: ivan, password: bar}]
        imports = [
          { service: {account: "foo", subject:"$request.*.$in.*.>"}, to:"my.request.$2.$1.>"}
          { stream:  {account: "foo", subject:"$events.*.$in.*.>"}, to:"my.events.$2.$1.>"}
        ]
      }
    }
    `))

	s, opts := RunServerWithConfig(cf)
	defer s.Shutdown()

	ncFoo := natsConnect(t, fmt.Sprintf("nats://derek:foo@%s:%d", opts.Host, opts.Port))
	defer ncFoo.Close()

	ncBar := natsConnect(t, fmt.Sprintf("nats://ivan:bar@%s:%d", opts.Host, opts.Port))
	defer ncBar.Close()

	// Create subscriber for the service endpoint in foo.
	_, err := ncFoo.Subscribe("$request.>", func(m *nats.Msg) {
		if m.Subject != "$request.2.$in.1.bar" {
			t.Fatalf("Expected literal subject for request, got %q", m.Subject)
		}
		m.Respond([]byte("yes!"))
	})
	if err != nil {
		t.Fatalf("Error on subscribe: %v", err)
	}
	ncFoo.Flush()

	// Now test service import.
	if resp, err := ncBar.Request("my.request.1.2.bar", []byte("yes?"), time.Second); err != nil {
		t.Fatalf("Expected a response")
	} else if string(resp.Data) != "yes!" {
		t.Fatalf("Expected a response of %q, got %q", "yes!", resp.Data)
	}
	subBar, err := ncBar.SubscribeSync("my.events.>")
	if err != nil {
		t.Fatalf("Expected a response")
	}
	ncBar.Flush()

	ncFoo.Publish("$events.1.$in.2.bar", nil)

	m, err := subBar.NextMsg(time.Second)
	if err != nil {
		t.Fatalf("Expected a response")
	}
	if m.Subject != "my.events.2.1.bar" {
		t.Fatalf("Expected literal subject for request, got %q", m.Subject)
	}
}

func BenchmarkNewRouteReply(b *testing.B) {
	opts := defaultServerOptions
	s := New(&opts)
	g := s.globalAccount()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.newServiceReply(false)
	}
}

func TestSamplingHeader(t *testing.T) {
	test := func(expectSampling bool, h http.Header) {
		t.Helper()
		b := strings.Builder{}
		b.WriteString("\r\n") // simulate status line
		h.Write(&b)
		b.WriteString("\r\n")
		hdrString := b.String()
		c := &client{parseState: parseState{msgBuf: []byte(hdrString), pa: pubArg{hdr: len(hdrString)}}}
		sample, hdr := shouldSample(&serviceLatency{0, "foo"}, c)
		if expectSampling {
			if !sample {
				t.Fatal("Expected to sample")
			} else if hdr == nil {
				t.Fatal("Expected a header")
			}
			for k, v := range h {
				if hdr.Get(k) != v[0] {
					t.Fatal("Expect header to match")
				}
			}
		} else {
			if sample {
				t.Fatal("Expected not to sample")
			} else if hdr != nil {
				t.Fatal("Expected no header")
			}
		}
	}

	test(false, http.Header{"Uber-Trace-Id": []string{"0:0:0:0"}})
	test(false, http.Header{"Uber-Trace-Id": []string{"0:0:0:00"}}) // one byte encoded as two hex digits
	test(true, http.Header{"Uber-Trace-Id": []string{"0:0:0:1"}})
	test(true, http.Header{"Uber-Trace-Id": []string{"0:0:0:01"}})
	test(true, http.Header{"Uber-Trace-Id": []string{"0:0:0:5"}}) // debug and sample
	test(true, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:5adb976bfc1f95c1:479fefe9525eddb:1"}})
	test(true, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:479fefe9525eddb:0:1"}})
	test(false, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:5adb976bfc1f95c1:479fefe9525eddb:0"}})
	test(false, http.Header{"Uber-Trace-Id": []string{"479fefe9525eddb:479fefe9525eddb:0:0"}})

	test(true, http.Header{"X-B3-Sampled": []string{"1"}})
	test(false, http.Header{"X-B3-Sampled": []string{"0"}})
	test(true, http.Header{"X-B3-TraceId": []string{"80f198ee56343ba864fe8b2a57d3eff7"}}) // decision left to recipient
	test(false, http.Header{"X-B3-TraceId": []string{"80f198ee56343ba864fe8b2a57d3eff7"}, "X-B3-Sampled": []string{"0"}})
	test(true, http.Header{"X-B3-TraceId": []string{"80f198ee56343ba864fe8b2a57d3eff7"}, "X-B3-Sampled": []string{"1"}})

	test(false, http.Header{"B3": []string{"0"}}) // deny only
	test(false, http.Header{"B3": []string{"0-0-0-0"}})
	test(false, http.Header{"B3": []string{"0-0-0"}})
	test(true, http.Header{"B3": []string{"0-0-1-0"}})
	test(true, http.Header{"B3": []string{"0-0-1"}})
	test(true, http.Header{"B3": []string{"0-0-d"}}) // debug is not a deny
	test(true, http.Header{"B3": []string{"80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1"}})
	test(true, http.Header{"B3": []string{"80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-1-05e3ac9a4f6e3b90"}})
	test(false, http.Header{"B3": []string{"80f198ee56343ba864fe8b2a57d3eff7-e457b5a2e4d86bd1-0-05e3ac9a4f6e3b90"}})

	test(true, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"}})
	test(true, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-27"}})
	test(false, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"}})
	test(false, http.Header{"traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-22"}})
}

func TestAccountSystemPermsWithGlobalAccess(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		accounts {
			$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
		}
	`))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// Make sure we can connect with no auth to global account as normal.
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer nc.Close()

	// Make sure we can connect to the system account with correct credentials.
	sc, err := nats.Connect(s.ClientURL(), nats.UserInfo("admin", "s3cr3t!"))
	if err != nil {
		t.Fatalf("Failed to create system client: %v", err)
	}
	defer sc.Close()
}

const importSubscriptionOverlapTemplate = `
listen: 127.0.0.1:-1
accounts: {
  ACCOUNT_X: {
	users: [
	  {user: publisher}
	]
	exports: [
	  {stream: %s}
	]
  },
  ACCOUNT_Y: {
	users: [
	  {user: subscriber}
	]
	imports: [
	  {stream: {account: ACCOUNT_X, subject: %s }, %s}
	]
  }
}`

func TestImportSubscriptionPartialOverlapWithPrefix(t *testing.T) {
	cf := createConfFile(t, []byte(fmt.Sprintf(importSubscriptionOverlapTemplate, ">", ">", "prefix: myprefix")))

	s, opts := RunServerWithConfig(cf)
	defer s.Shutdown()

	ncX := natsConnect(t, fmt.Sprintf("nats://%s:%s@127.0.0.1:%d", "publisher", "", opts.Port))
	defer ncX.Close()

	ncY := natsConnect(t, fmt.Sprintf("nats://%s:%s@127.0.0.1:%d", "subscriber", "", opts.Port))
	defer ncY.Close()

	for _, subj := range []string{">", "myprefix.*", "myprefix.>", "myprefix.test", "*.>", "*.*", "*.test"} {
		t.Run(subj, func(t *testing.T) {
			sub, err := ncY.SubscribeSync(subj)
			sub.AutoUnsubscribe(1)
			require_NoError(t, err)
			require_NoError(t, ncY.Flush())

			ncX.Publish("test", []byte("hello"))

			m, err := sub.NextMsg(time.Second)
			require_NoError(t, err)
			require_True(t, string(m.Data) == "hello")
		})
	}
}

func TestImportSubscriptionPartialOverlapWithTransform(t *testing.T) {
	cf := createConfFile(t, []byte(fmt.Sprintf(importSubscriptionOverlapTemplate, "*.*.>", "*.*.>", "to: myprefix.$2.$1.>")))

	s, opts := RunServerWithConfig(cf)
	defer s.Shutdown()

	ncX := natsConnect(t, fmt.Sprintf("nats://%s:%s@127.0.0.1:%d", "publisher", "", opts.Port))
	defer ncX.Close()

	ncY := natsConnect(t, fmt.Sprintf("nats://%s:%s@127.0.0.1:%d", "subscriber", "", opts.Port))
	defer ncY.Close()

	for _, subj := range []string{">", "*.*.*.>", "*.2.*.>", "*.*.1.>", "*.2.1.>", "*.*.*.*", "*.2.1.*", "*.*.*.test",
		"*.*.1.test", "*.2.*.test", "*.2.1.test", "myprefix.*.*.*", "myprefix.>", "myprefix.*.>", "myprefix.*.*.>",
		"myprefix.2.>", "myprefix.2.1.>", "myprefix.*.1.>", "myprefix.2.*.>", "myprefix.2.1.*", "myprefix.*.*.test",
		"myprefix.2.1.test"} {
		t.Run(subj, func(t *testing.T) {
			sub, err := ncY.SubscribeSync(subj)
			sub.AutoUnsubscribe(1)
			require_NoError(t, err)
			require_NoError(t, ncY.Flush())

			ncX.Publish("1.2.test", []byte("hello"))

			m, err := sub.NextMsg(time.Second)
			require_NoError(t, err)
			require_True(t, string(m.Data) == "hello")
			require_Equal(t, m.Subject, "myprefix.2.1.test")
		})
	}
}

func TestAccountLimitsServerConfig(t *testing.T) {
	cf := createConfFile(t, []byte(`
	port: -1
	max_connections: 10
	accounts {
		MAXC {
			users = [{user: derek, password: foo}]
			limits {
				max_connections: 5
				max_subs: 10
				max_payload: 32k
				max_leafnodes: 1
			}
		}
	}
    `))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	acc, err := s.lookupAccount("MAXC")
	require_NoError(t, err)

	if mc := acc.MaxActiveConnections(); mc != 5 {
		t.Fatalf("Did not set MaxActiveConnections properly, expected 5, got %d", mc)
	}
	if mlc := acc.MaxActiveLeafNodes(); mlc != 1 {
		t.Fatalf("Did not set MaxActiveLeafNodes properly, expected 1, got %d", mlc)
	}

	// Do quick test on connections, but if they are registered above should be good.
	for i := 0; i < 5; i++ {
		c, err := nats.Connect(s.ClientURL(), nats.UserInfo("derek", "foo"))
		require_NoError(t, err)
		defer c.Close()
	}

	// Should fail.
	_, err = nats.Connect(s.ClientURL(), nats.UserInfo("derek", "foo"))
	require_Error(t, err)
}

// Connections being closed should be the newer ones in case of JWT limits.
func TestAccountMaxConnectionsDisconnectsNewestFirst(t *testing.T) {
	cf := createConfFile(t, []byte(`
        port: -1
        server_name: A
        accounts {
                TEST {
                        users = [
                          {user: user1, password: foo}
                          {user: user2, password: foo}
                          {user: user3, password: foo}
                        ]
                        limits {
                                max_connections: 3
                        }
                }
        }
        `))
	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	var conns []*nats.Conn

	disconnects := make([]chan error, 0)
	for i := 1; i <= 3; i++ {
		disconnectCh := make(chan error)
		c, err := nats.Connect(
			s.ClientURL(),
			nats.UserInfo(fmt.Sprintf("user%d", i), "foo"),
			nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
				disconnectCh <- err
			}),
			nats.NoReconnect(),
		)
		require_NoError(t, err)
		defer c.Close()
		conns = append(conns, c)
		disconnects = append(disconnects, disconnectCh)
		// Small delay to ensure distinct start times.
		time.Sleep(10 * time.Millisecond)
	}
	acc, err := s.lookupAccount("TEST")
	require_NoError(t, err)
	require_Equal(t, acc.NumConnections(), 3)

	// Force account update to trigger connection limit enforcement.
	accClaims := jwt.NewAccountClaims(acc.Name)
	accClaims.Limits.Conn = 2
	s.UpdateAccountClaims(acc, accClaims)

	// Wait for disconnections from the most recent client.
	disconnectCh := disconnects[2]
	select {
	case <-disconnectCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Expected newest connection to disconnect!")
	}

	// Check which connections are still active
	// The newest connection (last one created) should be disconnected first.
	activeConnections := 0
	var connected []int
	for i, conn := range conns {
		if !conn.IsClosed() {
			activeConnections++
			connected = append(connected, i)
		}
	}
	require_Equal(t, activeConnections, 2)
	require_Equal(t, len(connected), 2)

	// The first two connections should still be connected.
	require_Equal(t, connected[0], 0)
	require_Equal(t, connected[1], 1)

	// The newest connection should be closed.
	require_True(t, conns[2].IsClosed())
}

func TestAccountUpdateRemoteServerDisconnectsNewestFirst(t *testing.T) {
	cf := createConfFile(t, []byte(`
          port: -1
          accounts {
            TEST {
              users = [{user: dummy, password: foo}]
              limits {
                max_connections: 5
              }
            }
          }
        `))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	acc, err := s.lookupAccount("TEST")
	require_NoError(t, err)

	for i := 0; i < 3; i++ {
		c, err := nats.Connect(s.ClientURL(), nats.UserInfo("dummy", "foo"))
		require_NoError(t, err)
		defer c.Close()

		// Small delay to ensure distinct start times.
		time.Sleep(10 * time.Millisecond)
	}
	require_Equal(t, acc.NumConnections(), 3)

	// Simulate remote server reporting connections that would exceed the limit.
	// Remote has 4 + we have 3, meaning that 2 will have to be disconnected.
	remoteServerMsg := &AccountNumConns{
		Server: ServerInfo{
			ID:   "fake-server-1",
			Name: "fake-nats-1",
		},
		AccountStat: AccountStat{
			Account: "TEST",
			Conns:   4,
		},
	}
	toDisconnect := acc.updateRemoteServer(remoteServerMsg)

	// Should want to disconnect 2 clients (7 total - 5 max conns limit = 2 over).
	require_Equal(t, len(toDisconnect), 2)

	// Verify the returned clients are in reverse chronological order.
	var startTimes []time.Time
	for _, c := range toDisconnect {
		startTimes = append(startTimes, c.start)
	}
	if !startTimes[0].After(startTimes[1]) {
		t.Fatalf("Expected clients to be in reverse chronological order: %v is before %v", startTimes[0], startTimes[1])
	}

	// The clients to disconnect should be the newest ones we created.
	disconnected := make(map[uint64]bool)
	for _, c := range toDisconnect {
		disconnected[c.cid] = true
	}

	// Get all current clients and find the oldest ones.
	allClients := acc.getClients()
	byStartTime := make([]*client, len(allClients))
	copy(byStartTime, allClients)
	slices.SortFunc(byStartTime, func(i, j *client) int {
		return i.start.Compare(j.start)
	})

	// The last two clients in the sorted list should be the ones selected for disconnection.
	require_False(t, disconnected[byStartTime[0].cid])
	require_True(t, disconnected[byStartTime[1].cid])
	require_True(t, disconnected[byStartTime[2].cid])
}

func TestAccountMaxConnectionsDuringLameDuckMode(t *testing.T) {
	cf := createConfFile(t, []byte(`
        port: -1
        accounts {
                TEST {
                        users = [
                          {user: user, password: user}
                        ]
                        limits {
                                max_connections: 3
                        }
                }
        }
		cluster {
		  listen: 127.0.0.1:7248
		  name: "abc"
		}
		no_auth_user: user
		lame_duck_grace_period: 1s
        `))

	optsA, err := ProcessConfigFile(cf)
	require_NoError(t, err)
	optsA.NoSigs, optsA.NoLog = true, true
	optsA.ServerName = "A"
	srvA := RunServer(optsA)
	defer srvA.Shutdown()
	optsB := nextServerOpts(optsA)
	optsB.Routes = RoutesFromStr(fmt.Sprintf("nats://%s:%d", optsA.Cluster.Host, optsA.Cluster.Port))
	optsB.ServerName = "B"
	srvB := RunServer(optsB)
	defer srvB.Shutdown()

	checkClusterFormed(t, srvA, srvB)

	disconnects := make([]chan error, 0)
	for range 3 {
		disconnectCh := make(chan error)
		c, err := nats.Connect(
			srvA.ClientURL(),
			nats.UserInfo("user", "user"),
			nats.DisconnectErrHandler(func(c *nats.Conn, err error) {
				disconnectCh <- err
			}),
		)
		require_NoError(t, err)
		defer c.Close()
		disconnects = append(disconnects, disconnectCh)
		// Small delay to ensure distinct start times.
		time.Sleep(10 * time.Millisecond)
	}
	acc, err := srvA.lookupAccount("TEST")
	require_NoError(t, err)
	require_Equal(t, acc.NumConnections(), 3)

	go srvA.LameDuckShutdown()

	for _, disconnectCh := range disconnects {
		select {
		case err := <-disconnectCh:
			require_Equal(t, err.Error(), "EOF")
		case <-time.After(5 * time.Second):
			t.Fatal("Expected LDM reconnect")
		}
	}
}

func TestAccountUserSubPermsWithQueueGroups(t *testing.T) {
	cf := createConfFile(t, []byte(`
	listen: 127.0.0.1:-1

	authorization {
	users = [
		{ user: user, password: "pass",
			permissions: {
				publish: "foo.restricted"
				subscribe: { allow: "foo.>", deny: "foo.restricted" }
				allow_responses: { max: 1, ttl: 0s }
			}
		}
	]}
    `))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	nc, err := nats.Connect(s.ClientURL(), nats.UserInfo("user", "pass"))
	require_NoError(t, err)
	defer nc.Close()

	// qsub solo.
	qsub, err := nc.QueueSubscribeSync("foo.>", "qg")
	require_NoError(t, err)

	err = nc.Publish("foo.restricted", []byte("RESTRICTED"))
	require_NoError(t, err)
	nc.Flush()

	// Expect no msgs.
	checkSubsPending(t, qsub, 0)
}

func TestAccountImportCycle(t *testing.T) {
	tmpl := `
	port: -1
	accounts: {
		CP: {
			users: [
				{user: cp, password: cp},
			],
			exports: [
				{service: "q1.>", response_type: Singleton},
				{service: "q2.>", response_type: Singleton},
				%s
			],
		},
		A: {
			users: [
				{user: a, password: a},
			],
			imports: [
				{service: {account: CP, subject: "q1.>"}},
				{service: {account: CP, subject: "q2.>"}},
				%s
			]
		},
	}
	`
	cf := createConfFile(t, []byte(fmt.Sprintf(tmpl, _EMPTY_, _EMPTY_)))
	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()
	ncCp, err := nats.Connect(s.ClientURL(), nats.UserInfo("cp", "cp"))
	require_NoError(t, err)
	defer ncCp.Close()
	ncA, err := nats.Connect(s.ClientURL(), nats.UserInfo("a", "a"))
	require_NoError(t, err)
	defer ncA.Close()
	// setup responder
	natsSub(t, ncCp, "q1.>", func(m *nats.Msg) { m.Respond([]byte("reply")) })
	// setup requestor
	ib := "q2.inbox"
	subAResp, err := ncA.SubscribeSync(ib)
	ncA.Flush()
	require_NoError(t, err)
	req := func() {
		t.Helper()
		// send request
		err = ncA.PublishRequest("q1.a", ib, []byte("test"))
		ncA.Flush()
		require_NoError(t, err)
		mRep, err := subAResp.NextMsg(time.Second)
		require_NoError(t, err)
		require_Equal(t, string(mRep.Data), "reply")
	}
	req()

	// Update the config and do a config reload and make sure it all still work
	changeCurrentConfigContentWithNewContent(t, cf, []byte(
		fmt.Sprintf(tmpl, `{service: "q3.>", response_type: Singleton},`, `{service: {account: CP, subject: "q3.>"}},`)))
	err = s.Reload()
	require_NoError(t, err)
	req()
}

func TestAccountImportOwnExport(t *testing.T) {
	conf := createConfFile(t, []byte(`
		port: -1
		accounts: {
			A: {
			exports: [
				{ service: echo, accounts: [A], latency: { subject: "latency.echo" } }
			],
			imports: [
				{ service: { account: A, subject: echo } }
			]

			users: [
				{ user: user, pass: pass }
			]
			}
		}
	`))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	nc := natsConnect(t, s.ClientURL(), nats.UserInfo("user", "pass"))
	defer nc.Close()

	natsSub(t, nc, "echo", func(m *nats.Msg) { m.Respond(nil) })
	_, err := nc.Request("echo", []byte("request"), time.Second)
	require_NoError(t, err)
}

// Test for a bug that would cause duplicate deliveries in certain situations when
// service export/imports and leafnodes involved.
// https://github.com/nats-io/nats-server/issues/3191
func TestAccountImportDuplicateResponseDeliveryWithLeafnodes(t *testing.T) {
	conf := createConfFile(t, []byte(`
		port: -1
		accounts: {
			A: {
				users = [{user: A, password: P}]
				exports: [ { service: "foo", response_type: stream } ]
			}
			B: {
				users = [{user: B, password: P}]
				imports: [ { service: {account: "A", subject:"foo"} } ]
			}
		}
		leaf { listen: "127.0.0.1:17222" }
	`))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// Requestors will connect to account B.
	nc, err := nats.Connect(s.ClientURL(), nats.UserInfo("B", "P"))
	require_NoError(t, err)
	defer nc.Close()

	// By sending a request (regardless of no responders), this will trigger a wildcard _R_ subscription since
	// we do not have a leafnode connected.
	nc.PublishRequest("foo", "reply", nil)
	nc.Flush()

	// Now connect the LN. This will be where the service responder lives.
	conf = createConfFile(t, []byte(`
		port: -1
		leaf {
			remotes [ { url: "nats://A:P@127.0.0.1:17222" } ]
		}
	`))
	ln, _ := RunServerWithConfig(conf)
	defer ln.Shutdown()
	checkLeafNodeConnected(t, s)

	// Now attach a responder to the LN.
	lnc, err := nats.Connect(ln.ClientURL())
	require_NoError(t, err)
	defer lnc.Close()

	lnc.Subscribe("foo", func(m *nats.Msg) {
		m.Respond([]byte("bar"))
	})
	lnc.Flush()
	checkSubInterest(t, s, "A", "foo", time.Second)

	// Make sure it works, but request only wants one, so need second test to show failure, but
	// want to make sure we are wired up correctly.
	_, err = nc.Request("foo", nil, time.Second)
	require_NoError(t, err)

	// Now setup inbox reply so we can check if we get multiple responses.
	reply := nats.NewInbox()
	sub, err := nc.SubscribeSync(reply)
	require_NoError(t, err)

	nc.PublishRequest("foo", reply, nil)

	// Do another to make sure we know the other request will have been processed too.
	_, err = nc.Request("foo", nil, time.Second)
	require_NoError(t, err)

	if n, _, _ := sub.Pending(); n > 1 {
		t.Fatalf("Expected only 1 response, got %d", n)
	}
}

func TestAccountReloadServiceImportPanic(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		accounts {
			A {
				users = [ { user: "a", pass: "p" } ]
				exports [ { service: "HELP" } ]
			}
			B {
				users = [ { user: "b", pass: "p" } ]
				imports [ { service: { account: A, subject: "HELP"} } ]
			}
			$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
		}
	`))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// Now connect up the subscriber for HELP. No-op for this test.
	nc, _ := jsClientConnect(t, s, nats.UserInfo("a", "p"))
	defer nc.Close()

	_, err := nc.Subscribe("HELP", func(m *nats.Msg) { m.Respond([]byte("OK")) })
	require_NoError(t, err)
	// Make sure the subscription is processed before using a new connection to publish.
	natsFlush(t, nc)

	// Now create connection to account b where we will publish to HELP.
	nc, _ = jsClientConnect(t, s, nats.UserInfo("b", "p"))
	defer nc.Close()

	// We want to continually be publishing messages that will trigger the service import while calling reload.
	done := make(chan bool)
	var wg sync.WaitGroup
	wg.Add(1)

	var requests, responses atomic.Uint64
	reply := nats.NewInbox()
	_, err = nc.Subscribe(reply, func(m *nats.Msg) { responses.Add(1) })
	require_NoError(t, err)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				nc.PublishRequest("HELP", reply, []byte("HELP"))
				requests.Add(1)
			}
		}
	}()

	// Perform a bunch of reloads.
	for i := 0; i < 1000; i++ {
		require_NoError(t, s.Reload())
	}

	close(done)
	wg.Wait()

	totalRequests := requests.Load()
	checkFor(t, 20*time.Second, 250*time.Millisecond, func() error {
		resp := responses.Load()
		if resp == totalRequests {
			return nil
		}
		return fmt.Errorf("Have not received all responses, want %d got %d", totalRequests, resp)
	})
}

// https://github.com/nats-io/nats-server/issues/4674
func TestAccountServiceAndStreamExportDoubleDelivery(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: 127.0.0.1:-1
		accounts: {
			tenant1: {
				jetstream: enabled
				users: [ { user: "one", password: "one" } ]
				exports: [
					{ stream: "DW.>" }
					{ service: "DW.>" }
				]
 			}
			global: {
				jetstream: enabled
				users: [ { user: "global", password: "global" } ]
				imports: [
					{ stream: { account: tenant1, subject: "DW.>" }, prefix: tenant1 }
					{ service: { account: tenant1, subject: "DW.>" }, to: "tenant1.DW.>" }
				]
			}
			$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
		}
	`))

	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// Now connect up the subscriber for HELP. No-op for this test.
	nc, _ := jsClientConnect(t, s, nats.UserInfo("one", "one"))
	defer nc.Close()

	var msgs atomic.Int32
	_, err := nc.Subscribe(">", func(m *nats.Msg) {
		msgs.Add(1)
	})
	require_NoError(t, err)

	nc.Publish("DW.test.123", []byte("test"))
	time.Sleep(200 * time.Millisecond)
	require_Equal(t, msgs.Load(), 1)
}

func TestAccountServiceImportNoResponders(t *testing.T) {
	// Setup NATS server.
	cf := createConfFile(t, []byte(`
				port: -1
				accounts: {
					accExp: {
						users: [{user: accExp, password: accExp}]
						exports: [{service: "foo"}]
					}
					accImp: {
						users: [{user: accImp, password: accImp}]
						imports: [{service: {account: accExp, subject: "foo"}}]
					}
				}
			`))

	s, _ := RunServerWithConfig(cf)
	defer s.Shutdown()

	// Connect to the import account. We will not setup any responders, so a request should
	// error out with ErrNoResponders.
	nc := natsConnect(t, s.ClientURL(), nats.UserInfo("accImp", "accImp"))
	defer nc.Close()

	_, err := nc.Request("foo", []byte("request"), 250*time.Millisecond)
	require_Error(t, err, nats.ErrNoResponders)
}

// Test that service import replies are delivered when the requester's reply inbox
// is subscribed on a different cluster node.
func TestAccountServiceImportReplyDroppedAcrossClusterRoutes(t *testing.T) {
	tmpl := `
		server_name: %s
		listen: 127.0.0.1:-1
		cluster {
			name: test
			listen: 127.0.0.1:-1
			%s
		}
		accounts {
			A {
				users = [{ user: a, password: a }]
				imports = [{ service: { account: B, subject: svc } }]
			}
			B {
				users = [{ user: b, password: b }]
				exports = [{ service: svc, accounts: [A] }]
			}
		}
	`
	confA := createConfFile(t, []byte(fmt.Sprintf(tmpl, "node-A", "")))
	srvA, optsA := RunServerWithConfig(confA)
	defer srvA.Shutdown()

	confB := createConfFile(t, []byte(fmt.Sprintf(tmpl, "node-B",
		fmt.Sprintf(`routes = ["nats-route://127.0.0.1:%d"]`, optsA.Cluster.Port))))
	srvB, _ := RunServerWithConfig(confB)
	defer srvB.Shutdown()

	checkClusterFormed(t, srvA, srvB)

	// Responder on node-A, account B.
	ncB := natsConnect(t, srvA.ClientURL(), nats.UserInfo("b", "b"))
	defer ncB.Close()
	natsSub(t, ncB, "svc", func(m *nats.Msg) { m.Respond([]byte("pong")) })
	natsFlush(t, ncB)

	// Wait for B's "svc" sub to propagate to node-B so it can route the request.
	checkSubInterest(t, srvB, "B", "svc", time.Second)

	// Subscriber on node-A, account A: explicit reply inbox.
	// This subscription will be a ROUTE sub on node-B once it propagates.
	ncSub := natsConnect(t, srvA.ClientURL(), nats.UserInfo("a", "a"))
	defer ncSub.Close()
	inbox := "_INBOX.xroute.reply"
	replyCh := make(chan *nats.Msg, 1)
	_, err := ncSub.Subscribe(inbox, func(m *nats.Msg) { replyCh <- m })
	require_NoError(t, err)
	natsFlush(t, ncSub)

	// Wait for the inbox to appear as a ROUTE sub on node-B.
	checkSubInterest(t, srvB, "A", inbox, time.Second)

	// Publisher on node-B, account A: publish with explicit cross-node reply.
	// The response service import on node-B receives the reply via route
	// (c.kind==ROUTER) and must forward it back to the ROUTE sub for the inbox.
	ncPub := natsConnect(t, srvB.ClientURL(), nats.UserInfo("a", "a"))
	defer ncPub.Close()
	err = ncPub.PublishMsg(&nats.Msg{Subject: "svc", Reply: inbox, Data: []byte("ping")})
	require_NoError(t, err)

	select {
	case msg := <-replyCh:
		require_Equal(t, string(msg.Data), "pong")
	case <-time.After(3 * time.Second):
		t.Fatal("reply not received — service import reply was dropped across cluster routes")
	}

	// Reverse: subscribe on node-B, publish from node-A.
	ncSub2 := natsConnect(t, srvB.ClientURL(), nats.UserInfo("a", "a"))
	defer ncSub2.Close()
	inbox2 := "_INBOX.xroute.reply2"
	replyCh2 := make(chan *nats.Msg, 1)
	_, err = ncSub2.Subscribe(inbox2, func(m *nats.Msg) { replyCh2 <- m })
	require_NoError(t, err)
	natsFlush(t, ncSub2)
	checkSubInterest(t, srvA, "A", inbox2, time.Second)

	err = ncSub.PublishMsg(&nats.Msg{Subject: "svc", Reply: inbox2, Data: []byte("ping")})
	require_NoError(t, err)

	select {
	case msg := <-replyCh2:
		require_Equal(t, string(msg.Data), "pong")
	case <-time.After(3 * time.Second):
		t.Fatal("reverse reply not received — service import reply was dropped across cluster routes")
	}
}

func TestStreamActivationExpiredNoMatchDoesNotInvalidate(t *testing.T) {
	// Account performing the import.
	a := NewAccount("importer")
	// The account we will pass as the (non-matching) export account.
	exportAcc := NewAccount("exporter")
	// A different, still-valid stream import that does NOT match the
	// (exportAcc, subject) pair passed to streamActivationExpired.
	otherAcc := NewAccount("other")
	si := &streamImport{
		acc:  otherAcc,
		from: "other.subject",
		// claim is nil, so checkActivation would return false and the
		// buggy code would wrongly mark this import invalid.
		claim: nil,
	}
	a.imports.streams = []*streamImport{si}

	// No matching import.
	a.streamActivationExpired(exportAcc, "nomatch.subject")
	if si.invalid {
		t.Fatalf("unrelated stream import was wrongly invalidated on no match")
	}
}

func TestRemoveAllServiceImportSubsNoRaceUnderConcurrentReaders(t *testing.T) {
	for range 2000 {
		a := &Account{}
		a.imports.services = make(map[string][]*serviceImport)
		for i := 0; i < 8; i++ {
			si := &serviceImport{sid: []byte("sid")}
			a.imports.services[fmt.Sprintf("svc.%d", i)] = []*serviceImport{si}
		}

		var wg sync.WaitGroup
		wg.Add(2)

		// Reader: mimics updateAccountClaimsWithRefresh reading a.ic and
		// iterating si.sid under a read lock.
		go func() {
			defer wg.Done()
			a.mu.RLock()
			_ = a.ic
			for _, sis := range a.imports.services {
				for _, si := range sis {
					_ = si.sid
				}
			}
			a.mu.RUnlock()
		}()

		// Writer: nils si.sid and a.ic. a.ic is nil so the post-unlock
		// path returns early and does not touch a real client.
		go func() {
			defer wg.Done()
			a.removeAllServiceImportSubs()
		}()

		wg.Wait()
	}
}

func TestAccountDefaultPermsRaceDuringAuth(t *testing.T) {
	acc := NewAccount("foo")

	// User claims with no permissions so buildInternalNkeyUser hits the
	// acc.defaultPerms read path (p == nil).
	uc := jwt.NewUserClaims("U" + strings.Repeat("A", 51))

	var someClaims jwt.Permissions
	someClaims.Pub.Allow.Add("foo")

	var wg sync.WaitGroup
	wg.Add(2)

	// Reader: mimics authentication path.
	go func() {
		defer wg.Done()
		for range 1000 {
			_ = buildInternalNkeyUser(uc, nil, acc)
		}
	}()

	// Writer: mimics updateAccountClaimsWithRefresh refreshing defaultPerms.
	go func() {
		defer wg.Done()
		for range 1000 {
			acc.mu.Lock()
			acc.defaultPerms = buildPermissionsFromJwt(&someClaims)
			acc.mu.Unlock()
		}
	}()

	wg.Wait()
}

// Must be run with -race.
func TestAccountRemoveCbJSWriteRace(t *testing.T) {
	opts := DefaultTestOptions
	opts.Port = -1
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	s := RunServer(&opts)
	defer s.Shutdown()

	for i := range 50 {
		name := fmt.Sprintf("ACC_%d", i)
		acc, _ := s.LookupOrRegisterAccount(name)
		require_NoError(t, acc.EnableJetStream(nil, nil))
		// Confirm a.js is set, so removeCb will reach the `a.js = nil` write.
		if !acc.JetStreamEnabled() {
			t.Fatalf("expected JetStream enabled (a.js != nil) for %s", name)
		}

		var stop atomic.Bool
		done := make(chan struct{})
		// Reader: read a.js under a.mu.RLock, exactly like maxBytesLimits does.
		go func(a *Account) {
			defer close(done)
			for !stop.Load() {
				a.mu.RLock()
				_ = a.js
				a.mu.RUnlock()
			}
		}(acc)

		// Writer: removeCb sets `a.js = nil`, which must synchronize with the
		// locked read above.
		removeCb(s, name)

		stop.Store(true)
		<-done
	}
}

// Must be run with -race.
func TestAccountSendTrackingLatencyRcRace(t *testing.T) {
	a := NewAccount("A")
	rc := &client{kind: CLIENT}
	responder := &client{kind: SYSTEM}

	si := &serviceImport{
		acc:      a,
		rc:       rc,
		share:    false,
		ts:       time.Now().UnixNano(),
		tracking: true,
		latency:  &serviceLatency{subject: "latency.subj"},
	}

	const iters = 1000
	var wg sync.WaitGroup
	wg.Add(2)

	// Reader goroutine: exercises the unlocked re-read of si.rc.
	go func() {
		defer wg.Done()
		for range iters {
			a.sendTrackingLatency(si, responder)
			a.mu.Lock()
			si.m1 = nil
			a.mu.Unlock()
		}
	}()

	// Writer goroutine: mimics sendLatencyResult writing si.rc under a.mu.Lock.
	go func() {
		defer wg.Done()
		for range iters {
			a.mu.Lock()
			si.rc = rc
			a.mu.Unlock()
		}
	}()

	wg.Wait()
}

// sharedInboxRequests stands up a foo/bar service export/import pair and has
// bar send numReqs requests that all share one reply subject. The responder
// never answers, so every response is left outstanding under that single rrMap
// key. Returns both accounts and the shared reply subject.
func sharedInboxRequests(t *testing.T, numReqs int) (*Account, *Account, string) {
	t.Helper()

	s, fooAcc, barAcc := simpleAccountServer(t)
	t.Cleanup(s.Shutdown)

	if err := fooAcc.AddServiceExport("test", nil); err != nil {
		t.Fatalf("Error adding service export: %v", err)
	}
	if err := barAcc.AddServiceImport(fooAcc, "test", _EMPTY_); err != nil {
		t.Fatalf("Error adding service import: %v", err)
	}

	// Both connections are net.Pipe, so anything the server writes blocks until
	// it is read. Drain them, otherwise the write loops sit on the flush
	// deadline and shutdown takes ten seconds.
	cfoo, rfoo, _ := newClientForServer(s)
	t.Cleanup(cfoo.close)
	go io.Copy(io.Discard, rfoo)
	if err := cfoo.registerWithAccount(fooAcc); err != nil {
		t.Fatalf("Error registering client with 'foo' account: %v", err)
	}
	// Responder never answers, so the entries stay outstanding.
	cfoo.parse([]byte("SUB test 1\r\n"))

	cbar, rbar, _ := newClientForServer(s)
	t.Cleanup(cbar.close)
	go io.Copy(io.Discard, rbar)
	if err := cbar.registerWithAccount(barAcc); err != nil {
		t.Fatalf("Error registering client with 'bar' account: %v", err)
	}

	const inbox = "my.inbox"
	cbar.parse([]byte("SUB my.inbox 11\r\n"))
	for i := 0; i < numReqs; i++ {
		cbar.parse([]byte("PUB test my.inbox 4\r\nhelp\r\n"))
	}

	return fooAcc, barAcc, inbox
}

// A client is allowed to reuse a single reply subject across many concurrent
// service import requests, which piles every outstanding response entry under
// one rrMap key. Make sure those entries are tracked and removed correctly in
// both the small (unindexed) and large (indexed) cases.
func TestServiceImportReverseEntriesSharedReplySubject(t *testing.T) {
	for _, test := range []struct {
		name    string
		numReqs int
		indexed bool
	}{
		{"below index threshold", rrIndexThreshold - 1, false},
		{"above index threshold", rrIndexThreshold * 100, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fooAcc, barAcc, inbox := sharedInboxRequests(t, test.numReqs)

			barAcc.mu.RLock()
			re, ok := barAcc.imports.rrMap[inbox]
			numEntries, indexed := len(re.list), re.idx != nil
			barAcc.mu.RUnlock()

			if !ok {
				t.Fatalf("Expected a reverse entry for %q", inbox)
			}
			if numEntries != test.numReqs {
				t.Fatalf("Expected %d reverse entries, got %d", test.numReqs, numEntries)
			}
			if indexed != test.indexed {
				t.Fatalf("Expected indexed to be %v, got %v", test.indexed, indexed)
			}

			// Now expire them the way the response threshold timer does, and make
			// sure every entry is accounted for as we go.
			fooAcc.mu.RLock()
			var expired []*serviceImport
			for _, si := range fooAcc.exports.responses {
				expired = append(expired, si)
			}
			fooAcc.mu.RUnlock()

			if len(expired) != test.numReqs {
				t.Fatalf("Expected %d outstanding responses, got %d", test.numReqs, len(expired))
			}

			for i, si := range expired {
				fooAcc.removeRespServiceImport(si, rsiTimeout)
				barAcc.mu.RLock()
				re, ok := barAcc.imports.rrMap[inbox]
				remaining := len(re.list)
				idxLen := len(re.idx)
				barAcc.mu.RUnlock()

				if expect := test.numReqs - i - 1; remaining != expect {
					t.Fatalf("After %d removals expected %d entries, got %d", i+1, expect, remaining)
				} else if expect == 0 {
					if ok {
						t.Fatalf("Expected the reverse entry for %q to be removed once empty", inbox)
					}
				} else if re.idx != nil && idxLen != remaining {
					t.Fatalf("Index out of sync with list: %d vs %d", idxLen, remaining)
				}
			}

			fooAcc.mu.RLock()
			left := len(fooAcc.exports.responses)
			fooAcc.mu.RUnlock()
			if left != 0 {
				t.Fatalf("Expected no outstanding responses left, got %d", left)
			}
		})
	}
}

// The other removal path drops a whole reply subject at once instead of one
// entry at a time. That is what runs when interest in the reply subject goes
// away, so it is the path a disconnecting requestor takes.
func TestServiceImportReverseEntriesBulkRemoval(t *testing.T) {
	for _, test := range []struct {
		name    string
		numReqs int
	}{
		{"below index threshold", rrIndexThreshold - 1},
		{"above index threshold", rrIndexThreshold * 100},
	} {
		t.Run(test.name, func(t *testing.T) {
			fooAcc, barAcc, inbox := sharedInboxRequests(t, test.numReqs)

			fooAcc.mu.RLock()
			outstanding := len(fooAcc.exports.responses)
			fooAcc.mu.RUnlock()
			if outstanding != test.numReqs {
				t.Fatalf("Expected %d outstanding responses, got %d", test.numReqs, outstanding)
			}

			// A nil si means drop every entry under this reply subject and clean
			// up the responses they point at on the exporting account.
			barAcc.checkForReverseEntry(inbox, nil, false)

			barAcc.mu.RLock()
			_, ok := barAcc.imports.rrMap[inbox]
			remaining := len(barAcc.imports.rrMap)
			barAcc.mu.RUnlock()
			if ok {
				t.Fatalf("Expected the reverse entry for %q to be gone", inbox)
			}
			if remaining != 0 {
				t.Fatalf("Expected no reverse entries left, got %d", remaining)
			}

			fooAcc.mu.RLock()
			outstanding = len(fooAcc.exports.responses)
			fooAcc.mu.RUnlock()
			if outstanding != 0 {
				t.Fatalf("Expected every outstanding response to be cleaned up, got %d", outstanding)
			}
		})
	}
}

// Guards the cost of clearing outstanding responses. Each iteration clears the
// whole set, so ns/op is the cost of draining n entries, not of one removal.
// The shared case is the one that used to go quadratic; the unique case is the
// common one and should stay where it is.
func BenchmarkReverseRespMapRemoval(b *testing.B) {
	for _, bench := range []struct {
		name   string
		shared bool
	}{
		{"SharedReplySubject", true},
		{"UniqueReplySubjects", false},
	} {
		for _, n := range []int{1000, 10000, 40000} {
			b.Run(fmt.Sprintf("%s/%d", bench.name, n), func(b *testing.B) {
				replies, sis := make([]string, n), make([]*serviceImport, n)
				for i := 0; i < n; i++ {
					if bench.shared {
						replies[i] = "my.inbox"
					} else {
						replies[i] = fmt.Sprintf("my.inbox.%d", i)
					}
					sis[i] = &serviceImport{from: fmt.Sprintf("_R_.%d", i), to: replies[i]}
				}

				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					acc := NewAccount("bar")
					for j := 0; j < n; j++ {
						acc.addReverseRespMapEntry(acc, replies[j], sis[j].from)
					}
					b.StartTimer()

					for j := 0; j < n; j++ {
						acc.checkForReverseEntry(replies[j], sis[j], false)
					}

					if left := len(acc.imports.rrMap); left != 0 {
						b.Fatalf("Expected no reverse entries left, got %d", left)
					}
				}
			})
		}
	}
}
