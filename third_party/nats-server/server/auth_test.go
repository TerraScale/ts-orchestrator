// Copyright 2012-2026 The NATS Authors
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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestUserCloneNilPermissions(t *testing.T) {
	user := &User{
		Username: "foo",
		Password: "bar",
	}

	clone := user.clone()

	if !reflect.DeepEqual(user, clone) {
		t.Fatalf("Cloned Users are incorrect.\nexpected: %+v\ngot: %+v",
			user, clone)
	}

	clone.Password = "baz"
	if reflect.DeepEqual(user, clone) {
		t.Fatal("Expected Users to be different")
	}
}

func TestUserClone(t *testing.T) {
	user := &User{
		Username: "foo",
		Password: "bar",
		Permissions: &Permissions{
			Publish: &SubjectPermission{
				Allow: []string{"foo"},
			},
			Subscribe: &SubjectPermission{
				Allow: []string{"bar"},
			},
		},
	}

	clone := user.clone()

	if !reflect.DeepEqual(user, clone) {
		t.Fatalf("Cloned Users are incorrect.\nexpected: %+v\ngot: %+v",
			user, clone)
	}

	clone.Permissions.Subscribe.Allow = []string{"baz"}
	if reflect.DeepEqual(user, clone) {
		t.Fatal("Expected Users to be different")
	}
}

func TestUserClonePermissionsNoLists(t *testing.T) {
	user := &User{
		Username:    "foo",
		Password:    "bar",
		Permissions: &Permissions{},
	}

	clone := user.clone()

	if clone.Permissions.Publish != nil {
		t.Fatalf("Expected Publish to be nil, got: %v", clone.Permissions.Publish)
	}
	if clone.Permissions.Subscribe != nil {
		t.Fatalf("Expected Subscribe to be nil, got: %v", clone.Permissions.Subscribe)
	}
}

func TestUserCloneNoPermissions(t *testing.T) {
	user := &User{
		Username: "foo",
		Password: "bar",
	}

	clone := user.clone()

	if clone.Permissions != nil {
		t.Fatalf("Expected Permissions to be nil, got: %v", clone.Permissions)
	}
}

func TestUserCloneNil(t *testing.T) {
	user := (*User)(nil)
	clone := user.clone()
	if clone != nil {
		t.Fatalf("Expected nil, got: %+v", clone)
	}
}

func TestAuthDNSAltNamesTLSRoutes(t *testing.T) {
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	require_NoError(t, err)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	require_NoError(t, err)
	ca, err = x509.ParseCertificate(caDER)
	require_NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	serial := int64(1)
	certificate := func(t *testing.T, names []string, usage x509.ExtKeyUsage) tls.Certificate {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		require_NoError(t, err)
		serial++
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
			DNSNames: names, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
		require_NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	serverCert := certificate(t, []string{"localhost"}, x509.ExtKeyUsageServerAuth)
	for idx, tc := range []struct {
		altName string
		urls    []string
		match   bool
	}{
		{"foo", []string{"FOO"}, true},
		{"foo", []string{".."}, false},
		{"foo", []string{"."}, false},
		{"Foo", []string{"foO"}, true},
		{"FOO", []string{"foo"}, true},
		{"foo1", []string{"bar"}, false},
		{"multi", []string{"m", "mu", "mul", "multi"}, true},
		{"multi", []string{"multi", "m", "mu", "mul"}, true},
		{"foo.bar", []string{"foo", "foo.bar.bar", "foo.baz"}, false},
		{"foo.Bar", []string{"foo", "bar.foo", "Foo.Bar"}, true},
		{"foo.*", []string{"foo", "bar.foo", "Foo.Bar"}, false}, // only match left most
		{"f*.bar", []string{"foo", "bar.foo", "Foo.Bar"}, false},
		{"*.bar", []string{"foo.bar"}, true},
		{"*", []string{"baz.bar", "bar", "z.y"}, true},
		{"*", []string{"bar"}, true},
		{"*", []string{"."}, false},
		{"*", []string{""}, true},
		{"*", []string{"*"}, true},
		{"bar.*", []string{"bar.*"}, true},
		{"*.Y-X-red-mgmt.default.svc", []string{"A.Y-X-red-mgmt.default.svc"}, true},
		{"*.Y-X-green-mgmt.default.svc", []string{"A.Y-X-green-mgmt.default.svc"}, true},
		{"*.Y-X-blue-mgmt.default.svc", []string{"A.Y-X-blue-mgmt.default.svc"}, true},
		{"Y-X-red-mgmt", []string{"Y-X-red-mgmt"}, true},
		{"Y-X-red-mgmt", []string{"X-X-red-mgmt"}, false},
		{"Y-X-red-mgmt", []string{"Y-X-green-mgmt"}, false},
		{"Y-X-red-mgmt", []string{"Y"}, false},
		{"Y-X-red-mgmt", []string{"Y-X"}, false},
		{"Y-X-red-mgmt", []string{"Y-X-red"}, false},
		{"Y-X-red-mgmt", []string{"X-red-mgmt"}, false},
		{"Y-X-green-mgmt", []string{"Y-X-green-mgmt"}, true},
		{"Y-X-blue-mgmt", []string{"Y-X-blue-mgmt"}, true},
		{"connect.Y.local", []string{"connect.Y.local"}, true},
		{"connect.Y.local", []string{".Y.local"}, false},
		{"connect.Y.local", []string{"..local"}, false},
		{"gcp.Y.local", []string{"gcp.Y.local"}, true},
		{"uswest1.gcp.Y.local", []string{"uswest1.gcp.Y.local"}, true},
	} {
		t.Run(fmt.Sprintf("%02d_%s", idx, tc.altName), func(t *testing.T) {
			peerCert := certificate(t, []string{tc.altName}, x509.ExtKeyUsageClientAuth)
			o := defaultServerOptions
			o.NoSystemAccount = true
			o.Cluster = ClusterOpts{
				Name: "auth-dns", Host: "127.0.0.1", Port: -1, PoolSize: -1,
				TLSCheckKnownURLs: true, resolver: &localhostResolver{},
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert},
					ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, RootCAs: roots,
				},
			}
			for _, host := range tc.urls {
				// Port zero keeps configured trust names from reaching another listener.
				u, err := url.Parse("nats://" + net.JoinHostPort(host, "0"))
				require_NoError(t, err)
				o.Routes = append(o.Routes, u)
			}
			s := RunServer(&o)
			t.Cleanup(s.Shutdown)
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(o.Cluster.Host, fmt.Sprint(o.Cluster.Port)), 2*time.Second)
			require_NoError(t, err)
			t.Cleanup(func() { conn.Close() })
			require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			peer := tls.Client(conn, &tls.Config{
				MinVersion: tls.VersionTLS12, ServerName: "localhost", RootCAs: roots,
				Certificates: []tls.Certificate{peerCert},
			})
			require_NoError(t, peer.Handshake())
			_, err = io.WriteString(peer, "CONNECT {\"name\":\"dns-peer\",\"cluster\":\"auth-dns\",\"tls_required\":true}\r\nINFO {\"server_id\":\"dns-peer\",\"cluster\":\"auth-dns\"}\r\nPING\r\n")
			require_NoError(t, err)
			br := bufio.NewReader(peer)
			for {
				line, err := br.ReadString('\n')
				require_NoError(t, err)
				switch {
				case strings.HasPrefix(line, "INFO "), line == "+OK\r\n":
					continue
				case line == "PING\r\n":
					_, err := io.WriteString(peer, "PONG\r\n")
					require_NoError(t, err)
					continue
				case tc.match:
					require_Equal(t, line, "PONG\r\n")
					checkNumRoutes(t, s, 1)
				default:
					require_Equal(t, strings.TrimSpace(line), authViolation)
					_, err := br.ReadByte()
					require_True(t, errors.Is(err, io.EOF))
					require_Equal(t, s.NumRoutes(), 0)
				}
				break
			}
		})
	}
}

func TestAuthPermissionTemplatesTCP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*jwt.UserScope, *jwt.UserClaims)
	}{
		{"malformed deny operation", func(scope *jwt.UserScope, _ *jwt.UserClaims) {
			scope.Template.Sub.Deny.Add("foo.{{x}}")
		}},
		{"unknown allow operation", func(scope *jwt.UserScope, _ *jwt.UserClaims) {
			scope.Template.Pub.Allow.Add("foo.{{unknown()}}")
		}},
		{"excessive tag expansion", func(scope *jwt.UserScope, user *jwt.UserClaims) {
			scope.Template.Pub.Allow.Add("foo.{{tag(a)}}.{{tag(b)}}")
			for i := range 128 {
				user.Tags.Add(fmt.Sprintf("a:v%d", i), fmt.Sprintf("b:v%d", i))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, accountPub := createKey(t)
			badKey, badPub := createKey(t)
			goodKey, goodPub := createKey(t)
			badScope, goodScope := jwt.NewUserScope(), jwt.NewUserScope()
			badScope.Key, goodScope.Key = badPub, goodPub
			goodScope.Template.Pub.Allow.Add("control.{{name()}}")
			goodScope.Template.Sub.Allow.Add("control.{{name()}}")

			badUser := newJWTTestUserClaims()
			badUser.SetScoped(true)
			badUser.IssuerAccount = accountPub
			tc.configure(badScope, badUser)
			goodUser := newJWTTestUserClaims()
			goodUser.SetScoped(true)
			goodUser.IssuerAccount = accountPub
			goodUser.Name = "valid"

			account := jwt.NewAccountClaims(accountPub)
			account.SigningKeys.AddScopedSigner(badScope)
			account.SigningKeys.AddScopedSigner(goodScope)
			accountJWT, err := account.Encode(oKp)
			require_NoError(t, err)
			conf := createConfFile(t, fmt.Appendf(nil, `
				listen: "127.0.0.1:-1"
				operator: %s
				resolver: MEM
				resolver_preload: { %s: %s }
			`, ojwt, accountPub, accountJWT))
			s, _ := RunServerWithConfig(conf)
			t.Cleanup(s.Shutdown)

			goodCreds := createUserCredsEx(t, goodUser, goodKey)
			checkDelivery := func() {
				t.Helper()
				nc := natsConnect(t, s.ClientURL(), goodCreds, nats.Timeout(2*time.Second), nats.NoReconnect())
				defer nc.Close()
				sub := natsSubSync(t, nc, "control.valid")
				require_NoError(t, nc.Publish("control.valid", []byte("authorized")))
				require_NoError(t, nc.FlushTimeout(2*time.Second))
				msg := natsNexMsg(t, sub, 2*time.Second)
				require_Equal(t, string(msg.Data), "authorized")
			}
			checkDelivery()
			nc, err := nats.Connect(s.ClientURL(), createUserCredsEx(t, badUser, badKey), nats.Timeout(2*time.Second), nats.NoReconnect())
			if nc != nil {
				nc.Close()
			}
			require_True(t, errors.Is(err, nats.ErrAuthorization))
			checkDelivery()
		})
	}
}

func authSubjectDelivery(t *testing.T, nc *nats.Conn, subject string) {
	t.Helper()
	sub := natsSubSync(t, nc, subject)
	defer sub.Unsubscribe()
	require_NoError(t, nc.Publish(subject, []byte("authorized")))
	require_NoError(t, nc.FlushTimeout(2*time.Second))
	msg := natsNexMsg(t, sub, 2*time.Second)
	require_Equal(t, string(msg.Data), "authorized")
}

func TestAuthAllowedConnectionTypesListeners(t *testing.T) {
	kp, err := nkeys.CreateUser()
	require_NoError(t, err)
	pub, err := kp.PublicKey()
	require_NoError(t, err)
	o := defaultServerOptions
	o.Users = []*User{{Username: "user", Password: "pwd"}}
	o.Nkeys = []*NkeyUser{{Nkey: pub}}
	o.Websocket = WebsocketOpts{Host: "127.0.0.1", Port: -1, NoTLS: true}
	s := RunServer(&o)
	t.Cleanup(s.Shutdown)
	credentials := []struct {
		name string
		opt  nats.Option
	}{
		{"password", nats.UserInfo("user", "pwd")},
		{"nkey", nats.Nkey(pub, kp.Sign)},
	}
	checkTCP := func(t *testing.T) {
		t.Helper()
		for _, cred := range credentials {
			nc := natsConnect(t, s.ClientURL(), cred.opt, nats.Timeout(2*time.Second), nats.NoReconnect())
			authSubjectDelivery(t, nc, "types.control")
			nc.Close()
		}
	}
	checkTCP(t)
	for _, cred := range credentials {
		t.Run("reject unknown "+cred.name, func(t *testing.T) {
			next := s.getOpts().Clone()
			unknown := testCreateAllowedConnectionTypes([]string{jwt.ConnectionTypeStandard, "someNewType"})
			if cred.name == "password" {
				next.Users[0].AllowedConnectionTypes = unknown
			} else {
				next.Nkeys[0].AllowedConnectionTypes = unknown
			}
			err := s.ReloadOptions(next)
			require_Error(t, err)
			require_Contains(t, err.Error(), "connection type")
			checkTCP(t)
		})
	}
	next := s.getOpts().Clone()
	next.Users[0].AllowedConnectionTypes = testCreateAllowedConnectionTypes([]string{"websocket"})
	next.Nkeys[0].AllowedConnectionTypes = testCreateAllowedConnectionTypes([]string{"websocket"})
	require_NoError(t, s.ReloadOptions(next))
	wsURL := fmt.Sprintf("ws://%s:%d", o.Websocket.Host, o.Websocket.Port)
	for _, cred := range credentials {
		t.Run("normalized websocket "+cred.name, func(t *testing.T) {
			nc, err := nats.Connect(s.ClientURL(), cred.opt, nats.Timeout(2*time.Second), nats.NoReconnect())
			if nc != nil {
				nc.Close()
			}
			require_True(t, errors.Is(err, nats.ErrAuthorization))
			nc = natsConnect(t, wsURL, cred.opt, nats.Timeout(2*time.Second), nats.NoReconnect())
			defer nc.Close()
			authSubjectDelivery(t, nc, "types.control")
		})
	}
}

func TestAuthUserOptionsIsolationTCP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		permissions *Permissions
	}{
		{"nil permissions", nil},
		{"empty permissions", &Permissions{}},
		{"restricted permissions", &Permissions{
			Publish:   &SubjectPermission{Allow: []string{"foo"}},
			Subscribe: &SubjectPermission{Allow: []string{"bar"}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := &User{Username: "user", Password: "original", Permissions: tc.permissions}
			o := defaultServerOptions
			o.Users = []*User{user, {Username: "control", Password: "control"}}
			s := RunServer(&o)
			t.Cleanup(s.Shutdown)
			control := natsConnect(t, s.ClientURL(), nats.UserInfo("control", "control"), nats.Timeout(2*time.Second), nats.NoReconnect())
			defer control.Close()
			checkDelivery := func(nc *nats.Conn) {
				t.Helper()
				incoming := natsSubSync(t, nc, "bar")
				defer incoming.Unsubscribe()
				outgoing := natsSubSync(t, control, "foo")
				defer outgoing.Unsubscribe()
				require_NoError(t, nc.FlushTimeout(2*time.Second))
				require_NoError(t, control.FlushTimeout(2*time.Second))
				require_NoError(t, control.Publish("bar", []byte("to-user")))
				require_NoError(t, nc.Publish("foo", []byte("from-user")))
				require_NoError(t, control.FlushTimeout(2*time.Second))
				require_NoError(t, nc.FlushTimeout(2*time.Second))
				require_Equal(t, string(natsNexMsg(t, incoming, 2*time.Second).Data), "to-user")
				require_Equal(t, string(natsNexMsg(t, outgoing, 2*time.Second).Data), "from-user")
			}
			baseline := natsConnect(t, s.ClientURL(), nats.UserInfo("user", "original"), nats.Timeout(2*time.Second), nats.NoReconnect())
			checkDelivery(baseline)
			baseline.Close()

			// Caller-owned options must not mutate the installed authentication snapshot.
			user.Password = "changed"
			if tc.name == "restricted permissions" {
				user.Permissions.Publish.Allow[0] = "changed"
				user.Permissions.Subscribe.Allow[0] = "changed"
			} else {
				if user.Permissions == nil {
					user.Permissions = &Permissions{}
				}
				user.Permissions.Publish = &SubjectPermission{Allow: []string{"changed"}}
				user.Permissions.Subscribe = &SubjectPermission{Allow: []string{"changed"}}
			}
			nc, err := nats.Connect(s.ClientURL(), nats.UserInfo("user", "changed"), nats.Timeout(2*time.Second), nats.NoReconnect())
			if nc != nil {
				nc.Close()
			}
			require_True(t, errors.Is(err, nats.ErrAuthorization))
			errorsCh := make(chan error, 2)
			nc = natsConnect(t, s.ClientURL(), nats.UserInfo("user", "original"), nats.Timeout(2*time.Second), nats.NoReconnect(),
				nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
					errorsCh <- err
				}))
			defer nc.Close()
			checkDelivery(nc)
			if tc.name == "restricted permissions" {
				_, err := nc.SubscribeSync("changed")
				require_NoError(t, err)
				require_NoError(t, nc.Publish("changed", nil))
				require_NoError(t, nc.FlushTimeout(2*time.Second))
				seen := make(map[string]bool)
				for range 2 {
					select {
					case err := <-errorsCh:
						switch {
						case strings.Contains(err.Error(), `Permissions Violation for Subscription to "changed"`):
							seen["subscribe"] = true
						case strings.Contains(err.Error(), `Permissions Violation for Publish to "changed"`):
							seen["publish"] = true
						default:
							t.Fatalf("Unexpected authentication snapshot error: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("Expected installed publish and subscribe permissions to remain enforced")
					}
				}
				require_True(t, seen["subscribe"])
				require_True(t, seen["publish"])
			} else {
				// Nil/empty permissions remain unrestricted despite the caller's new allow lists.
				authSubjectDelivery(t, nc, "unrestricted")
			}
		})
	}
}

func TestNoAuthUser(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: "127.0.0.1:-1"
		accounts {
			FOO { users [{user: "foo", password: "pwd1"}] }
			BAR { users [{user: "bar", password: "pwd2"}] }
		}
		no_auth_user: "foo"
	`))
	defer os.Remove(conf)
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()

	for _, test := range []struct {
		name    string
		usrInfo string
		ok      bool
		account string
	}{
		{"valid user/pwd", "bar:pwd2@", true, "BAR"},
		{"invalid pwd", "bar:wrong@", false, _EMPTY_},
		{"some token", "sometoken@", false, _EMPTY_},
		{"user used without pwd", "bar@", false, _EMPTY_}, // will be treated as a token
		{"user with empty password", "bar:@", false, _EMPTY_},
		{"no user", _EMPTY_, true, "FOO"},
	} {
		t.Run(test.name, func(t *testing.T) {
			url := fmt.Sprintf("nats://%s127.0.0.1:%d", test.usrInfo, o.Port)
			nc, err := nats.Connect(url)
			if err != nil {
				if test.ok {
					t.Fatalf("Unexpected error: %v", err)
				}
				return
			} else if !test.ok {
				nc.Close()
				t.Fatalf("Should have failed, did not")
			}
			var accName string
			s.mu.Lock()
			for _, c := range s.clients {
				c.mu.Lock()
				if c.acc != nil {
					accName = c.acc.Name
				}
				c.mu.Unlock()
				break
			}
			s.mu.Unlock()
			nc.Close()
			checkClientsCount(t, s, 0)
			if accName != test.account {
				t.Fatalf("The account should have been %q, got %q", test.account, accName)
			}
		})
	}
}

func TestNoAuthUserNkey(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: "127.0.0.1:-1"
		accounts {
			FOO { users [{user: "foo", password: "pwd1"}] }
			BAR { users [{nkey: "UBO2MQV67TQTVIRV3XFTEZOACM4WLOCMCDMAWN5QVN5PI2N6JHTVDRON"}] }
		}
		no_auth_user: "UBO2MQV67TQTVIRV3XFTEZOACM4WLOCMCDMAWN5QVN5PI2N6JHTVDRON"
	`))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	// Make sure we connect ok and to the correct account.
	nc := natsConnect(t, s.ClientURL())
	defer nc.Close()
	resp, err := nc.Request(userDirectInfoSubj, nil, time.Second)
	require_NoError(t, err)
	response := ServerAPIResponse{Data: &UserInfo{}}
	err = json.Unmarshal(resp.Data, &response)
	require_NoError(t, err)
	userInfo := response.Data.(*UserInfo)
	require_Equal(t, userInfo.UserID, "UBO2MQV67TQTVIRV3XFTEZOACM4WLOCMCDMAWN5QVN5PI2N6JHTVDRON")
	require_Equal(t, userInfo.Account, "BAR")
}

func TestUserConnectionDeadline(t *testing.T) {
	clientAuth := &DummyAuth{
		t:        t,
		register: true,
		deadline: time.Now().Add(50 * time.Millisecond),
	}

	opts := DefaultOptions()
	opts.CustomClientAuthentication = clientAuth

	s := RunServer(opts)
	defer s.Shutdown()

	var dcerr error

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)

	nc, err := nats.Connect(
		s.ClientURL(),
		nats.UserInfo("valid", _EMPTY_),
		nats.NoReconnect(),
		nats.ErrorHandler(func(nc *nats.Conn, _ *nats.Subscription, err error) {
			dcerr = err
			cancel()
		}))
	if err != nil {
		t.Fatalf("Expected client to connect, got: %s", err)
	}

	<-ctx.Done()

	checkFor(t, 2*time.Second, 100*time.Millisecond, func() error {
		if nc.IsConnected() {
			return fmt.Errorf("Expected to be disconnected")
		}
		return nil
	})

	if dcerr == nil || dcerr.Error() != "nats: authentication expired" {
		t.Fatalf("Expected a auth expired error: got: %v", dcerr)
	}
}

func TestNoAuthUserNoConnectProto(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: "127.0.0.1:-1"
		accounts {
			A { users [{user: "foo", password: "pwd"}] }
		}
		authorization { timeout: 1 }
		no_auth_user: "foo"
	`))
	defer os.Remove(conf)
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()

	checkClients := func(n int) {
		t.Helper()
		time.Sleep(100 * time.Millisecond)
		if nc := s.NumClients(); nc != n {
			t.Fatalf("Expected %d clients, got %d", n, nc)
		}
	}

	conn, err := net.Dial("tcp", net.JoinHostPort(o.Host, fmt.Sprintf("%d", o.Port)))
	require_NoError(t, err)
	defer conn.Close()
	checkClientsCount(t, s, 1)

	// With no auth user we should not require a CONNECT.
	// Make sure we are good on not sending CONN first.
	_, err = conn.Write([]byte("PUB foo 2\r\nok\r\n"))
	require_NoError(t, err)
	checkClients(1)
	conn.Close()

	// Now make sure we still do get timed out though.
	conn, err = net.Dial("tcp", net.JoinHostPort(o.Host, fmt.Sprintf("%d", o.Port)))
	require_NoError(t, err)
	defer conn.Close()
	checkClientsCount(t, s, 1)

	time.Sleep(1200 * time.Millisecond)
	checkClientsCount(t, s, 0)
}

type captureProxyRequiredLogger struct {
	DummyLogger
	ch chan string
}

func (l *captureProxyRequiredLogger) Debugf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if strings.Contains(msg, ErrAuthProxyRequired.Error()) {
		select {
		case l.ch <- msg:
		default:
		}
	}
}

func TestAuthProxyRequired(t *testing.T) {
	conf := createConfFile(t, []byte(`
		port: -1
		authorization {
			user: user
			password: pwd
			proxy_required: true
		}
	`))
	s, _ := RunServerWithConfig(conf)
	defer s.Shutdown()

	l := &captureProxyRequiredLogger{ch: make(chan string, 1)}
	s.SetLogger(l, true, false)

	_, err := nats.Connect(s.ClientURL(), nats.UserInfo("user", "pwd"))
	require_True(t, errors.Is(err, nats.ErrAuthorization))

	checkLog := func() {
		t.Helper()
		select {
		case <-l.ch:
			return
		case <-time.After(time.Second):
			t.Fatal("Did not get log statement")
		}
	}
	checkLog()

	drainLog := func() {
		for {
			select {
			case <-l.ch:
			default:
				return
			}
		}
	}
	s.Shutdown()
	drainLog()

	nkUsr1, err := nkeys.CreateUser()
	require_NoError(t, err)
	nkPub1, err := nkUsr1.PublicKey()
	require_NoError(t, err)

	nkUsr2, err := nkeys.CreateUser()
	require_NoError(t, err)
	nkPub2, err := nkUsr2.PublicKey()
	require_NoError(t, err)

	conf = createConfFile(t, fmt.Appendf(nil, `
		port: -1
		authorization {
			users: [
				{user: user1, password: pwd1}
				{user: user2, password: pwd2, proxy_required: true}
				{user: user3, password: pwd3, proxy_required: false}
				{nkey: "%s", proxy_required: true}
				{nkey: "%s", proxy_required: false}
			]
		}
	`, nkPub1, nkPub2))
	s, _ = RunServerWithConfig(conf)
	defer s.Shutdown()

	s.SetLogger(l, true, false)

	checkClients := func() {
		t.Helper()
		// Should connect ok.
		nc := natsConnect(t, s.ClientURL(), nats.UserInfo("user1", "pwd1"))
		nc.Close()

		// Should not, since it requires going through proxy.
		_, err = nats.Connect(s.ClientURL(), nats.UserInfo("user2", "pwd2"))
		require_True(t, errors.Is(err, nats.ErrAuthorization))
		checkLog()

		// Should connect ok.
		nc = natsConnect(t, s.ClientURL(), nats.UserInfo("user3", "pwd3"))
		nc.Close()

		// Should not, since it requires going through proxy.
		_, err = nats.Connect(s.ClientURL(), nats.Nkey(nkPub1, func(nonce []byte) ([]byte, error) {
			return nkUsr1.Sign(nonce)
		}))
		require_True(t, errors.Is(err, nats.ErrAuthorization))
		checkLog()

		// Should connect ok.
		nc = natsConnect(t, s.ClientURL(), nats.Nkey(nkPub2, func(nonce []byte) ([]byte, error) {
			return nkUsr2.Sign(nonce)
		}))
		nc.Close()
	}
	checkClients()
	s.Shutdown()
	drainLog()

	conf = createConfFile(t, fmt.Appendf(nil, `
		port: -1
		accounts {
			A {
				users: [
					{user: user1, password: pwd1}
					{user: user2, password: pwd2, proxy_required: true}
					{user: user3, password: pwd3, proxy_required: false}
					{nkey: "%s", proxy_required: true}
					{nkey: "%s", proxy_required: false}
				]
			}
			SYS { users: [ {user:sys, password: pwd} ] }
		}
		system_account: SYS
	`, nkPub1, nkPub2))
	s, _ = RunServerWithConfig(conf)
	defer s.Shutdown()

	s.SetLogger(l, true, false)

	snc := natsConnect(t, s.ClientURL(), nats.UserInfo("sys", "pwd"))
	defer snc.Close()
	sub := natsSubSync(t, snc, "$SYS.SERVER.*.CLIENT.AUTH.ERR")
	sub2 := natsSubSync(t, snc, "$SYS.ACCOUNT.A.DISCONNECT")
	natsFlush(t, snc)

	checkClients()

	// We should get 2 authentication error messages, saying that
	// the reason is "ProxyRequired".
	for range 2 {
		var de DisconnectEventMsg
		msg := natsNexMsg(t, sub, time.Second)
		err = json.Unmarshal(msg.Data, &de)
		require_NoError(t, err)
		require_Equal(t, de.Reason, ProxyRequired.String())
	}

	// We should get 3 disconnect events since only 3 have connected
	// ok and then just closed.
	for range 3 {
		var de DisconnectEventMsg
		msg := natsNexMsg(t, sub2, time.Second)
		err = json.Unmarshal(msg.Data, &de)
		require_NoError(t, err)
		require_Equal(t, de.Reason, ClientClosed.String())
	}
	// Make sure there is no more.
	if msg, err := sub2.NextMsg(100 * time.Millisecond); err != nats.ErrTimeout {
		t.Fatalf("Should have received only 3 disconnect messages, got another: %s", msg.Data)
	}

	s.Shutdown()
	drainLog()

	conf = createConfFile(t, []byte(`
		port: -1
		leafnodes: {
			port: -1
			authorization {
				user: user
				password: pwd
				proxy_required: true
			}
		}
	`))
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()

	s.SetLogger(l, true, false)

	lconf := createConfFile(t, fmt.Appendf(nil, `
		port: -1
		leafnodes {
			reconnect_interval: "50ms"
			remotes [ {url: "nats://user:pwd@127.0.0.1:%d"} ]
		}
	`, o.LeafNode.Port))
	leaf, _ := RunServerWithConfig(lconf)
	defer leaf.Shutdown()

	time.Sleep(125 * time.Millisecond)
	checkLeafNodeConnectedCount(t, leaf, 0)
	checkLog()
	leaf.Shutdown()
	s.Shutdown()
	drainLog()

	conf = createConfFile(t, []byte(`
		port: -1
		leafnodes: {
			port: -1
			reconnect_interval: "50ms"
			authorization {
				users: [
					{user: user1, password: pwd1}
					{user: user2, password: pwd2, proxy_required: true}
					{user: user3, password: pwd3, proxy_required: false}
				]
			}
		}
	`))
	s, o = RunServerWithConfig(conf)
	defer s.Shutdown()

	s.SetLogger(l, true, false)

	lconf = createConfFile(t, fmt.Appendf(nil, `
		port: -1
		leafnodes {
			reconnect_interval: "50ms"
			remotes [ {url: "nats://user2:pwd@127.0.0.1:%d"} ]
		}
	`, o.LeafNode.Port))
	leaf, _ = RunServerWithConfig(lconf)
	defer leaf.Shutdown()

	time.Sleep(125 * time.Millisecond)
	checkLeafNodeConnectedCount(t, leaf, 0)
	checkLog()
	leaf.Shutdown()
	s.Shutdown()
	drainLog()

	conf = createConfFile(t, fmt.Appendf(nil, `
		port: -1
		leafnodes: {
			port: -1
			authorization {
				nkey: %s
				proxy_required: true
			}
		}
	`, nkPub1))
	s, o = RunServerWithConfig(conf)
	defer s.Shutdown()

	s.SetLogger(l, true, false)

	nkSeed1, err := nkUsr1.Seed()
	require_NoError(t, err)

	lconf = createConfFile(t, fmt.Appendf(nil, `
		port: -1
		leafnodes {
			reconnect_interval: "50ms"
			remotes [
				{
					url: "nats://127.0.0.1:%d"
					nkey: "%s"
				}
			]
		}
	`, o.LeafNode.Port, nkSeed1))
	leaf, _ = RunServerWithConfig(lconf)
	defer leaf.Shutdown()

	time.Sleep(125 * time.Millisecond)
	checkLeafNodeConnectedCount(t, leaf, 0)
	checkLog()
	leaf.Shutdown()
	s.Shutdown()
	drainLog()

	// Check with operator mode.
	conf = createConfFile(t, []byte(`
		port: -1
		server_name: OP
		operator = "../test/configs/nkeys/op.jwt"
		resolver = MEMORY
		listen: "127.0.0.1:-1"
		leafnodes {
			listen: "127.0.0.1:-1"
		}
	`))
	s, o = RunServerWithConfig(conf)
	defer s.Shutdown()

	s.SetLogger(l, true, false)

	_, akp := createAccount(s)
	kp, err := nkeys.CreateUser()
	require_NoError(t, err)
	pub, err := kp.PublicKey()
	require_NoError(t, err)
	nuc := jwt.NewUserClaims(pub)
	nuc.ProxyRequired = true
	ujwt, err := nuc.Encode(akp)
	require_NoError(t, err)

	dto := DefaultTestOptions
	lopts := &dto
	u, err := url.Parse(fmt.Sprintf("nats://%s:%d", o.LeafNode.Host, o.LeafNode.Port))
	require_NoError(t, err)
	remote := &RemoteLeafOpts{URLs: []*url.URL{u}}
	remote.SignatureCB = func(nonce []byte) (string, []byte, error) {
		sig, err := kp.Sign(nonce)
		return ujwt, sig, err
	}
	lopts.LeafNode.Remotes = []*RemoteLeafOpts{remote}
	lopts.LeafNode.ReconnectInterval = 100 * time.Millisecond
	leaf = RunServer(lopts)
	defer leaf.Shutdown()

	time.Sleep(125 * time.Millisecond)
	checkLeafNodeConnectedCount(t, leaf, 0)
	checkLog()
	leaf.Shutdown()

	// Try with an user.
	drainLog()

	_, err = nats.Connect(s.ClientURL(), createUserCredsEx(t, nuc, akp))
	require_True(t, errors.Is(err, nats.ErrAuthorization))
	checkLog()

	drainLog()

	// Try with creds file.
	kp, err = nkeys.CreateUser()
	require_NoError(t, err)
	useed, err := kp.Seed()
	require_NoError(t, err)
	pub, err = kp.PublicKey()
	require_NoError(t, err)
	nuc = jwt.NewUserClaims(pub)
	nuc.ProxyRequired = true
	ujwt, err = nuc.Encode(akp)
	require_NoError(t, err)
	credsFile := genCredsFile(t, ujwt, useed)

	lconf = createConfFile(t, fmt.Appendf(nil, `
		port: -1
		leafnodes {
			reconnect_interval: "50ms"
			remotes [
				{
					url: "nats://127.0.0.1:%d"
					credentials: '%s'
				}
			]
		}
	`, o.LeafNode.Port, credsFile))
	leaf, _ = RunServerWithConfig(lconf)
	defer leaf.Shutdown()

	time.Sleep(125 * time.Millisecond)
	checkLeafNodeConnectedCount(t, leaf, 0)
	checkLog()
	leaf.Shutdown()

	s.Shutdown()
	drainLog()
}

func TestAuthProxyCheckConnClosedDuringAuth(t *testing.T) {
	pkp, err := nkeys.CreateUser()
	require_NoError(t, err)
	pub, err := pkp.PublicKey()
	require_NoError(t, err)

	o := DefaultOptions()
	o.Proxies = &ProxiesConfig{Trusted: []*ProxyConfig{{Key: pub}}}
	s := RunServer(o)
	defer s.Shutdown()

	c, _, _ := newClientForServer(s)
	defer c.close()

	// Sign the connection's nonce as the trusted proxy would and store
	// the signature in the connect options.
	c.mu.Lock()
	sig, err := pkp.Sign(c.nonce)
	if err == nil {
		c.opts.ProxySig = base64.RawURLEncoding.EncodeToString(sig)
	}
	c.mu.Unlock()
	require_NoError(t, err)

	// Simulate the connection being closed concurrently (write error,
	// shutdown, kick, etc..) while the readLoop is still authenticating:
	// closeConnection invokes removeClient, which tries to remove the
	// connection from s.proxiedConns before proxyCheck registered it.
	c.client.closeConnection(ClientClosed)

	// Now run proxyCheck as checkAuthentication would on the readLoop.
	proxied, ok := s.proxyCheck(c.client, s.getOpts())
	require_True(t, proxied)
	require_True(t, ok)

	// Since the connection is already closed and removeClient already ran,
	// the client must not have been registered in s.proxiedConns, since
	// nothing would ever remove it.
	s.mu.RLock()
	conns := s.proxiedConns[pub]
	s.mu.RUnlock()
	require_Len(t, len(conns), 0)
}

// authVerifyGate preserves real signature verification while controlling its completion.
type authVerifyGate struct {
	nkeys.KeyPair
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (g *authVerifyGate) Verify(data, sig []byte) error {
	if err := g.KeyPair.Verify(data, sig); err != nil {
		return err
	}
	close(g.entered)
	defer close(g.finished)
	select {
	case <-g.release:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("proxy verification gate timed out")
	}
}

func TestAuthProxyShutdownDuringTCPAuthentication(t *testing.T) {
	kp, err := nkeys.CreateUser()
	require_NoError(t, err)
	pub, err := kp.PublicKey()
	require_NoError(t, err)
	o := defaultServerOptions
	o.Proxies = &ProxiesConfig{Trusted: []*ProxyConfig{{Key: pub}}}
	s := RunServer(&o)
	t.Cleanup(s.Shutdown)
	connect := func() (net.Conn, *bufio.Reader) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(o.Host, fmt.Sprint(o.Port)), 2*time.Second)
		require_NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
		br := bufio.NewReader(conn)
		line, err := br.ReadString('\n')
		require_NoError(t, err)
		require_True(t, strings.HasPrefix(line, "INFO "))
		var info Info
		require_NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "INFO ")), &info))
		require_NotEqual(t, info.Nonce, "")
		sig, err := kp.Sign([]byte(info.Nonce))
		require_NoError(t, err)
		_, err = fmt.Fprintf(conn, "CONNECT {\"verbose\":false,\"proxy_sig\":%q}\r\nPING\r\n", base64.RawURLEncoding.EncodeToString(sig))
		require_NoError(t, err)
		return conn, br
	}
	control, br := connect()
	line, err := br.ReadString('\n')
	require_NoError(t, err)
	require_Equal(t, line, "PONG\r\n")
	s.mu.RLock()
	registered := len(s.proxiedConns[pub])
	s.mu.RUnlock()
	require_Equal(t, registered, 1)
	require_NoError(t, control.Close())
	checkFor(t, 2*time.Second, 10*time.Millisecond, func() error {
		if s.NumClients() != 0 {
			return errors.New("control proxy connection has not closed")
		}
		return nil
	})

	gate := &authVerifyGate{KeyPair: kp, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
	release := func() {
		select {
		case <-gate.release:
		default:
			close(gate.release)
		}
	}
	t.Cleanup(release)
	s.mu.Lock()
	s.proxiesKeyPairs = []nkeys.KeyPair{gate}
	s.mu.Unlock()
	_, br = connect()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP authentication did not reach real proxy signature verification")
	}
	shutdownDone := make(chan struct{})
	go func() {
		s.Shutdown()
		close(shutdownDone)
	}()
	t.Cleanup(func() {
		release()
		select {
		case <-shutdownDone:
		case <-time.After(5 * time.Second):
			t.Error("server shutdown did not finish during cleanup")
		}
	})
	// Shutdown must close the actual socket before verification can register it.
	_, err = io.ReadAll(br)
	require_NoError(t, err)
	select {
	case <-gate.finished:
		t.Fatal("proxy verification finished before shutdown closed the TCP connection")
	default:
	}
	require_Equal(t, s.NumClients(), 0)
	release()
	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		t.Fatal("server shutdown did not finish after proxy authentication resumed")
	}
	s.mu.RLock()
	registered = len(s.proxiedConns[pub])
	s.mu.RUnlock()
	require_Equal(t, registered, 0)
}

const (
	authViolation = "-ERR 'Authorization Violation'"
	authAccepted  = "PONG\r\n"
)

// testAuthWSConnect sends a websocket CONNECT with the given user and password
// followed by a PING, and checks that the first protocol frame the server sends
// back starts with expect. Going through the raw protocol rather than a
// nats.Conn keeps the failure deterministic: the server closes right after
// writing the error, so a client would race it and may surface the closed
// connection instead.
func testAuthWSConnect(t *testing.T, o *Options, user, pass, expect string) {
	t.Helper()
	wsc, br, _ := testNewWSClient(t, testWSClientOptions{
		host:  o.Websocket.Host,
		port:  o.Websocket.Port,
		noTLS: true,
	})
	defer wsc.Close()

	proto := fmt.Sprintf("CONNECT {\"verbose\":false,\"protocol\":1,\"user\":%q,\"pass\":%q}\r\nPING\r\n", user, pass)
	if _, err := wsc.Write(testWSCreateClientMsg(wsBinaryMessage, 1, true, false, []byte(proto))); err != nil {
		t.Fatalf("Error sending message: %v", err)
	}
	if msg := string(testWSReadFrame(t, br)); !strings.HasPrefix(msg, expect) {
		t.Fatalf("Expected %q, got %q", expect, msg)
	}
}

func TestAuthCertMappedUserNotPasswordAuthenticatable(t *testing.T) {
	const certUser = "CN=example.com,OU=NATS.io"

	// The client port has to be reachable under a name the test certificates
	// carry a SAN for, hence localhost rather than 127.0.0.1.
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: "localhost:-1"
		server_name: "S1"
		tls {
			cert_file: "../test/configs/certs/tlsauth/server.pem"
			key_file:  "../test/configs/certs/tlsauth/server-key.pem"
			ca_file:   "../test/configs/certs/tlsauth/ca.pem"
			verify_and_map: true
		}
		leafnodes { listen: "127.0.0.1:-1" }
		websocket { listen: "127.0.0.1:-1", no_tls: true }
		authorization {
			users [
				{ user = "CN=other.example.com,OU=NATS.io" }
				{ user = "%s" }
			]
		}
	`, certUser)))
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()

	for _, test := range []struct {
		name string
		user string
		pass string
	}{
		{"empty password", certUser, _EMPTY_},
		{"wrong password", certUser, "wrongpassword"},
		{"unknown user", "CN=attacker.com,OU=NATS.io", _EMPTY_},
		{"anonymous", _EMPTY_, _EMPTY_},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Run("leafnode", func(t *testing.T) {
				c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", o.LeafNode.Port))
				require_NoError(t, err)
				defer c.Close()

				br := bufio.NewReader(c)
				c.SetDeadline(time.Now().Add(2 * time.Second))
				// Consume the INFO the server sends on accept.
				_, _, err = br.ReadLine()
				require_NoError(t, err)

				_, err = fmt.Fprintf(c, "CONNECT {\"user\":%q,\"pass\":%q}\r\nPING\r\n", test.user, test.pass)
				require_NoError(t, err)

				line, _, err := br.ReadLine()
				require_NoError(t, err)
				require_Contains(t, string(line), authViolation)
			})

			// The mqtt listener is covered by
			// TestMQTTCertMappedUserNotPasswordAuthenticatable, its helpers are
			// behind the skip_mqtt_tests build tag.
			t.Run("websocket", func(t *testing.T) {
				testAuthWSConnect(t, o, test.user, test.pass, authViolation)
			})
		})
	}

	// The certificate based login on the mapped listener must still work.
	nc := natsConnect(t, s.ClientURL(),
		nats.ClientCert("../test/configs/certs/tlsauth/client.pem", "../test/configs/certs/tlsauth/client-key.pem"),
		nats.RootCAs("../test/configs/certs/tlsauth/ca.pem"))
	defer nc.Close()
	natsFlush(t, nc)
}

func TestAuthCertMappedUserWithPassword(t *testing.T) {
	const certUser = "CN=example.com,OU=NATS.io"

	conf := createConfFile(t, []byte(`
		listen: "localhost:-1"
		tls {
			cert_file: "../test/configs/certs/tlsauth/server.pem"
			key_file:  "../test/configs/certs/tlsauth/server-key.pem"
			ca_file:   "../test/configs/certs/tlsauth/ca.pem"
			verify_and_map: true
		}
		websocket { listen: "127.0.0.1:-1", no_tls: true }
		authorization {
			users [
				{ user = "CN=other.example.com,OU=NATS.io" }
				{ user = "CN=example.com,OU=NATS.io", password = "s3cr3t" }
			]
		}
	`))
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()

	certOpts := []nats.Option{
		nats.ClientCert("../test/configs/certs/tlsauth/client.pem", "../test/configs/certs/tlsauth/client-key.pem"),
		nats.RootCAs("../test/configs/certs/tlsauth/ca.pem"),
	}

	// The certificate on its own does not authenticate: the configured password
	// is still compared against what the client sent.
	if bad, err := nats.Connect(s.ClientURL(), certOpts...); err == nil {
		bad.Close()
		t.Fatal("Expected connection without the password to fail, it did not")
	}

	// The certificate together with the password does.
	nc := natsConnect(t, s.ClientURL(), append(certOpts, nats.UserInfo(_EMPTY_, "s3cr3t"))...)
	defer nc.Close()
	natsFlush(t, nc)

	// On the listener that does not map, the password is what authenticates.
	testAuthWSConnect(t, o, certUser, "s3cr3t", authAccepted)

	// But an empty one still does not.
	testAuthWSConnect(t, o, certUser, _EMPTY_, authViolation)
}

func TestAuthNoAuthUserWithoutPasswordAndCertMapping(t *testing.T) {
	conf := createConfFile(t, []byte(`
		listen: "127.0.0.1:-1"
		tls {
			cert_file: "../test/configs/certs/tlsauth/server.pem"
			key_file:  "../test/configs/certs/tlsauth/server-key.pem"
			ca_file:   "../test/configs/certs/tlsauth/ca.pem"
			verify_and_map: true
		}
		websocket { listen: "127.0.0.1:-1", no_tls: true }
		authorization {
			users [
				{ user = "CN=example.com,OU=NATS.io" }
				{ user = "guest" }
			]
		}
		no_auth_user: "guest"
	`))
	s, o := RunServerWithConfig(conf)
	defer s.Shutdown()

	// No credentials at all, so the server selects the no_auth_user itself.
	testAuthWSConnect(t, o, _EMPTY_, _EMPTY_, authAccepted)

	// Naming the no_auth_user explicitly is equivalent, it is reachable without
	// credentials either way.
	testAuthWSConnect(t, o, "guest", _EMPTY_, authAccepted)

	// The other passwordless user is a certificate identity, so naming it
	// explicitly must not authenticate.
	testAuthWSConnect(t, o, "CN=example.com,OU=NATS.io", _EMPTY_, authViolation)
}

func TestAuthCertMappedLeafNodeUsersScope(t *testing.T) {
	const (
		certUser = "CN=example.com,OU=NATS.io"
		leafTLS  = `tls {
				cert_file: "../test/configs/certs/tlsauth/server.pem"
				key_file:  "../test/configs/certs/tlsauth/server-key.pem"
				ca_file:   "../test/configs/certs/tlsauth/ca.pem"
				verify_and_map: true
			}`
	)

	// A leafnode block with its own users never consults the server's users
	// table, so its mapping says nothing about the users defined there. A
	// passwordless user in the top-level authorization block is not a
	// certificate identity here and must still authenticate.
	t.Run("leafnode users", func(t *testing.T) {
		conf := createConfFile(t, []byte(fmt.Sprintf(`
			listen: "127.0.0.1:-1"
			websocket { listen: "127.0.0.1:-1", no_tls: true }
			leafnodes {
				listen: "127.0.0.1:-1"
				%s
				authorization { users = [ { user = %q } ] }
			}
			authorization { users = [ { user = "telemetry" } ] }
		`, leafTLS, certUser)))
		s, o := RunServerWithConfig(conf)
		defer s.Shutdown()

		testAuthWSConnect(t, o, "telemetry", _EMPTY_, authAccepted)
	})

	// Without a leafnode authorization block the leafnode listener falls back to
	// the server's users table, so its mapping does make the passwordless users
	// there certificate identities.
	t.Run("no leafnode users", func(t *testing.T) {
		conf := createConfFile(t, []byte(fmt.Sprintf(`
			listen: "127.0.0.1:-1"
			websocket { listen: "127.0.0.1:-1", no_tls: true }
			leafnodes {
				listen: "127.0.0.1:-1"
				%s
			}
			authorization { users = [ { user = %q } ] }
		`, leafTLS, certUser)))
		s, o := RunServerWithConfig(conf)
		defer s.Shutdown()

		testAuthWSConnect(t, o, certUser, _EMPTY_, authViolation)
	})
}

// testAuthConnect performs the same CONNECT/PING exchange as testAuthWSConnect,
// but over the plain client port.
func testAuthConnect(t *testing.T, o *Options, user, pass, expect string) {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", o.Port))
	require_NoError(t, err)
	defer c.Close()

	br := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// Consume the INFO the server sends on accept.
	_, err = br.ReadString('\n')
	require_NoError(t, err)

	_, err = fmt.Fprintf(c, "CONNECT {\"verbose\":false,\"protocol\":1,\"user\":%q,\"pass\":%q}\r\nPING\r\n", user, pass)
	require_NoError(t, err)

	msg, err := br.ReadString('\n')
	require_NoError(t, err)
	if !strings.HasPrefix(msg, expect) {
		t.Fatalf("Expected %q, got %q", expect, msg)
	}
}

func TestAuthCertMappedUserConnectionTypeScope(t *testing.T) {
	// Only the client listener maps, so a passwordless user is a certificate
	// identity only if the mapping lookup there could have selected it, which it
	// cannot once allowed_connection_types excludes STANDARD.
	for _, test := range []struct {
		name   string
		types  string
		expect string
	}{
		{"unscoped", _EMPTY_, authViolation},
		{"standard and websocket", `, allowed_connection_types: ["STANDARD","WEBSOCKET"]`, authViolation},
		{"websocket only", `, allowed_connection_types: ["WEBSOCKET"]`, authAccepted},
		{"mqtt and websocket", `, allowed_connection_types: ["MQTT","WEBSOCKET"]`, authAccepted},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := createConfFile(t, []byte(fmt.Sprintf(`
				listen: "127.0.0.1:-1"
				tls {
					cert_file: "../test/configs/certs/tlsauth/server.pem"
					key_file:  "../test/configs/certs/tlsauth/server-key.pem"
					ca_file:   "../test/configs/certs/tlsauth/ca.pem"
					verify_and_map: true
				}
				websocket { listen: "127.0.0.1:-1", no_tls: true }
				authorization {
					users [
						{ user = "CN=example.com,OU=NATS.io" }
						{ user = "scoped"%s }
					]
				}
			`, test.types)))
			s, o := RunServerWithConfig(conf)
			defer s.Shutdown()

			testAuthWSConnect(t, o, "scoped", _EMPTY_, test.expect)
		})
	}
}

func TestAuthCertMappedUserOnOtherListeners(t *testing.T) {
	const certs = `
				cert_file: "../test/configs/certs/tlsauth/server.pem"
				key_file:  "../test/configs/certs/tlsauth/server-key.pem"
				ca_file:   "../test/configs/certs/tlsauth/ca.pem"
				verify_and_map: true`

	wsMapped := fmt.Sprintf(`websocket { listen: "127.0.0.1:-1", tls {%s} }`, certs)
	mqttMapped := fmt.Sprintf(`mqtt { listen: "127.0.0.1:-1", tls {%s} }`, certs)

	// The same blocks without a listen, so the listener never starts.
	wsDisabled := fmt.Sprintf(`websocket { tls {%s} }`, certs)
	mqttDisabled := fmt.Sprintf(`mqtt { tls {%s} }`, certs)
	leafDisabled := fmt.Sprintf(`leafnodes { tls {%s} }`, certs)

	// The client listener never maps here, so whether the passwordless user is a
	// certificate identity depends entirely on the listener that does.
	for _, test := range []struct {
		name     string
		listener string
		types    string
		expect   string
	}{
		{"websocket mapped", wsMapped, _EMPTY_, authViolation},
		{"websocket mapped, standard only", wsMapped, `, allowed_connection_types: ["STANDARD"]`, authAccepted},
		{"mqtt mapped", mqttMapped, _EMPTY_, authViolation},
		{"mqtt mapped, standard only", mqttMapped, `, allowed_connection_types: ["STANDARD"]`, authAccepted},
		// A block without a listener is inert, its mapping can select nobody.
		{"websocket mapped but disabled", wsDisabled, _EMPTY_, authAccepted},
		{"mqtt mapped but disabled", mqttDisabled, _EMPTY_, authAccepted},
		{"leafnode mapped but disabled", leafDisabled, _EMPTY_, authAccepted},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := createConfFile(t, []byte(fmt.Sprintf(`
				listen: "127.0.0.1:-1"
				jetstream { store_dir: %q }
				%s
				authorization {
					users [
						{ user = "CN=example.com,OU=NATS.io" }
						{ user = "scoped"%s }
					]
				}
			`, t.TempDir(), test.listener, test.types)))
			s, o := RunServerWithConfig(conf)
			defer s.Shutdown()

			testAuthConnect(t, o, "scoped", _EMPTY_, test.expect)
		})
	}
}

func TestAuthCertMappedUserOverWebsocketTransport(t *testing.T) {
	const certs = `
				cert_file: "../test/configs/certs/tlsauth/server.pem"
				key_file:  "../test/configs/certs/tlsauth/server-key.pem"
				ca_file:   "../test/configs/certs/tlsauth/ca.pem"`

	mqttMapped := fmt.Sprintf(`mqtt { listen: "127.0.0.1:-1", tls {%s
				verify_and_map: true} }`, certs)
	leafMapped := fmt.Sprintf(`leafnodes { listen: "127.0.0.1:-1", tls {%s
				verify_and_map: true} }`, certs)
	// Only the second websocket listener can collect a client certificate.
	wsPlain := `websocket { listen: "127.0.0.1:-1", no_tls: true }`
	wsCerts := fmt.Sprintf(`websocket { listen: "127.0.0.1:-1", tls {%s
				verify: true} }`, certs)

	// Mqtt and leafnode connections over websocket are mapped with their own
	// listener, but can only present a certificate if the websocket listener
	// asks for one.
	for _, test := range []struct {
		name   string
		mapped string
		ws     string
		types  string
		expect string
	}{
		{"mqtt, plain websocket", mqttMapped, wsPlain, `"STANDARD","MQTT_WS"`, authAccepted},
		{"mqtt, websocket with client certs", mqttMapped, wsCerts, `"STANDARD","MQTT_WS"`, authViolation},
		{"mqtt, direct mqtt allowed", mqttMapped, wsPlain, `"STANDARD","MQTT"`, authViolation},
		{"leafnode, plain websocket", leafMapped, wsPlain, `"STANDARD","LEAFNODE_WS"`, authAccepted},
		{"leafnode, websocket with client certs", leafMapped, wsCerts, `"STANDARD","LEAFNODE_WS"`, authViolation},
		{"leafnode, direct leafnode allowed", leafMapped, wsPlain, `"STANDARD","LEAFNODE"`, authViolation},
	} {
		t.Run(test.name, func(t *testing.T) {
			conf := createConfFile(t, []byte(fmt.Sprintf(`
				listen: "127.0.0.1:-1"
				jetstream { store_dir: %q }
				%s
				%s
				authorization {
					users [
						{ user = "CN=example.com,OU=NATS.io" }
						{ user = "scoped", allowed_connection_types: [%s] }
					]
				}
			`, t.TempDir(), test.mapped, test.ws, test.types)))
			s, o := RunServerWithConfig(conf)
			defer s.Shutdown()

			testAuthConnect(t, o, "scoped", _EMPTY_, test.expect)
		})
	}
}
