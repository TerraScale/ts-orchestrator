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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	crand "crypto/rand"
	mrand "math/rand/v2"

	"github.com/nats-io/nkeys"
)

// Nonce has to be a string since we used different encoding by default than json.Unmarshal.
type nonceInfo struct {
	Id    string `json:"server_id"`
	CID   uint64 `json:"client_id,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

// This is a seed for a user. We can extract public and private keys from this for testing.
var seed = []byte("SUAKYRHVIOREXV7EUZTBHUHL7NUMHPMAS7QMDU3GTIUWEI5LDNOXD43IZY")

func nkeyTCPServer(t *testing.T, opts *Options) *Server {
	t.Helper()
	s := RunServer(opts)
	t.Cleanup(func() {
		s.Shutdown()
		s.WaitForShutdown()
	})
	return s
}

func nkeyTCPClient(t *testing.T, s *Server) (net.Conn, *bufio.Reader, nonceInfo) {
	t.Helper()
	c, err := net.DialTimeout("tcp", s.Addr().String(), 5*time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { c.Close() })
	require_NoError(t, c.SetDeadline(time.Now().Add(5*time.Second)))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	require_NoError(t, err)
	if !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("Expected TCP INFO, got %q", line)
	}
	var info nonceInfo
	require_NoError(t, json.Unmarshal([]byte(line[5:]), &info))
	return c, br, info
}

func nkeyTCPConnect(t *testing.T, c net.Conn, br *bufio.Reader, fields, expected string) {
	t.Helper()
	if fields != "" {
		fields = "," + fields
	}
	_, err := fmt.Fprintf(c, "CONNECT {\"verbose\":true,\"pedantic\":true%s}\r\nPING\r\n", fields)
	require_NoError(t, err)
	line, err := br.ReadString('\n')
	require_NoError(t, err)
	if strings.TrimSpace(line) != expected {
		t.Fatalf("Expected %q after TCP CONNECT, got %q", expected, line)
	}
	line, err = br.ReadString('\n')
	if expected == "+OK" {
		require_NoError(t, err)
		if line != "PONG\r\n" {
			t.Fatalf("Expected authenticated TCP PONG, got %q", line)
		}
	} else if line != "" || !errors.Is(err, io.EOF) {
		t.Fatalf("Expected refused connection to close, got %q, error %v", line, err)
	}
}

func nkeyTCPKey(t *testing.T) (nkeys.KeyPair, string) {
	t.Helper()
	kp, err := nkeys.FromSeed(seed)
	require_NoError(t, err)
	pub, err := kp.PublicKey()
	require_NoError(t, err)
	return kp, pub
}

func nkeyTCPFields(t *testing.T, kp nkeys.KeyPair, pub string, info nonceInfo) string {
	t.Helper()
	if info.Nonce == "" {
		t.Fatal("Expected nonempty nonce from TCP INFO")
	}
	sig, err := kp.Sign([]byte(info.Nonce))
	require_NoError(t, err)
	return fmt.Sprintf(`"nkey":%q,"sig":%q`, pub, base64.RawURLEncoding.EncodeToString(sig))
}

func TestServerInfoNonceAlwaysEnabledTCP(t *testing.T) {
	opts := defaultServerOptions
	opts.AlwaysEnableNonce = true
	s := nkeyTCPServer(t, &opts)
	c, br, info := nkeyTCPClient(t, s)
	if info.Nonce == "" {
		t.Fatal("Expected TCP INFO nonce with AlwaysEnableNonce set")
	}
	nkeyTCPConnect(t, c, br, "", "+OK")
}

func TestServerInfoNonceTCP(t *testing.T) {
	t.Run("without nkeys", func(t *testing.T) {
		opts := defaultServerOptions
		s := nkeyTCPServer(t, &opts)
		c, br, info := nkeyTCPClient(t, s)
		if info.Nonce != "" {
			t.Fatal("Expected no TCP INFO nonce without nkeys")
		}
		nkeyTCPConnect(t, c, br, "", "+OK")
	})
	t.Run("distinct connection nonces", func(t *testing.T) {
		kp, pub := nkeyTCPKey(t)
		opts := defaultServerOptions
		opts.Nkeys = []*NkeyUser{{Nkey: pub}}
		s := nkeyTCPServer(t, &opts)
		c1, br1, info1 := nkeyTCPClient(t, s)
		c2, br2, info2 := nkeyTCPClient(t, s)
		if info1.Nonce == "" || info2.Nonce == "" || info1.Nonce == info2.Nonce {
			t.Fatal("Expected nonempty distinct TCP INFO nonces")
		}
		nkeyTCPConnect(t, c1, br1, nkeyTCPFields(t, kp, pub, info1), "+OK")
		nkeyTCPConnect(t, c2, br2, nkeyTCPFields(t, kp, pub, info2), "+OK")
	})
}

func TestNkeyClientConnectTCP(t *testing.T) {
	kp, pub := nkeyTCPKey(t)
	opts := defaultServerOptions
	opts.Nkeys = []*NkeyUser{{Nkey: pub}}
	s := nkeyTCPServer(t, &opts)
	for _, tc := range []struct {
		name   string
		fields string
	}{
		{"missing nkey and signature", ""},
		{"missing signature", fmt.Sprintf(`"nkey":%q`, pub)},
		{"invalid signature", fmt.Sprintf(`"nkey":%q,"sig":"bad_sig"`, pub)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, br, _ := nkeyTCPClient(t, s)
			nkeyTCPConnect(t, c, br, tc.fields, "-ERR 'Authorization Violation'")
		})
	}
	t.Run("signed nonce", func(t *testing.T) {
		c, br, info := nkeyTCPClient(t, s)
		nkeyTCPConnect(t, c, br, nkeyTCPFields(t, kp, pub, info), "+OK")
	})
}

func TestMixedClientConnectTCP(t *testing.T) {
	kp, pub := nkeyTCPKey(t)
	opts := defaultServerOptions
	opts.Nkeys = []*NkeyUser{{Nkey: pub}}
	opts.Users = []*User{{Username: "derek", Password: "foo"}}
	s := nkeyTCPServer(t, &opts)
	t.Run("password", func(t *testing.T) {
		c, br, _ := nkeyTCPClient(t, s)
		nkeyTCPConnect(t, c, br, `"user":"derek","pass":"foo"`, "+OK")
	})
	t.Run("nkey", func(t *testing.T) {
		c, br, info := nkeyTCPClient(t, s)
		nkeyTCPConnect(t, c, br, nkeyTCPFields(t, kp, pub, info), "+OK")
	})
}

func TestMixedClientConfigTCP(t *testing.T) {
	kp, pub := nkeyTCPKey(t)
	conf := createConfFile(t, []byte(fmt.Sprintf(`
		listen: "127.0.0.1:-1"
		authorization {
			users = [
				{nkey: %q}
				{user: alice, password: foo}
			]
		}`, pub)))
	opts, err := ProcessConfigFile(conf)
	require_NoError(t, err)
	opts.NoLog, opts.NoSigs = true, true
	s := nkeyTCPServer(t, opts)
	t.Run("password", func(t *testing.T) {
		c, br, _ := nkeyTCPClient(t, s)
		nkeyTCPConnect(t, c, br, `"user":"alice","pass":"foo"`, "+OK")
	})
	t.Run("nkey", func(t *testing.T) {
		c, br, info := nkeyTCPClient(t, s)
		nkeyTCPConnect(t, c, br, nkeyTCPFields(t, kp, pub, info), "+OK")
	})
	t.Run("wrong password", func(t *testing.T) {
		c, br, _ := nkeyTCPClient(t, s)
		nkeyTCPConnect(t, c, br, `"user":"alice","pass":"wrong"`, "-ERR 'Authorization Violation'")
	})
	t.Run("invalid signature", func(t *testing.T) {
		c, br, _ := nkeyTCPClient(t, s)
		nkeyTCPConnect(t, c, br, fmt.Sprintf(`"nkey":%q,"sig":"bad_sig"`, pub), "-ERR 'Authorization Violation'")
	})
}

func BenchmarkCryptoRandGeneration(b *testing.B) {
	data := make([]byte, 16)
	for i := 0; i < b.N; i++ {
		crand.Read(data)
	}
}

func BenchmarkMathRandGeneration(b *testing.B) {
	data := make([]byte, 16)
	prng := mrand.NewChaCha8([32]byte{42})
	for i := 0; i < b.N; i++ {
		prng.Read(data)
	}
}

func BenchmarkNonceGeneration(b *testing.B) {
	data := make([]byte, nonceRawLen)
	b64 := make([]byte, nonceLen)
	prand := mrand.NewChaCha8([32]byte{42})
	for i := 0; i < b.N; i++ {
		prand.Read(data)
		base64.RawURLEncoding.Encode(b64, data)
	}
}

func BenchmarkPublicVerify(b *testing.B) {
	data := make([]byte, nonceRawLen)
	nonce := make([]byte, nonceLen)
	crand.Read(data)
	base64.RawURLEncoding.Encode(nonce, data)

	user, err := nkeys.CreateUser()
	if err != nil {
		b.Fatalf("Error creating User Nkey: %v", err)
	}
	sig, err := user.Sign(nonce)
	if err != nil {
		b.Fatalf("Error sigining nonce: %v", err)
	}
	pk, err := user.PublicKey()
	if err != nil {
		b.Fatalf("Could not extract public key from user: %v", err)
	}
	pub, err := nkeys.FromPublicKey(pk)
	if err != nil {
		b.Fatalf("Could not create public key pair from public key string: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pub.Verify(nonce, sig); err != nil {
			b.Fatalf("Error verifying nonce: %v", err)
		}
	}
}
