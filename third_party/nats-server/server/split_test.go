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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type splitTCPReadConn struct {
	net.Conn
	width int
	reads atomic.Int64
}

func (c *splitTCPReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p[:min(len(p), c.width)])
	if n > 0 {
		c.reads.Add(1)
	}
	return n, err
}

func splitTCPConn(t *testing.T, width int, accept func(net.Conn) *client) (net.Conn, *bufio.Reader, *splitTCPReadConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require_NoError(t, err)
	defer listener.Close()
	nc, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { nc.Close() })
	require_NoError(t, nc.SetDeadline(time.Now().Add(5*time.Second)))
	accepted, err := listener.Accept()
	require_NoError(t, err)
	fragmented := &splitTCPReadConn{Conn: accepted, width: width}
	// This is the production accept action; only real socket read sizes change.
	require_NotNil(t, accept(fragmented))
	reader := bufio.NewReader(nc)
	line, err := reader.ReadString('\n')
	require_NoError(t, err)
	if !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("expected initial INFO, got %q", line)
	}
	return nc, reader, fragmented
}

func splitTCPClient(t *testing.T, s *Server, width int) (net.Conn, *bufio.Reader, *splitTCPReadConn) {
	t.Helper()
	nc, reader, fragmented := splitTCPConn(t, width, s.createClient)
	_, err := io.WriteString(nc, "CONNECT {\"verbose\":false,\"pedantic\":true,\"user\":\"test\",\"pass\":\"pass\"}\r\nPING\r\n")
	require_NoError(t, err)
	line, err := reader.ReadString('\n')
	require_NoError(t, err)
	require_Equal(t, line, "PONG\r\n")
	return nc, reader, fragmented
}

func TestSplitClientCommandsOverTCP(t *testing.T) {
	opts := DefaultOptions()
	opts.Username, opts.Password = "test", "pass"
	opts.NoSystemAccount = true
	s := RunServer(opts)
	defer s.Shutdown()

	for _, width := range []int{1, 2, 7, 64} {
		t.Run(fmt.Sprintf("read-width-%d", width), func(t *testing.T) {
			nc, reader, fragmented := splitTCPClient(t, s, width)
			write := func(packet string) {
				t.Helper()
				_, err := io.WriteString(nc, packet)
				require_NoError(t, err)
			}
			line := func(want string) {
				t.Helper()
				got, err := reader.ReadString('\n')
				require_NoError(t, err)
				require_Equal(t, got, want)
			}
			message := func(subject, sid, reply, payload string) {
				t.Helper()
				if reply != "" {
					reply += " "
				}
				line(fmt.Sprintf("MSG %s %s %s%d\r\n", subject, sid, reply, len(payload)))
				body := make([]byte, len(payload)+2)
				_, err := io.ReadFull(reader, body)
				require_NoError(t, err)
				require_Equal(t, string(body), payload+"\r\n")
			}

			write("SUB foo.bar 1024\r\nPING\r\n")
			line("PONG\r\n")
			for _, test := range []struct{ reply, payload string }{
				{"INBOX.22", "hello world"},
				{"", "hello world"},
				{"large.reply", strings.Repeat("A", 6040)},
			} {
				reply := test.reply
				if reply != "" {
					reply += " "
				}
				packet := fmt.Sprintf("PUB foo.bar %s%d\r\n%s\r\nPING\r\n", reply, len(test.payload), test.payload)
				before := fragmented.reads.Load()
				write(packet)
				message("foo.bar", "1024", test.reply, test.payload)
				line("PONG\r\n")
				if reads := fragmented.reads.Load() - before; reads < int64((len(packet)+width-1)/width) {
					t.Fatalf("packet was not fragmented: %d reads for %d bytes at width %d", reads, len(packet), width)
				}
			}
			write("UNSUB 999\r\nPUB foo.bar 11\r\nhello world\r\nPING\r\n")
			message("foo.bar", "1024", "", "hello world")
			line("PONG\r\n")
			write("UNSUB 1024\r\nSUB marker 2\r\nPUB foo.bar 11\r\nhello world\r\nPUB marker 2\r\nok\r\nPING\r\n")
			message("marker", "2", "", "ok")
			line("PONG\r\n")
		})
	}
}

func TestSplitPeerMessagesOverTCP(t *testing.T) {
	for _, kind := range []string{"route", "leaf"} {
		t.Run(kind, func(t *testing.T) {
			opts := DefaultOptions()
			opts.NoSystemAccount = true
			opts.Cluster.PoolSize = 1
			opts.Cluster.Compression.Mode = CompressionOff
			opts.LeafNode.Host, opts.LeafNode.Port = "127.0.0.1", -1
			opts.LeafNode.Compression.Mode = CompressionOff
			s := RunServer(opts)
			defer s.Shutdown()

			for _, width := range []int{1, 7} {
				t.Run(fmt.Sprintf("read-width-%d", width), func(t *testing.T) {
					subject := "foo.bar"
					accept := func(conn net.Conn) *client {
						return s.createRoute(conn, nil, Implicit, gossipDefault, _EMPTY_)
					}
					if kind == "leaf" {
						subject = "foo"
						accept = func(conn net.Conn) *client { return s.createLeafNode(conn, nil, nil, nil) }
					}
					nc := natsConnect(t, s.ClientURL())
					defer nc.Close()
					plain := natsSubSync(t, nc, subject)
					var queue *nats.Subscription
					if kind == "leaf" {
						queue = natsQueueSubSync(t, nc, subject, "baz")
					}
					natsFlush(t, nc)
					peer, reader, fragmented := splitTCPConn(t, width, accept)
					fence := func(protocol string) {
						t.Helper()
						require_NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
						_, err := io.WriteString(peer, protocol+"PING\r\n")
						require_NoError(t, err)
						for range 100 {
							line, err := reader.ReadString('\n')
							require_NoError(t, err)
							if line == "PONG\r\n" {
								return
							}
							if line == "PING\r\n" {
								_, err := io.WriteString(peer, "PONG\r\n")
								require_NoError(t, err)
							}
							if strings.HasPrefix(line, "-ERR") {
								t.Fatalf("peer protocol rejected: %s", line)
							}
						}
						t.Fatal("peer sent 100 control frames without PONG")
					}
					name := fmt.Sprintf("SPLIT_%s_%d", kind, width)
					if kind == "route" {
						info, err := json.Marshal(Info{ID: name, Name: name, Cluster: opts.Cluster.Name, Headers: true, RoutePoolSize: 1, Proto: RouteProtoV2})
						require_NoError(t, err)
						fence(fmt.Sprintf("CONNECT {\"name\":%q,\"cluster\":%q,\"headers\":true}\r\nINFO %s\r\n", name, opts.Cluster.Name, info))
					} else {
						fence(fmt.Sprintf("CONNECT {\"name\":%q}\r\n", name))
					}

					for _, payload := range []string{"hello world", strings.Repeat("A", 6040)} {
						prefix, reply := "RMSG $G foo.bar INBOX.22", "INBOX.22"
						if kind == "leaf" {
							prefix, reply = "LMSG foo + bar baz", "bar"
						}
						packet := fmt.Sprintf("%s %d\r\n%s\r\n", prefix, len(payload), payload)
						before := fragmented.reads.Load()
						fence(packet)
						for _, sub := range []*nats.Subscription{plain, queue} {
							if sub == nil {
								continue
							}
							msg, err := sub.NextMsg(time.Second)
							require_NoError(t, err)
							require_Equal(t, msg.Subject, subject)
							require_Equal(t, msg.Reply, reply)
							require_Equal(t, string(msg.Data), payload)
						}
						if reads := fragmented.reads.Load() - before; reads < int64((len(packet)+width-1)/width) {
							t.Fatalf("peer packet was not fragmented: %d reads for %d bytes at width %d", reads, len(packet), width)
						}
					}
				})
			}
		})
	}
}

func TestSplitBufferSubOp(t *testing.T) {
	cli, trash := net.Pipe()
	defer cli.Close()
	defer trash.Close()

	s := &Server{gacc: NewAccount(globalAccountName)}
	if err := s.newGateway(DefaultOptions()); err != nil {
		t.Fatalf("Error creating gateways: %v", err)
	}
	s.registerAccount(s.gacc)
	c := &client{srv: s, acc: s.gacc, msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription), nc: cli}

	subop := []byte("SUB foo 1\r\n")
	subop1 := subop[:6]
	subop2 := subop[6:]

	if err := c.parse(subop1); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != SUB_ARG {
		t.Fatalf("Expected SUB_ARG state vs %d\n", c.state)
	}
	if err := c.parse(subop2); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected OP_START state vs %d\n", c.state)
	}
	r := s.gacc.sl.Match("foo")
	if r == nil || len(r.psubs) != 1 {
		t.Fatalf("Did not match subscription properly: %+v\n", r)
	}
	sub := r.psubs[0]
	if !bytes.Equal(sub.subject, []byte("foo")) {
		t.Fatalf("Subject did not match expected 'foo' : '%s'\n", sub.subject)
	}
	if !bytes.Equal(sub.sid, []byte("1")) {
		t.Fatalf("Sid did not match expected '1' : '%s'\n", sub.sid)
	}
	if sub.queue != nil {
		t.Fatalf("Received a non-nil queue: '%s'\n", sub.queue)
	}
}

func TestSplitBufferUnsubOp(t *testing.T) {
	s := &Server{gacc: NewAccount(globalAccountName), gateway: &srvGateway{}}
	s.registerAccount(s.gacc)
	c := &client{srv: s, acc: s.gacc, msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}

	subop := []byte("SUB foo 1024\r\n")
	if err := c.parse(subop); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected OP_START state vs %d\n", c.state)
	}

	unsubop := []byte("UNSUB 1024\r\n")
	unsubop1 := unsubop[:8]
	unsubop2 := unsubop[8:]

	if err := c.parse(unsubop1); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != UNSUB_ARG {
		t.Fatalf("Expected UNSUB_ARG state vs %d\n", c.state)
	}
	if err := c.parse(unsubop2); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected OP_START state vs %d\n", c.state)
	}
	r := s.gacc.sl.Match("foo")
	if r != nil && len(r.psubs) != 0 {
		t.Fatalf("Should be no subscriptions in results: %+v\n", r)
	}
}

func TestSplitBufferPubOp(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}
	pub := []byte("PUB foo.bar INBOX.22 11\r\nhello world\r")
	pub1 := pub[:2]
	pub2 := pub[2:9]
	pub3 := pub[9:15]
	pub4 := pub[15:22]
	pub5 := pub[22:25]
	pub6 := pub[25:33]
	pub7 := pub[33:]

	if err := c.parse(pub1); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != OP_PU {
		t.Fatalf("Expected OP_PU state vs %d\n", c.state)
	}
	if err := c.parse(pub2); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != PUB_ARG {
		t.Fatalf("Expected OP_PU state vs %d\n", c.state)
	}
	if err := c.parse(pub3); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != PUB_ARG {
		t.Fatalf("Expected OP_PU state vs %d\n", c.state)
	}
	if err := c.parse(pub4); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != PUB_ARG {
		t.Fatalf("Expected PUB_ARG state vs %d\n", c.state)
	}
	if err := c.parse(pub5); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_PAYLOAD {
		t.Fatalf("Expected MSG_PAYLOAD state vs %d\n", c.state)
	}

	// Check c.pa
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("PUB arg subject incorrect: '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("INBOX.22")) {
		t.Fatalf("PUB arg reply subject incorrect: '%s'\n", c.pa.reply)
	}
	if c.pa.size != 11 {
		t.Fatalf("PUB arg msg size incorrect: %d\n", c.pa.size)
	}
	if err := c.parse(pub6); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_PAYLOAD {
		t.Fatalf("Expected MSG_PAYLOAD state vs %d\n", c.state)
	}
	if err := c.parse(pub7); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_END_N {
		t.Fatalf("Expected MSG_END_N state vs %d\n", c.state)
	}
}

func TestSplitBufferPubOp2(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}
	pub := []byte("PUB foo.bar INBOX.22 11\r\nhello world\r\n")
	pub1 := pub[:30]
	pub2 := pub[30:]

	if err := c.parse(pub1); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_PAYLOAD {
		t.Fatalf("Expected MSG_PAYLOAD state vs %d\n", c.state)
	}
	if err := c.parse(pub2); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected OP_START state vs %d\n", c.state)
	}
}

func TestSplitBufferPubOp3(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}
	pubAll := []byte("PUB foo bar 11\r\nhello world\r\n")
	pub := pubAll[:16]

	if err := c.parse(pub); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Unexpected subject: '%s' vs '%s'\n", c.pa.subject, "foo")
	}

	// Simulate next read of network, make sure pub state is saved
	// until msg payload has cleared.
	copy(pubAll, "XXXXXXXXXXXXXXXX")
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Unexpected subject: '%s' vs '%s'\n", c.pa.subject, "foo")
	}
	if !bytes.Equal(c.pa.reply, []byte("bar")) {
		t.Fatalf("Unexpected reply: '%s' vs '%s'\n", c.pa.reply, "bar")
	}
	if !bytes.Equal(c.pa.szb, []byte("11")) {
		t.Fatalf("Unexpected size bytes: '%s' vs '%s'\n", c.pa.szb, "11")
	}
}

func TestSplitBufferPubOp4(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}
	pubAll := []byte("PUB foo 11\r\nhello world\r\n")
	pub := pubAll[:12]

	if err := c.parse(pub); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Unexpected subject: '%s' vs '%s'\n", c.pa.subject, "foo")
	}

	// Simulate next read of network, make sure pub state is saved
	// until msg payload has cleared.
	copy(pubAll, "XXXXXXXXXXXX")
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Unexpected subject: '%s' vs '%s'\n", c.pa.subject, "foo")
	}
	if !bytes.Equal(c.pa.reply, []byte("")) {
		t.Fatalf("Unexpected reply: '%s' vs '%s'\n", c.pa.reply, "")
	}
	if !bytes.Equal(c.pa.szb, []byte("11")) {
		t.Fatalf("Unexpected size bytes: '%s' vs '%s'\n", c.pa.szb, "11")
	}
}

func TestSplitBufferPubOp5(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}
	pubAll := []byte("PUB foo 11\r\nhello world\r\n")

	// Splits need to be on MSG_END_R now too, so make sure we check that.
	// Split between \r and \n
	pub := pubAll[:len(pubAll)-1]

	if err := c.parse(pub); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.msgBuf == nil {
		t.Fatalf("msgBuf should not be nil!\n")
	}
	if !bytes.Equal(c.msgBuf, []byte("hello world\r")) {
		t.Fatalf("c.msgBuf did not snaphot the msg")
	}
}

func TestSplitConnectArg(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}
	connectAll := []byte("CONNECT {\"verbose\":false,\"tls_required\":false," +
		"\"user\":\"test\",\"pedantic\":true,\"pass\":\"pass\"}\r\n")

	argJSON := connectAll[8:]

	c1 := connectAll[:5]
	c2 := connectAll[5:22]
	c3 := connectAll[22 : len(connectAll)-2]
	c4 := connectAll[len(connectAll)-2:]

	if err := c.parse(c1); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.argBuf != nil {
		t.Fatalf("Unexpected argBug placeholder.\n")
	}

	if err := c.parse(c2); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.argBuf == nil {
		t.Fatalf("Expected argBug to not be nil.\n")
	}
	if !bytes.Equal(c.argBuf, argJSON[:14]) {
		t.Fatalf("argBuf not correct, received %q, wanted %q\n", argJSON[:14], c.argBuf)
	}

	if err := c.parse(c3); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.argBuf == nil {
		t.Fatalf("Expected argBug to not be nil.\n")
	}
	if !bytes.Equal(c.argBuf, argJSON[:len(argJSON)-2]) {
		t.Fatalf("argBuf not correct, received %q, wanted %q\n",
			argJSON[:len(argJSON)-2], c.argBuf)
	}

	if err := c.parse(c4); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.argBuf != nil {
		t.Fatalf("Unexpected argBuf placeholder.\n")
	}
}

func TestSplitDanglingArgBuf(t *testing.T) {
	opts := defaultServerOptions
	s := New(&opts)
	c := &client{srv: s, acc: s.gacc, msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription)}

	// We test to make sure we do not dangle any argBufs after processing
	// since that could lead to performance issues.

	// SUB
	subop := []byte("SUB foo 1\r\n")
	c.parse(subop[:6])
	c.parse(subop[6:])
	if c.argBuf != nil {
		t.Fatalf("Expected c.argBuf to be nil: %q\n", c.argBuf)
	}

	// UNSUB
	unsubop := []byte("UNSUB 1024\r\n")
	c.parse(unsubop[:8])
	c.parse(unsubop[8:])
	if c.argBuf != nil {
		t.Fatalf("Expected c.argBuf to be nil: %q\n", c.argBuf)
	}

	// PUB
	pubop := []byte("PUB foo.bar INBOX.22 11\r\nhello world\r\n")
	c.parse(pubop[:22])
	c.parse(pubop[22:25])
	if c.argBuf == nil {
		t.Fatal("Expected a non-nil argBuf!")
	}
	c.parse(pubop[25:])
	if c.argBuf != nil {
		t.Fatalf("Expected c.argBuf to be nil: %q\n", c.argBuf)
	}

	// MINUS_ERR
	errop := []byte("-ERR Too Long\r\n")
	c.parse(errop[:8])
	c.parse(errop[8:])
	if c.argBuf != nil {
		t.Fatalf("Expected c.argBuf to be nil: %q\n", c.argBuf)
	}

	// CONNECT_ARG
	connop := []byte("CONNECT {\"verbose\":false,\"tls_required\":false," +
		"\"user\":\"test\",\"pedantic\":true,\"pass\":\"pass\"}\r\n")
	c.parse(connop[:22])
	c.parse(connop[22:])
	if c.argBuf != nil {
		t.Fatalf("Expected c.argBuf to be nil: %q\n", c.argBuf)
	}

	// INFO_ARG
	infoop := []byte("INFO {\"server_id\":\"id\"}\r\n")
	c.parse(infoop[:8])
	c.parse(infoop[8:])
	if c.argBuf != nil {
		t.Fatalf("Expected c.argBuf to be nil: %q\n", c.argBuf)
	}

	// MSG (the client has to be a ROUTE)
	c = &client{msubs: -1, mpay: -1, subs: make(map[string]*subscription), kind: ROUTER, route: &route{}, mcl: MAX_CONTROL_LINE_SIZE}
	msgop := []byte("RMSG $foo foo 5\r\nhello\r\n")
	c.parse(msgop[:5])
	c.parse(msgop[5:10])
	if c.argBuf == nil {
		t.Fatal("Expected a non-nil argBuf")
	}
	if string(c.argBuf) != "$foo " {
		t.Fatalf("Expected argBuf to be \"$foo \", got %q", string(c.argBuf))
	}
	c.parse(msgop[10:])
	if c.argBuf != nil {
		t.Fatalf("Expected argBuf to be nil: %q", c.argBuf)
	}
	if c.msgBuf != nil {
		t.Fatalf("Expected msgBuf to be nil: %q", c.msgBuf)
	}

	c.state = OP_START
	// Parse up-to somewhere in the middle of the payload.
	// Verify that we have saved the MSG_ARG info
	c.parse(msgop[:23])
	if c.argBuf == nil {
		t.Fatal("Expected a non-nil argBuf")
	}
	if string(c.pa.account) != "$foo" {
		t.Fatalf("Expected account to be \"$foo\", got %q", c.pa.account)
	}
	if string(c.pa.subject) != "foo" {
		t.Fatalf("Expected subject to be \"foo\", got %q", c.pa.subject)
	}
	if string(c.pa.reply) != "" {
		t.Fatalf("Expected reply to be \"\", got %q", c.pa.reply)
	}
	if c.pa.size != 5 {
		t.Fatalf("Expected sid to 5, got %v", c.pa.size)
	}
	// msg buffer should be
	if c.msgBuf == nil || string(c.msgBuf) != "hello\r" {
		t.Fatalf("Expected msgBuf to be \"hello\r\", got %q", c.msgBuf)
	}
	c.parse(msgop[23:])
	// At the end, we should have cleaned-up both arg and msg buffers.
	if c.argBuf != nil {
		t.Fatalf("Expected argBuf to be nil: %q", c.argBuf)
	}
	if c.msgBuf != nil {
		t.Fatalf("Expected msgBuf to be nil: %q", c.msgBuf)
	}
}

func TestSplitRoutedMsgArg(t *testing.T) {
	_, c, _ := setupClient()
	defer c.close()
	// Allow parser to process RMSG
	c.kind = ROUTER
	c.route = &route{}

	b := make([]byte, 1024)

	copy(b, []byte("RMSG $G hello.world 6040\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	c.parse(b)

	copy(b, []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n"))
	c.parse(b)

	wantAccount := "$G"
	wantSubject := "hello.world"
	wantSzb := "6040"

	if string(c.pa.account) != wantAccount {
		t.Fatalf("Incorrect account: want %q, got %q", wantAccount, c.pa.account)
	}
	if string(c.pa.subject) != wantSubject {
		t.Fatalf("Incorrect subject: want %q, got %q", wantSubject, c.pa.subject)
	}
	if string(c.pa.szb) != wantSzb {
		t.Fatalf("Incorrect szb: want %q, got %q", wantSzb, c.pa.szb)
	}
}

func TestSplitBufferMsgOp(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription), kind: ROUTER, route: &route{}}
	msg := []byte("RMSG $G foo.bar _INBOX.22 11\r\nhello world\r")
	msg1 := msg[:2]
	msg2 := msg[2:9]
	msg3 := msg[9:15]
	msg4 := msg[15:22]
	msg5 := msg[22:25]
	msg6 := msg[25:37]
	msg7 := msg[37:40]
	msg8 := msg[40:]

	if err := c.parse(msg1); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != OP_M {
		t.Fatalf("Expected OP_M state vs %d\n", c.state)
	}
	if err := c.parse(msg2); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_ARG {
		t.Fatalf("Expected MSG_ARG state vs %d\n", c.state)
	}
	if err := c.parse(msg3); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_ARG {
		t.Fatalf("Expected MSG_ARG state vs %d\n", c.state)
	}
	if err := c.parse(msg4); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_ARG {
		t.Fatalf("Expected MSG_ARG state vs %d\n", c.state)
	}
	if err := c.parse(msg5); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_ARG {
		t.Fatalf("Expected MSG_ARG state vs %d\n", c.state)
	}
	if err := c.parse(msg6); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_PAYLOAD {
		t.Fatalf("Expected MSG_PAYLOAD state vs %d\n", c.state)
	}

	// Check c.pa
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("MSG arg subject incorrect: '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("_INBOX.22")) {
		t.Fatalf("MSG arg reply subject incorrect: '%s'\n", c.pa.reply)
	}
	if c.pa.size != 11 {
		t.Fatalf("MSG arg msg size incorrect: %d\n", c.pa.size)
	}
	if err := c.parse(msg7); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_PAYLOAD {
		t.Fatalf("Expected MSG_PAYLOAD state vs %d\n", c.state)
	}
	if err := c.parse(msg8); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_END_N {
		t.Fatalf("Expected MSG_END_N state vs %d\n", c.state)
	}
}

func TestSplitBufferLeafMsgArg(t *testing.T) {
	c := &client{msubs: -1, mpay: -1, mcl: 1024, subs: make(map[string]*subscription), kind: LEAF}
	msg := []byte("LMSG foo + bar baz 11\r\n")
	if err := c.parse(msg); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_PAYLOAD {
		t.Fatalf("Expected MSG_PAYLOAD state vs %d\n", c.state)
	}
	checkPA := func(t *testing.T) {
		t.Helper()
		if !bytes.Equal(c.pa.subject, []byte("foo")) {
			t.Fatalf("Expected subject to be %q, got %q", "foo", c.pa.subject)
		}
		if !bytes.Equal(c.pa.reply, []byte("bar")) {
			t.Fatalf("Expected reply to be %q, got %q", "bar", c.pa.reply)
		}
		if n := len(c.pa.queues); n != 1 {
			t.Fatalf("Expected 1 queue, got %v", n)
		}
		if !bytes.Equal(c.pa.queues[0], []byte("baz")) {
			t.Fatalf("Expected queues to be %q, got %q", "baz", c.pa.queues)
		}
	}
	checkPA(t)

	// overwrite msg with payload
	n := copy(msg, []byte("fffffffffff"))
	if err := c.parse(msg[:n]); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != MSG_END_R {
		t.Fatalf("Expected MSG_END_R state vs %d\n", c.state)
	}
	checkPA(t)

	// Finish processing
	copy(msg, []byte("\r\n"))
	if err := c.parse(msg[:2]); err != nil {
		t.Fatalf("Unexpected parse error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected OP_START state vs %d\n", c.state)
	}
	if c.pa.subject != nil || c.pa.reply != nil || c.pa.queues != nil || c.pa.size != 0 ||
		c.pa.szb != nil || c.pa.arg != nil {
		t.Fatalf("parser state not cleaned-up properly: %+v", c.pa)
	}
}
