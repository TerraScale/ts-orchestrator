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
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
)

func dummyClient() *client {
	opts := defaultServerOptions
	return &client{srv: New(&opts), msubs: -1, mpay: -1, mcl: MAX_CONTROL_LINE_SIZE}
}

func dummyRouteClient() *client {
	opts := defaultServerOptions
	return &client{srv: New(&opts), kind: ROUTER, mcl: MAX_CONTROL_LINE_SIZE}
}

func TestParsePing(t *testing.T) {
	c := dummyClient()
	if c.state != OP_START {
		t.Fatalf("Expected OP_START vs %d\n", c.state)
	}
	ping := []byte("PING\r\n")
	err := c.parse(ping[:1])
	if err != nil || c.state != OP_P {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(ping[1:2])
	if err != nil || c.state != OP_PI {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(ping[2:3])
	if err != nil || c.state != OP_PIN {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(ping[3:4])
	if err != nil || c.state != OP_PING {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(ping[4:5])
	if err != nil || c.state != OP_PING {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(ping[5:6])
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(ping)
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	// Should tolerate spaces
	ping = []byte("PING  \r")
	err = c.parse(ping)
	if err != nil || c.state != OP_PING {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	c.state = OP_START
	ping = []byte("PING  \r  \n")
	err = c.parse(ping)
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
}

func TestParsePong(t *testing.T) {
	c := dummyClient()
	if c.state != OP_START {
		t.Fatalf("Expected OP_START vs %d\n", c.state)
	}
	pong := []byte("PONG\r\n")
	err := c.parse(pong[:1])
	if err != nil || c.state != OP_P {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(pong[1:2])
	if err != nil || c.state != OP_PO {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(pong[2:3])
	if err != nil || c.state != OP_PON {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(pong[3:4])
	if err != nil || c.state != OP_PONG {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(pong[4:5])
	if err != nil || c.state != OP_PONG {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(pong[5:6])
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if c.ping.out != 0 {
		t.Fatalf("Unexpected ping.out value: %d vs 0\n", c.ping.out)
	}
	err = c.parse(pong)
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if c.ping.out != 0 {
		t.Fatalf("Unexpected ping.out value: %d vs 0\n", c.ping.out)
	}
	// Should tolerate spaces
	pong = []byte("PONG  \r")
	err = c.parse(pong)
	if err != nil || c.state != OP_PONG {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	c.state = OP_START
	pong = []byte("PONG  \r  \n")
	err = c.parse(pong)
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if c.ping.out != 0 {
		t.Fatalf("Unexpected ping.out value: %d vs 0\n", c.ping.out)
	}

	// Should be adjusting c.pout (Pings Outstanding): reset to 0
	c.state = OP_START
	c.ping.out = 10
	pong = []byte("PONG\r\n")
	err = c.parse(pong)
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if c.ping.out != 0 {
		t.Fatalf("Unexpected ping.out: %d vs 0\n", c.ping.out)
	}
}

func TestParseConnect(t *testing.T) {
	c := dummyClient()
	connect := []byte("CONNECT {\"verbose\":false,\"pedantic\":true,\"tls_required\":false}\r\n")
	err := c.parse(connect)
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	// Check saved state
	if c.as != 8 {
		t.Fatalf("ArgStart state incorrect: 8 vs %d\n", c.as)
	}
}

func TestParseSub(t *testing.T) {
	c := dummyClient()
	sub := []byte("SUB foo 1\r")
	err := c.parse(sub)
	if err != nil || c.state != SUB_ARG {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	// Check saved state
	if c.as != 4 {
		t.Fatalf("ArgStart state incorrect: 4 vs %d\n", c.as)
	}
	if c.drop != 1 {
		t.Fatalf("Drop state incorrect: 1 vs %d\n", c.as)
	}
	if !bytes.Equal(sub[c.as:], []byte("foo 1\r")) {
		t.Fatalf("Arg state incorrect: %s\n", sub[c.as:])
	}
}

func TestParsePub(t *testing.T) {
	c := dummyClient()

	pub := []byte("PUB foo 5\r\nhello\r")
	err := c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", string(c.pa.subject))
	}
	if c.pa.reply != nil {
		t.Fatalf("Did not parse reply correctly: 'nil' vs '%s'\n", string(c.pa.reply))
	}
	if c.pa.size != 5 {
		t.Fatalf("Did not parse msg size correctly: 5 vs %d\n", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("PUB foo.bar INBOX.22 11\r\nhello world\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", string(c.pa.subject))
	}
	if !bytes.Equal(c.pa.reply, []byte("INBOX.22")) {
		t.Fatalf("Did not parse reply correctly: 'INBOX.22' vs '%s'\n", string(c.pa.reply))
	}
	if c.pa.size != 11 {
		t.Fatalf("Did not parse msg size correctly: 11 vs %d\n", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	// This is the case when data has more bytes than expected by size.
	pub = []byte("PUB foo.bar 11\r\nhello world hello world\r")
	err = c.parse(pub)
	if err == nil {
		t.Fatalf("Expected an error parsing longer than expected message body")
	}
	if c.msgBuf != nil {
		t.Fatalf("Did not expect a c.msgBuf to be non-nil")
	}
}

// https://www.twistlock.com/labs-blog/finding-dos-vulnerability-nats-go-fuzz-cve-2019-13126/
func TestParsePubSizeOverflow(t *testing.T) {
	c := dummyClient()

	pub := []byte("PUB foo 3333333333333333333333333333333333333333333333333333333333333333\r\n")
	if err := c.parse(pub); err == nil {
		t.Fatalf("Expected an error")
	}
}

func TestParsePubArg(t *testing.T) {
	c := dummyClient()

	for _, test := range []struct {
		arg     string
		subject string
		reply   string
		size    int
		szb     string
	}{
		{arg: "a 2", subject: "a", reply: "", size: 2, szb: "2"},
		{arg: "a 222", subject: "a", reply: "", size: 222, szb: "222"},
		{arg: "foo 22", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: " foo 22", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "foo 22 ", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "foo   22", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: " foo 22 ", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: " foo   22 ", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "foo bar 22", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: " foo bar 22", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "foo bar 22 ", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "foo  bar  22", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: " foo bar 22 ", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "  foo   bar  22  ", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "  foo   bar  2222  ", subject: "foo", reply: "bar", size: 2222, szb: "2222"},
		{arg: "  foo     2222  ", subject: "foo", reply: "", size: 2222, szb: "2222"},
		{arg: "a\t2", subject: "a", reply: "", size: 2, szb: "2"},
		{arg: "a\t222", subject: "a", reply: "", size: 222, szb: "222"},
		{arg: "foo\t22", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "\tfoo\t22", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "foo\t22\t", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "foo\t\t\t22", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "\tfoo\t22\t", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "\tfoo\t\t\t22\t", subject: "foo", reply: "", size: 22, szb: "22"},
		{arg: "foo\tbar\t22", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "\tfoo\tbar\t22", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "foo\tbar\t22\t", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "foo\t\tbar\t\t22", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "\tfoo\tbar\t22\t", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "\t \tfoo\t \t \tbar\t \t22\t \t", subject: "foo", reply: "bar", size: 22, szb: "22"},
		{arg: "\t\tfoo\t\t\tbar\t\t2222\t\t", subject: "foo", reply: "bar", size: 2222, szb: "2222"},
		{arg: "\t \tfoo\t \t \t\t\t2222\t \t", subject: "foo", reply: "", size: 2222, szb: "2222"},
	} {
		t.Run(test.arg, func(t *testing.T) {
			if err := c.processPub([]byte(test.arg)); err != nil {
				t.Fatalf("Unexpected parse error: %v\n", err)
			}
			if !bytes.Equal(c.pa.subject, []byte(test.subject)) {
				t.Fatalf("Mismatched subject: '%s'\n", c.pa.subject)
			}
			if !bytes.Equal(c.pa.reply, []byte(test.reply)) {
				t.Fatalf("Mismatched reply subject: '%s'\n", c.pa.reply)
			}
			if !bytes.Equal(c.pa.szb, []byte(test.szb)) {
				t.Fatalf("Bad size buf: '%s'\n", c.pa.szb)
			}
			if c.pa.size != test.size {
				t.Fatalf("Bad size: %d\n", c.pa.size)
			}
		})
	}
}

func TestParsePubBadSize(t *testing.T) {
	c := dummyClient()
	// Setup localized max payload
	c.mpay = 32768
	if err := c.processPub([]byte("foo 2222222222222222")); err == nil {
		t.Fatalf("Expected parse error for size too large")
	}
}

func TestParseLeafMsgBadSize(t *testing.T) {
	c := dummyClient()
	c.kind = LEAF
	c.leaf = &leaf{}
	c.mpay = 16
	require_Error(t, c.processLeafMsgArgs([]byte("foo 17")), ErrMaxPayload)
}

func TestParseLeafHeaderMsgBadSize(t *testing.T) {
	c := dummyClient()
	c.kind = LEAF
	c.leaf = &leaf{}
	c.mpay = 16
	require_Error(t, c.processLeafHeaderMsgArgs([]byte("foo 4 17")), ErrMaxPayload)
}

func TestParseHeaderPub(t *testing.T) {
	c := dummyClient()
	c.headers = true

	hpub := []byte("HPUB foo 12 17\r\nname:derek\r\nHELLO\r")
	if err := c.parse(hpub); err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'", c.pa.subject)
	}
	if c.pa.reply != nil {
		t.Fatalf("Did not parse reply correctly: 'nil' vs '%s'", c.pa.reply)
	}
	if c.pa.hdr != 12 {
		t.Fatalf("Did not parse msg header size correctly: 12 vs %d", c.pa.hdr)
	}
	if !bytes.Equal(c.pa.hdb, []byte("12")) {
		t.Fatalf("Did not parse or capture the header size as bytes correctly: %q", c.pa.hdb)
	}
	if c.pa.size != 17 {
		t.Fatalf("Did not parse msg size correctly: 17 vs %d", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	hpub = []byte("HPUB foo INBOX.22 12 17\r\nname:derek\r\nHELLO\r")
	if err := c.parse(hpub); err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("INBOX.22")) {
		t.Fatalf("Did not parse reply correctly: 'INBOX.22' vs '%s'", c.pa.reply)
	}
	if c.pa.hdr != 12 {
		t.Fatalf("Did not parse msg header size correctly: 12 vs %d", c.pa.hdr)
	}
	if !bytes.Equal(c.pa.hdb, []byte("12")) {
		t.Fatalf("Did not parse or capture the header size as bytes correctly: %q", c.pa.hdb)
	}
	if c.pa.size != 17 {
		t.Fatalf("Did not parse msg size correctly: 17 vs %d", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	hpub = []byte("HPUB foo INBOX.22 0 5\r\nHELLO\r")
	if err := c.parse(hpub); err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("INBOX.22")) {
		t.Fatalf("Did not parse reply correctly: 'INBOX.22' vs '%s'\n", c.pa.reply)
	}
	if c.pa.hdr != 0 {
		t.Fatalf("Did not parse msg header size correctly: 0 vs %d\n", c.pa.hdr)
	}
	if !bytes.Equal(c.pa.hdb, []byte("0")) {
		t.Fatalf("Did not parse or capture the header size as bytes correctly: %q", c.pa.hdb)
	}
	if c.pa.size != 5 {
		t.Fatalf("Did not parse msg size correctly: 5 vs %d\n", c.pa.size)
	}
}

func TestParseHeaderPubArg(t *testing.T) {
	c := dummyClient()
	c.headers = true

	for _, test := range []struct {
		arg     string
		subject string
		reply   string
		hdr     int
		size    int
		szb     string
	}{
		{arg: "a 2 4", subject: "a", reply: "", hdr: 2, size: 4, szb: "4"},
		{arg: "a 22 222", subject: "a", reply: "", hdr: 22, size: 222, szb: "222"},
		{arg: "foo 3 22", subject: "foo", reply: "", hdr: 3, size: 22, szb: "22"},
		{arg: " foo   1 22", subject: "foo", reply: "", hdr: 1, size: 22, szb: "22"},
		{arg: "foo 0   22 ", subject: "foo", reply: "", hdr: 0, size: 22, szb: "22"},
		{arg: "foo  0     22", subject: "foo", reply: "", hdr: 0, size: 22, szb: "22"},
		{arg: " foo 1 22 ", subject: "foo", reply: "", hdr: 1, size: 22, szb: "22"},
		{arg: " foo   3 22 ", subject: "foo", reply: "", hdr: 3, size: 22, szb: "22"},
		{arg: "foo bar 1 22", subject: "foo", reply: "bar", hdr: 1, size: 22, szb: "22"},
		{arg: " foo bar 11 22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "foo bar 11 22 ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "foo  bar  11  22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: " foo bar  11 22 ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "  foo   bar  11   22  ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "  foo   bar  22   2222  ", subject: "foo", reply: "bar", hdr: 22, size: 2222, szb: "2222"},
		{arg: "  foo 1    2222  ", subject: "foo", reply: "", hdr: 1, size: 2222, szb: "2222"},
		{arg: "a\t2\t22", subject: "a", reply: "", hdr: 2, size: 22, szb: "22"},
		{arg: "a\t2\t\t222", subject: "a", reply: "", hdr: 2, size: 222, szb: "222"},
		{arg: "foo\t2 22", subject: "foo", reply: "", hdr: 2, size: 22, szb: "22"},
		{arg: "\tfoo\t11\t  22", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
		{arg: "foo\t11\t22\t", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
		{arg: "foo\t\t\t11 22", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
		{arg: "\tfoo\t11\t \t 22\t", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
		{arg: "\tfoo\t\t\t11 22\t", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
		{arg: "foo\tbar\t2 22", subject: "foo", reply: "bar", hdr: 2, size: 22, szb: "22"},
		{arg: "\tfoo\tbar\t11\t22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "foo\tbar\t11\t\t22\t ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "foo\t\tbar\t\t11\t\t\t22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "\tfoo\tbar\t11\t22\t", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "\t \tfoo\t \t \tbar\t \t11\t 22\t \t", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
		{arg: "\t\tfoo\t\t\tbar\t\t22\t\t\t2222\t\t", subject: "foo", reply: "bar", hdr: 22, size: 2222, szb: "2222"},
		{arg: "\t \tfoo\t \t \t\t\t11\t\t 2222\t \t", subject: "foo", reply: "", hdr: 11, size: 2222, szb: "2222"},
	} {
		t.Run(test.arg, func(t *testing.T) {
			if err := c.processHeaderPub([]byte(test.arg), nil); err != nil {
				t.Fatalf("Unexpected parse error: %v\n", err)
			}
			if !bytes.Equal(c.pa.subject, []byte(test.subject)) {
				t.Fatalf("Mismatched subject: '%s'\n", c.pa.subject)
			}
			if !bytes.Equal(c.pa.reply, []byte(test.reply)) {
				t.Fatalf("Mismatched reply subject: '%s'\n", c.pa.reply)
			}
			if !bytes.Equal(c.pa.szb, []byte(test.szb)) {
				t.Fatalf("Bad size buf: '%s'\n", c.pa.szb)
			}
			if c.pa.hdr != test.hdr {
				t.Fatalf("Bad header size: %d\n", c.pa.hdr)
			}
			if c.pa.size != test.size {
				t.Fatalf("Bad size: %d\n", c.pa.size)
			}
		})
	}
}

func TestParseRoutedHeaderMsg(t *testing.T) {
	c := dummyRouteClient()
	c.route = &route{}

	pub := []byte("HMSG $foo foo 10 8\r\nXXXhello\r")
	if err := c.parse(pub); err == nil {
		t.Fatalf("Expected an error")
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("HMSG $foo foo 3 8\r\nXXXhello\r")
	err := c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$foo")) {
		t.Fatalf("Did not parse account correctly: '$foo' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if c.pa.reply != nil {
		t.Fatalf("Did not parse reply correctly: 'nil' vs '%s'\n", c.pa.reply)
	}
	if c.pa.hdr != 3 {
		t.Fatalf("Did not parse header size correctly: 3 vs %d\n", c.pa.hdr)
	}
	if c.pa.size != 8 {
		t.Fatalf("Did not parse msg size correctly: 8 vs %d\n", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("HMSG $G foo.bar INBOX.22 3 14\r\nOK:hello world\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$G")) {
		t.Fatalf("Did not parse account correctly: '$G' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("INBOX.22")) {
		t.Fatalf("Did not parse reply correctly: 'INBOX.22' vs '%s'\n", c.pa.reply)
	}
	if c.pa.hdr != 3 {
		t.Fatalf("Did not parse header size correctly: 3 vs %d\n", c.pa.hdr)
	}
	if c.pa.size != 14 {
		t.Fatalf("Did not parse msg size correctly: 14 vs %d\n", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("HMSG $G foo.bar + reply baz 3 14\r\nOK:hello world\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$G")) {
		t.Fatalf("Did not parse account correctly: '$G' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("reply")) {
		t.Fatalf("Did not parse reply correctly: 'reply' vs '%s'\n", c.pa.reply)
	}
	if len(c.pa.queues) != 1 {
		t.Fatalf("Expected 1 queue, got %d", len(c.pa.queues))
	}
	if !bytes.Equal(c.pa.queues[0], []byte("baz")) {
		t.Fatalf("Did not parse queues correctly: 'baz' vs '%q'\n", c.pa.queues[0])
	}
	if c.pa.hdr != 3 {
		t.Fatalf("Did not parse header size correctly: 3 vs %d\n", c.pa.hdr)
	}
	if c.pa.size != 14 {
		t.Fatalf("Did not parse msg size correctly: 14 vs %d\n", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("HMSG $G foo.bar | baz 3 14\r\nOK:hello world\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$G")) {
		t.Fatalf("Did not parse account correctly: '$G' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("")) {
		t.Fatalf("Did not parse reply correctly: '' vs '%s'\n", c.pa.reply)
	}
	if len(c.pa.queues) != 1 {
		t.Fatalf("Expected 1 queue, got %d", len(c.pa.queues))
	}
	if !bytes.Equal(c.pa.queues[0], []byte("baz")) {
		t.Fatalf("Did not parse queues correctly: 'baz' vs '%q'\n", c.pa.queues[0])
	}
	if c.pa.hdr != 3 {
		t.Fatalf("Did not parse header size correctly: 3 vs %d\n", c.pa.hdr)
	}
	if c.pa.size != 14 {
		t.Fatalf("Did not parse msg size correctly: 14 vs %d\n", c.pa.size)
	}
}

func TestParseRouteMsg(t *testing.T) {
	c := dummyRouteClient()
	c.route = &route{}

	pub := []byte("MSG $foo foo 5\r\nhello\r")
	err := c.parse(pub)
	if err == nil {
		t.Fatalf("Expected an error, got none")
	}
	pub = []byte("RMSG $foo foo 5\r\nhello\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$foo")) {
		t.Fatalf("Did not parse account correctly: '$foo' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if c.pa.reply != nil {
		t.Fatalf("Did not parse reply correctly: 'nil' vs '%s'\n", c.pa.reply)
	}
	if c.pa.size != 5 {
		t.Fatalf("Did not parse msg size correctly: 5 vs %d\n", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("RMSG $G foo.bar INBOX.22 11\r\nhello world\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$G")) {
		t.Fatalf("Did not parse account correctly: '$G' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("INBOX.22")) {
		t.Fatalf("Did not parse reply correctly: 'INBOX.22' vs '%s'\n", c.pa.reply)
	}
	if c.pa.size != 11 {
		t.Fatalf("Did not parse msg size correctly: 11 vs %d\n", c.pa.size)
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("RMSG $G foo.bar + reply baz 11\r\nhello world\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$G")) {
		t.Fatalf("Did not parse account correctly: '$G' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("reply")) {
		t.Fatalf("Did not parse reply correctly: 'reply' vs '%s'\n", c.pa.reply)
	}
	if len(c.pa.queues) != 1 {
		t.Fatalf("Expected 1 queue, got %d", len(c.pa.queues))
	}
	if !bytes.Equal(c.pa.queues[0], []byte("baz")) {
		t.Fatalf("Did not parse queues correctly: 'baz' vs '%q'\n", c.pa.queues[0])
	}

	// Clear snapshots
	c.argBuf, c.msgBuf, c.state = nil, nil, OP_START

	pub = []byte("RMSG $G foo.bar | baz 11\r\nhello world\r")
	err = c.parse(pub)
	if err != nil || c.state != MSG_END_N {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	if !bytes.Equal(c.pa.account, []byte("$G")) {
		t.Fatalf("Did not parse account correctly: '$G' vs '%s'\n", c.pa.account)
	}
	if !bytes.Equal(c.pa.subject, []byte("foo.bar")) {
		t.Fatalf("Did not parse subject correctly: 'foo' vs '%s'\n", c.pa.subject)
	}
	if !bytes.Equal(c.pa.reply, []byte("")) {
		t.Fatalf("Did not parse reply correctly: '' vs '%s'\n", c.pa.reply)
	}
	if len(c.pa.queues) != 1 {
		t.Fatalf("Expected 1 queue, got %d", len(c.pa.queues))
	}
	if !bytes.Equal(c.pa.queues[0], []byte("baz")) {
		t.Fatalf("Did not parse queues correctly: 'baz' vs '%q'\n", c.pa.queues[0])
	}
}

func TestParseMsgSpace(t *testing.T) {
	c := dummyRouteClient()

	// Ivan bug he found
	if err := c.parse([]byte("MSG \r\n")); err == nil {
		t.Fatalf("Expected parse error for MSG <SPC>")
	}

	c = dummyClient()

	// Anything with an M from a client should parse error
	if err := c.parse([]byte("M")); err == nil {
		t.Fatalf("Expected parse error for M* from a client")
	}
}

func TestParsePingNoAuthUserExceptionsAndRestrictions(t *testing.T) {
	opts := defaultServerOptions
	s := New(&opts)
	s.opts.NoAuthUser = "foo"
	s.users = map[string]*User{
		"foo": {Username: "foo"},
	}

	newAuthPendingClient := func(kind int, gw *gateway, route *route, leaf *leaf, ws *websocket) *client {
		c := &client{
			srv: s, kind: kind,
			gw: gw, route: route, leaf: leaf, ws: ws,
			atmr: time.AfterFunc(time.Minute, func() {}),
		}
		c.flags.set(expectConnect)
		t.Cleanup(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.clearAuthTimer()
		})
		return c
	}

	for _, test := range []struct {
		name  string
		kind  int
		gw    *gateway
		route *route
		leaf  *leaf
	}{
		{name: "Leaf", kind: LEAF, leaf: &leaf{}},
		{name: "Route", kind: ROUTER, route: &route{}},
		{name: "Gateway", kind: GATEWAY, gw: &gateway{}},
	} {
		t.Run(test.name+"NotAllowed", func(t *testing.T) {
			c := newAuthPendingClient(test.kind, test.gw, test.route, test.leaf, nil)
			require_Error(t, c.parse([]byte("PING\r\n")), ErrAuthentication)
			require_False(t, c.flags.isSet(connectReceived))
		})
	}

	for _, test := range []struct {
		name string
		kind int
		ws   *websocket
	}{
		{name: "Client", kind: CLIENT},
		{name: "WebSocket", kind: CLIENT, ws: &websocket{}},
	} {
		t.Run(test.name+"Allowed", func(t *testing.T) {
			c := newAuthPendingClient(test.kind, nil, nil, nil, test.ws)
			require_NoError(t, c.parse([]byte("PING\r\n")))
			require_True(t, c.flags.isSet(connectReceived))
		})
	}
}

func TestParsePingNoAuthUserEnforcesUserRestrictions(t *testing.T) {
	newServer := func(user *User) *Server {
		opts := defaultServerOptions
		s := New(&opts)
		s.opts.NoAuthUser = user.Username
		s.users = map[string]*User{user.Username: user}
		return s
	}

	newAuthPendingClient := func(s *Server, ws *websocket) *client {
		c := &client{
			srv: s, kind: CLIENT, ws: ws,
			atmr: time.AfterFunc(time.Minute, func() {}),
		}
		c.flags.set(expectConnect)
		t.Cleanup(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.clearAuthTimer()
		})
		return c
	}

	t.Run("AllowedConnectionTypes", func(t *testing.T) {
		// no_auth_user restricted to WebSocket connections only.
		s := newServer(&User{
			Username:               "foo",
			AllowedConnectionTypes: map[string]struct{}{jwt.ConnectionTypeWebsocket: {}},
		})

		// A standard TCP client must be rejected, just like the CONNECT path.
		c := newAuthPendingClient(s, nil)
		require_Error(t, c.parse([]byte("PING\r\n")), ErrAuthentication)
		require_False(t, c.flags.isSet(connectReceived))

		// A WebSocket client satisfies the restriction and is allowed.
		c = newAuthPendingClient(s, &websocket{})
		require_NoError(t, c.parse([]byte("PING\r\n")))
		require_True(t, c.flags.isSet(connectReceived))
	})

	t.Run("ProxyRequired", func(t *testing.T) {
		// no_auth_user that may only connect through a trusted proxy. A
		// connection reaching the pre-CONNECT fast path never carries a proxy
		// signature, so it must always be rejected.
		s := newServer(&User{Username: "foo", ProxyRequired: true})

		for _, ws := range []*websocket{nil, {}} {
			c := newAuthPendingClient(s, ws)
			require_Error(t, c.parse([]byte("PING\r\n")), ErrAuthentication)
			require_False(t, c.flags.isSet(connectReceived))
		}
	})
}

func TestParsePingAllowedAfterConnectForNonClients(t *testing.T) {
	for _, test := range []struct {
		name  string
		kind  int
		gw    *gateway
		route *route
		leaf  *leaf
	}{
		{name: "Leaf", kind: LEAF, leaf: &leaf{}},
		{name: "Route", kind: ROUTER, route: &route{}},
		{name: "Gateway", kind: GATEWAY, gw: &gateway{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &client{
				srv: func() *Server {
					opts := defaultServerOptions
					return New(&opts)
				}(),
				kind:  test.kind,
				gw:    test.gw,
				route: test.route,
				leaf:  test.leaf,
			}
			c.flags.set(connectReceived)

			require_NoError(t, c.parse([]byte("PING\r\n")))
			require_Equal(t, c.state, OP_START)
		})
	}
}

func TestShouldFail(t *testing.T) {
	wrongProtos := []string{
		"xxx",
		"Px", "PIx", "PINx", " PING",
		"POx", "PONx",
		"+x", "+Ox",
		"-x", "-Ex", "-ERx", "-ERRx",
		"Cx", "COx", "CONx", "CONNx", "CONNEx", "CONNECx", "CONNECx", "CONNECT \r\n",
		"PUx", "PUB foo\r\n", "PUB  \r\n", "PUB foo bar       \r\n",
		"PUB foo 2\r\nok \r\n", "PUB foo 2\r\nok\r \n",
		"Sx", "SUx", "SUB\r\n", "SUB  \r\n", "SUB foo\r\n",
		"SUB foo bar baz 22\r\n",
		"Ux", "UNx", "UNSx", "UNSUx", "UNSUBx", "UNSUBUNSUB 1\r\n", "UNSUB_2\r\n",
		"UNSUB_UNSUB_UNSUB 2\r\n", "UNSUB_\t2\r\n", "UNSUB\r\n", "UNSUB \r\n",
		"UNSUB          \t       \r\n",
		"Ix", "INx", "INFx", "INFO  \r\n",
	}
	for _, proto := range wrongProtos {
		c := dummyClient()
		if err := c.parse([]byte(proto)); err == nil {
			t.Fatalf("Should have received a parse error for: %v", proto)
		}
	}

	// Special case for MSG, type needs to not be client.
	wrongProtos = []string{"Mx", "MSx", "MSGx", "MSG  \r\n"}
	for _, proto := range wrongProtos {
		c := dummyClient()
		c.kind = ROUTER
		if err := c.parse([]byte(proto)); err == nil {
			t.Fatalf("Should have received a parse error for: %v", proto)
		}
	}
}

func TestProtoSnippet(t *testing.T) {
	sample := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	tests := []struct {
		input    int
		expected string
	}{
		{0, `"abcdefghijklmnopqrstuvwxyzABCDEF"`},
		{1, `"bcdefghijklmnopqrstuvwxyzABCDEFG"`},
		{2, `"cdefghijklmnopqrstuvwxyzABCDEFGH"`},
		{3, `"defghijklmnopqrstuvwxyzABCDEFGHI"`},
		{4, `"efghijklmnopqrstuvwxyzABCDEFGHIJ"`},
		{5, `"fghijklmnopqrstuvwxyzABCDEFGHIJK"`},
		{6, `"ghijklmnopqrstuvwxyzABCDEFGHIJKL"`},
		{7, `"hijklmnopqrstuvwxyzABCDEFGHIJKLM"`},
		{8, `"ijklmnopqrstuvwxyzABCDEFGHIJKLMN"`},
		{9, `"jklmnopqrstuvwxyzABCDEFGHIJKLMNO"`},
		{10, `"klmnopqrstuvwxyzABCDEFGHIJKLMNOP"`},
		{11, `"lmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"`},
		{12, `"mnopqrstuvwxyzABCDEFGHIJKLMNOPQR"`},
		{13, `"nopqrstuvwxyzABCDEFGHIJKLMNOPQRS"`},
		{14, `"opqrstuvwxyzABCDEFGHIJKLMNOPQRST"`},
		{15, `"pqrstuvwxyzABCDEFGHIJKLMNOPQRSTU"`},
		{16, `"qrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"`},
		{17, `"rstuvwxyzABCDEFGHIJKLMNOPQRSTUVW"`},
		{18, `"stuvwxyzABCDEFGHIJKLMNOPQRSTUVWX"`},
		{19, `"tuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY"`},
		{20, `"uvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"`},
		{21, `"vwxyzABCDEFGHIJKLMNOPQRSTUVWXY"`},
		{22, `"wxyzABCDEFGHIJKLMNOPQRSTUVWXY"`},
		{23, `"xyzABCDEFGHIJKLMNOPQRSTUVWXY"`},
		{24, `"yzABCDEFGHIJKLMNOPQRSTUVWXY"`},
		{25, `"zABCDEFGHIJKLMNOPQRSTUVWXY"`},
		{26, `"ABCDEFGHIJKLMNOPQRSTUVWXY"`},
		{27, `"BCDEFGHIJKLMNOPQRSTUVWXY"`},
		{28, `"CDEFGHIJKLMNOPQRSTUVWXY"`},
		{29, `"DEFGHIJKLMNOPQRSTUVWXY"`},
		{30, `"EFGHIJKLMNOPQRSTUVWXY"`},
		{31, `"FGHIJKLMNOPQRSTUVWXY"`},
		{32, `"GHIJKLMNOPQRSTUVWXY"`},
		{33, `"HIJKLMNOPQRSTUVWXY"`},
		{34, `"IJKLMNOPQRSTUVWXY"`},
		{35, `"JKLMNOPQRSTUVWXY"`},
		{36, `"KLMNOPQRSTUVWXY"`},
		{37, `"LMNOPQRSTUVWXY"`},
		{38, `"MNOPQRSTUVWXY"`},
		{39, `"NOPQRSTUVWXY"`},
		{40, `"OPQRSTUVWXY"`},
		{41, `"PQRSTUVWXY"`},
		{42, `"QRSTUVWXY"`},
		{43, `"RSTUVWXY"`},
		{44, `"STUVWXY"`},
		{45, `"TUVWXY"`},
		{46, `"UVWXY"`},
		{47, `"VWXY"`},
		{48, `"WXY"`},
		{49, `"XY"`},
		{50, `"Y"`},
		{51, `""`},
		{52, `""`},
		{53, `""`},
		{54, `""`},
	}

	for _, tt := range tests {
		got := protoSnippet(tt.input, PROTO_SNIPPET_SIZE, sample)
		if tt.expected != got {
			t.Errorf("Expected protocol snippet to be %s when start=%d but got %s\n", tt.expected, tt.input, got)
		}
	}
}

func TestParseOK(t *testing.T) {
	c := dummyClient()
	if c.state != OP_START {
		t.Fatalf("Expected OP_START vs %d\n", c.state)
	}
	okProto := []byte("+OK\r\n")
	err := c.parse(okProto[:1])
	if err != nil || c.state != OP_PLUS {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(okProto[1:2])
	if err != nil || c.state != OP_PLUS_O {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(okProto[2:3])
	if err != nil || c.state != OP_PLUS_OK {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(okProto[3:4])
	if err != nil || c.state != OP_PLUS_OK {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
	err = c.parse(okProto[4:5])
	if err != nil || c.state != OP_START {
		t.Fatalf("Unexpected: %d : %v\n", c.state, err)
	}
}

func TestMaxControlLine(t *testing.T) {
	for _, test := range []struct {
		name       string
		kind       int
		shouldFail bool
	}{
		{"client", CLIENT, true},
		{"leaf", LEAF, false},
		{"route", ROUTER, false},
		{"gateway", GATEWAY, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			pub := []byte("PUB foo.bar.baz 2\r\nok\r\n")

			setupClient := func() *client {
				c := dummyClient()
				c.setNoReconnect()
				c.flags.set(connectReceived)
				c.kind = test.kind
				switch test.kind {
				case ROUTER:
					c.route = &route{}
				case GATEWAY:
					c.gw = &gateway{outbound: false, connected: true, insim: make(map[string]*insie)}
				}
				c.mcl = 8
				return c
			}

			c := setupClient()
			// First try with a partial:
			// PUB foo.bar.baz 2\r\nok\r\n
			// .............^
			err := c.parse(pub[:14])
			switch test.shouldFail {
			case true:
				if !ErrorIs(err, ErrMaxControlLine) {
					t.Fatalf("Expected an error parsing longer than expected control line")
				}
			case false:
				if err != nil {
					t.Fatalf("Should not have failed, got %v", err)
				}
			}

			// Now with full protocol (no split) and we should still enforce.
			c = setupClient()
			err = c.parse(pub)
			switch test.shouldFail {
			case true:
				if !ErrorIs(err, ErrMaxControlLine) {
					t.Fatalf("Expected an error parsing longer than expected control line")
				}
			case false:
				if err != nil {
					t.Fatalf("Should not have failed, got %v", err)
				}
			}
		})
	}
}

func TestMaxControlLineNonClientUpperBound(t *testing.T) {
	for _, test := range []struct {
		name string
		kind int
	}{
		{"leaf", LEAF},
		{"route", ROUTER},
		{"gateway", GATEWAY},
	} {
		t.Run(test.name, func(t *testing.T) {
			setupClient := func() *client {
				c := dummyClient()
				c.setNoReconnect()
				c.flags.set(connectReceived)
				c.kind = test.kind
				switch test.kind {
				case ROUTER:
					c.route = &route{}
				case GATEWAY:
					c.gw = &gateway{outbound: false, connected: true, insim: make(map[string]*insie)}
				}
				// mcl is the CLIENT default; non-CLIENT uses 16 times that instead
				c.mcl = MAX_CONTROL_LINE_SIZE
				return c
			}

			for _, off := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("%d", off), func(t *testing.T) {
					// Build a PUB arg that exceeds the max control line.
					// Feed it in two chunks so argBuf accumulates across parse calls
					// (replicates the split-buffer trickle-feed exploit path).
					defaultMaxControlLineSize := MAX_CONTROL_LINE_SIZE * 16
					subject := bytes.Repeat([]byte("x"), defaultMaxControlLineSize+off)
					chunk1 := append([]byte("PUB "), subject[:defaultMaxControlLineSize/2]...)
					chunk2 := subject[defaultMaxControlLineSize/2:]

					c := setupClient()
					// First chunk — no error expected yet (argBuf < limit)
					if err := c.parse(chunk1); err != nil {
						t.Fatalf("unexpected error on first chunk: %v", err)
					}
					// Second chunk pushes argBuf over max control line
					err := c.parse(chunk2)
					if off <= 0 && err != nil {
						t.Fatalf("unexpected error on second chunk: %v", err)
					} else if off > 0 && !ErrorIs(err, ErrMaxControlLine) {
						t.Fatalf("expected ErrMaxControlLine after oversized accumulation, got: %v", err)
					}
				})
			}
		})
	}
}

// Capping accepted TCP Reads forces parser boundaries through the production read loop.
type parserIngressReadConn struct {
	net.Conn
	width int
	reads atomic.Int64
}

func (c *parserIngressReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p[:min(len(p), c.width)])
	if n > 0 {
		c.reads.Add(1)
	}
	return n, err
}

type parserIngressWire struct {
	net.Conn
	reader *bufio.Reader
	input  *parserIngressReadConn
}

func parserIngressTCP(t *testing.T, s *Server, kind, width int) *parserIngressWire {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require_NoError(t, err)
	defer listener.Close()
	peer, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require_NoError(t, err)
	t.Cleanup(func() { peer.Close() })
	require_NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
	accepted, err := listener.Accept()
	require_NoError(t, err)
	input := &parserIngressReadConn{Conn: accepted, width: width}
	switch kind {
	case CLIENT:
		require_NotNil(t, s.createClient(input))
	case ROUTER:
		require_NotNil(t, s.createRoute(input, nil, Implicit, gossipDefault, _EMPTY_))
	case LEAF:
		require_NotNil(t, s.createLeafNode(input, nil, nil, nil))
	case GATEWAY:
		s.createGateway(nil, nil, input)
	default:
		t.Fatalf("unsupported ingress kind %d", kind)
	}
	p := &parserIngressWire{Conn: peer, reader: bufio.NewReader(peer), input: input}
	if line := p.line(t); !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("expected initial INFO, got %q", line)
	}
	return p
}

func (p *parserIngressWire) write(t *testing.T, protocol string) {
	t.Helper()
	require_NoError(t, p.SetDeadline(time.Now().Add(5*time.Second)))
	_, err := io.WriteString(p, protocol)
	require_NoError(t, err)
}

func (p *parserIngressWire) line(t *testing.T) string {
	t.Helper()
	line, err := p.reader.ReadString('\n')
	require_NoError(t, err)
	return line
}

func (p *parserIngressWire) pong(t *testing.T) {
	t.Helper()
	for range 100 {
		line := p.line(t)
		switch {
		case line == "PONG\r\n":
			return
		case line == "PING\r\n":
			p.write(t, "PONG\r\n")
		case line == "+OK\r\n":
		case strings.HasPrefix(line, "INFO "), strings.HasPrefix(line, "RS+ "), strings.HasPrefix(line, "LS+ "):
		default:
			t.Fatalf("unexpected control frame %q", line)
		}
	}
	t.Fatal("no PONG within 100 control frames")
}

func (p *parserIngressWire) roundTrip(t *testing.T, protocol string) {
	t.Helper()
	p.roundTripPongs(t, protocol, 1)
}

func (p *parserIngressWire) roundTripPongs(t *testing.T, protocol string, pongs int) {
	t.Helper()
	before := p.input.reads.Load()
	packet := protocol + "PING\r\n"
	p.write(t, packet)
	for range pongs {
		p.pong(t)
	}
	if reads := p.input.reads.Load() - before; reads < int64((len(packet)+p.input.width-1)/p.input.width) {
		t.Fatalf("input was not fragmented: %d reads for %d bytes at width %d", reads, len(packet), p.input.width)
	}
}

func (p *parserIngressWire) message(t *testing.T, subject, sid, reply, header, payload string) {
	t.Helper()
	prefix := "MSG "
	if len(header) > 0 {
		prefix = "HMSG "
	}
	want := prefix + subject + " " + sid + " "
	if reply != "" {
		want += reply + " "
	}
	if len(header) > 0 {
		want += fmt.Sprintf("%d ", len(header))
	}
	want += fmt.Sprintf("%d\r\n", len(header)+len(payload))
	var line string
	for range 100 {
		line = p.line(t)
		if line != "PING\r\n" {
			break
		}
		p.write(t, "PONG\r\n")
	}
	require_Equal(t, line, want)
	body := make([]byte, len(header)+len(payload)+2)
	_, err := io.ReadFull(p.reader, body)
	require_NoError(t, err)
	require_Equal(t, string(body), header+payload+"\r\n")
}

func parserIngressOptions() *Options {
	o := DefaultOptions()
	o.NoSystemAccount = true
	o.Cluster.PoolSize = 1
	o.Cluster.Compression.Mode = CompressionOff
	o.LeafNode.Host, o.LeafNode.Port = "127.0.0.1", -1
	o.LeafNode.Compression.Mode = CompressionOff
	return o
}

func TestParserClientProtocolIngress(t *testing.T) {
	s := RunServer(parserIngressOptions())
	defer s.Shutdown()
	for _, width := range []int{1, 2, 7, 64} {
		t.Run(fmt.Sprintf("read-width-%d", width), func(t *testing.T) {
			p := parserIngressTCP(t, s, CLIENT, width)
			p.roundTrip(t, "CONNECT {\"verbose\":false,\"pedantic\":true,\"tls_required\":false,\"headers\":true}\r\n")
			p.roundTripPongs(t, "PING  \r  \nPONG\r\nPONG  \r  \n+OK\r\n", 2)
			// An incomplete SUB must retain its arguments until the next production Read.
			p.write(t, "SUB > 1\r")
			p.roundTrip(t, "\n")
			for _, test := range []struct {
				arg, subject, reply string
				size                int
				szb                 string
			}{
				{arg: "a 2", subject: "a", reply: "", size: 2, szb: "2"},
				{arg: "a 222", subject: "a", reply: "", size: 222, szb: "222"},
				{arg: "foo 22", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: " foo 22", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "foo 22 ", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "foo   22", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: " foo 22 ", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: " foo   22 ", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "foo bar 22", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: " foo bar 22", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "foo bar 22 ", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "foo  bar  22", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: " foo bar 22 ", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "  foo   bar  22  ", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "  foo   bar  2222  ", subject: "foo", reply: "bar", size: 2222, szb: "2222"},
				{arg: "  foo     2222  ", subject: "foo", reply: "", size: 2222, szb: "2222"},
				{arg: "a\t2", subject: "a", reply: "", size: 2, szb: "2"},
				{arg: "a\t222", subject: "a", reply: "", size: 222, szb: "222"},
				{arg: "foo\t22", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "\tfoo\t22", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "foo\t22\t", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "foo\t\t\t22", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "\tfoo\t22\t", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "\tfoo\t\t\t22\t", subject: "foo", reply: "", size: 22, szb: "22"},
				{arg: "foo\tbar\t22", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "\tfoo\tbar\t22", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "foo\tbar\t22\t", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "foo\t\tbar\t\t22", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "\tfoo\tbar\t22\t", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "\t \tfoo\t \t \tbar\t \t22\t \t", subject: "foo", reply: "bar", size: 22, szb: "22"},
				{arg: "\t\tfoo\t\t\tbar\t\t2222\t\t", subject: "foo", reply: "bar", size: 2222, szb: "2222"},
				{arg: "\t \tfoo\t \t \t\t\t2222\t \t", subject: "foo", reply: "", size: 2222, szb: "2222"},
			} {
				t.Run("PUB/"+test.arg, func(t *testing.T) {
					payload := strings.Repeat("A", test.size)
					p.write(t, "PUB "+test.arg+"\r\n"+payload+"\r\n")
					p.message(t, test.subject, "1", test.reply, "", payload)
					p.roundTrip(t, "")
				})
			}
			for _, test := range []struct {
				arg, subject, reply string
				hdr, size           int
				szb                 string
			}{
				{arg: "a 2 4", subject: "a", reply: "", hdr: 2, size: 4, szb: "4"},
				{arg: "a 22 222", subject: "a", reply: "", hdr: 22, size: 222, szb: "222"},
				{arg: "foo 3 22", subject: "foo", reply: "", hdr: 3, size: 22, szb: "22"},
				{arg: " foo   1 22", subject: "foo", reply: "", hdr: 1, size: 22, szb: "22"},
				{arg: "foo 0   22 ", subject: "foo", reply: "", hdr: 0, size: 22, szb: "22"},
				{arg: "foo  0     22", subject: "foo", reply: "", hdr: 0, size: 22, szb: "22"},
				{arg: " foo 1 22 ", subject: "foo", reply: "", hdr: 1, size: 22, szb: "22"},
				{arg: " foo   3 22 ", subject: "foo", reply: "", hdr: 3, size: 22, szb: "22"},
				{arg: "foo bar 1 22", subject: "foo", reply: "bar", hdr: 1, size: 22, szb: "22"},
				{arg: " foo bar 11 22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "foo bar 11 22 ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "foo  bar  11  22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: " foo bar  11 22 ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "  foo   bar  11   22  ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "  foo   bar  22   2222  ", subject: "foo", reply: "bar", hdr: 22, size: 2222, szb: "2222"},
				{arg: "  foo 1    2222  ", subject: "foo", reply: "", hdr: 1, size: 2222, szb: "2222"},
				{arg: "a\t2\t22", subject: "a", reply: "", hdr: 2, size: 22, szb: "22"},
				{arg: "a\t2\t\t222", subject: "a", reply: "", hdr: 2, size: 222, szb: "222"},
				{arg: "foo\t2 22", subject: "foo", reply: "", hdr: 2, size: 22, szb: "22"},
				{arg: "\tfoo\t11\t  22", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
				{arg: "foo\t11\t22\t", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
				{arg: "foo\t\t\t11 22", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
				{arg: "\tfoo\t11\t \t 22\t", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
				{arg: "\tfoo\t\t\t11 22\t", subject: "foo", reply: "", hdr: 11, size: 22, szb: "22"},
				{arg: "foo\tbar\t2 22", subject: "foo", reply: "bar", hdr: 2, size: 22, szb: "22"},
				{arg: "\tfoo\tbar\t11\t22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "foo\tbar\t11\t\t22\t ", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "foo\t\tbar\t\t11\t\t\t22", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "\tfoo\tbar\t11\t22\t", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "\t \tfoo\t \t \tbar\t \t11\t 22\t \t", subject: "foo", reply: "bar", hdr: 11, size: 22, szb: "22"},
				{arg: "\t\tfoo\t\t\tbar\t\t22\t\t\t2222\t\t", subject: "foo", reply: "bar", hdr: 22, size: 2222, szb: "2222"},
				{arg: "\t \tfoo\t \t \t\t\t11\t\t 2222\t \t", subject: "foo", reply: "", hdr: 11, size: 2222, szb: "2222"},
			} {
				t.Run("HPUB/"+test.arg, func(t *testing.T) {
					header := strings.Repeat("H", test.hdr)
					payload := strings.Repeat("A", test.size-test.hdr)
					p.write(t, "HPUB "+test.arg+"\r\n"+header+payload+"\r\n")
					p.message(t, test.subject, "1", test.reply, header, payload)
					p.roundTrip(t, "")
				})
			}
			for _, reply := range []string{"", "INBOX.22"} {
				arg := ""
				if reply != "" {
					arg = reply + " "
				}
				p.write(t, "HPUB foo "+arg+"12 17\r\nname:derek\r\nHELLO\r")
				p.write(t, "\n")
				p.message(t, "foo", "1", reply, "name:derek\r\n", "HELLO")
				p.roundTrip(t, "")
			}
			p.write(t, "HPUB foo INBOX.22 0 5\r\nHELLO\r\n")
			p.message(t, "foo", "1", "INBOX.22", "", "HELLO")
			p.roundTrip(t, "")
		})
	}
}

func (p *parserIngressWire) rejected(t *testing.T, diagnostic string) {
	t.Helper()
	var output strings.Builder
	for {
		line, err := p.reader.ReadString('\n')
		output.WriteString(line)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				if networkError, ok := errors.AsType[net.Error](err); ok && networkError.Timeout() {
					t.Fatalf("connection remained open after malformed input: %q", output.String())
				}
			}
			break
		}
	}
	if diagnostic != "" && !strings.Contains(output.String(), diagnostic) {
		t.Fatalf("expected diagnostic %q, got %q", diagnostic, output.String())
	}
}

func TestParserMalformedClientIngress(t *testing.T) {
	o := parserIngressOptions()
	o.MaxPayload = 32768
	s := RunServer(o)
	defer s.Shutdown()
	healthy := parserIngressTCP(t, s, CLIENT, 7)
	healthy.roundTrip(t, "CONNECT {\"verbose\":false}\r\nSUB sentinel 1\r\n")
	protocols := []string{

		"xxx",
		"Px", "PIx", "PINx", " PING",
		"POx", "PONx",
		"+x", "+Ox",
		"-x", "-Ex", "-ERx", "-ERRx",
		"Cx", "COx", "CONx", "CONNx", "CONNEx", "CONNECx", "CONNECx", "CONNECT \r\n",
		"PUx", "PUB foo\r\n", "PUB  \r\n", "PUB foo bar       \r\n",
		"PUB foo 2\r\nok \r\n", "PUB foo 2\r\nok\r \n",
		"Sx", "SUx", "SUB\r\n", "SUB  \r\n", "SUB foo\r\n",
		"SUB foo bar baz 22\r\n",
		"Ux", "UNx", "UNSx", "UNSUx", "UNSUBx", "UNSUBUNSUB 1\r\n", "UNSUB_2\r\n",
		"UNSUB_UNSUB_UNSUB 2\r\n", "UNSUB_\t2\r\n", "UNSUB\r\n", "UNSUB \r\n",
		"UNSUB          \t       \r\n",
		"Ix", "INx", "INFx", "INFO  \r\n",
		"PUB foo 3333333333333333333333333333333333333333333333333333333333333333\r\n",
		"PUB foo 2222222222222222\r\n",
		"PUB foo 32769\r\n",
		"HPUB foo 10 8\r\n",
		"M",
	}
	for _, width := range []int{1, 7, 64} {
		for i, protocol := range protocols {
			t.Run(fmt.Sprintf("width-%d/case-%d", width, i), func(t *testing.T) {
				p := parserIngressTCP(t, s, CLIENT, width)
				p.roundTrip(t, "CONNECT {\"verbose\":false,\"headers\":true}\r\n")
				p.write(t, protocol)
				p.rejected(t, "")
				healthy.write(t, "PUB sentinel 2\r\nok\r\n")
				healthy.message(t, "sentinel", "1", "", "", "ok")
				healthy.roundTrip(t, "")
			})
		}
	}
	// The configured limit itself is accepted; rejection above cannot be only overflow.
	p := parserIngressTCP(t, s, CLIENT, 64)
	p.roundTrip(t, "CONNECT {\"verbose\":false}\r\nSUB boundary 1\r\n")
	payload := strings.Repeat("A", 32768)
	p.write(t, "PUB boundary 32768\r\n"+payload+"\r\n")
	p.message(t, "boundary", "1", "", "", payload)
	p.roundTrip(t, "")
}

func parserIngressPeerConnect(t *testing.T, p *parserIngressWire, s *Server, kind int) {
	t.Helper()
	name := "PARSER_" + t.Name() + "_" + p.LocalAddr().String()
	connect := fmt.Sprintf("CONNECT {\"name\":%q,\"cluster\":%q,\"headers\":true,\"user\":\"peer\",\"pass\":\"pwd\"}\r\n", name, s.ClusterName())
	switch kind {
	case ROUTER:
		info, err := json.Marshal(Info{ID: name, Name: name, Cluster: s.ClusterName(), Headers: true, RoutePoolSize: 1, Proto: RouteProtoV2})
		require_NoError(t, err)
		p.roundTrip(t, connect+"INFO "+string(info)+"\r\n")
	case LEAF:
		p.roundTrip(t, fmt.Sprintf("CONNECT {\"name\":%q,\"headers\":true,\"user\":\"peer\",\"pass\":\"pwd\"}\r\n", name))
	case GATEWAY:
		info, err := json.Marshal(Info{ID: name, Name: name, Gateway: "parser-remote", Headers: true})
		require_NoError(t, err)
		p.roundTrip(t, fmt.Sprintf("CONNECT {\"name\":%q,\"gateway\":\"parser-remote\",\"user\":\"peer\",\"pass\":\"pwd\"}\r\nINFO %s\r\n", name, info))
	default:
		t.Fatalf("unsupported peer kind %d", kind)
	}
}

func TestParserRouteProtocolIngress(t *testing.T) {
	for _, width := range []int{1, 7, 64} {
		t.Run(fmt.Sprintf("read-width-%d", width), func(t *testing.T) {
			a, b := NewAccount("A"), NewAccount("B")
			o := parserIngressOptions()
			o.Accounts = []*Account{a, b}
			o.Users = []*User{{Username: "a", Password: "pwd", Account: a}, {Username: "b", Password: "pwd", Account: b}}
			s := RunServer(o)
			defer s.Shutdown()
			subscriber := func(user, subscription string) *parserIngressWire {
				p := parserIngressTCP(t, s, CLIENT, 7)
				p.roundTrip(t, fmt.Sprintf("CONNECT {\"verbose\":false,\"headers\":true,\"user\":%q,\"pass\":\"pwd\"}\r\nSUB foo %s\r\n", user, subscription))
				return p
			}
			plain := subscriber("a", "1")
			queues := []*parserIngressWire{subscriber("a", "queue1 1"), subscriber("a", "queue2 1")}
			other := subscriber("b", "1")
			peer := parserIngressTCP(t, s, ROUTER, width)
			parserIngressPeerConnect(t, peer, s, ROUTER)
			checkNumRoutes(t, s, 1)
			for _, header := range []string{"", "XXX"} {
				for _, form := range []struct {
					args, reply string
					queued      bool
				}{
					{"", "", false}, {" INBOX.22", "INBOX.22", false},
					{" + reply queue1 queue2", "reply", true}, {" | queue1 queue2", "", true},
				} {
					op, size := "RMSG", "11"
					if header != "" {
						op, size = "HMSG", "3 14"
					}
					peer.roundTrip(t, op+" A foo"+form.args+" "+size+"\r\n"+header+"hello world\r\n")
					plain.message(t, "foo", "1", form.reply, header, "hello world")
					for _, q := range queues {
						if form.queued {
							q.message(t, "foo", "1", form.reply, header, "hello world")
						}
						q.roundTrip(t, "")
					}
					other.roundTrip(t, "")
				}
			}
			peer.write(t, "HMSG A foo 10 8\r\n")
			peer.rejected(t, "")
			checkNumRoutes(t, s, 0)
			for _, invalid := range []string{"Mx", "MSx", "MSGx", "MSG  \r\n", "MSG \r\n", "MSG A foo 5\r\nhello\r\n"} {
				bad := parserIngressTCP(t, s, ROUTER, width)
				parserIngressPeerConnect(t, bad, s, ROUTER)
				bad.write(t, invalid)
				bad.rejected(t, "")
			}
			plain.roundTrip(t, "")
		})
	}
}

func TestParserLeafPayloadBoundaryIngress(t *testing.T) {
	for _, width := range []int{1, 7, 64} {
		for _, header := range []string{"", "HEAD"} {
			t.Run(fmt.Sprintf("read-width-%d/header-%d", width, len(header)), func(t *testing.T) {
				a := NewAccount("A")
				o := parserIngressOptions()
				o.MaxPayload = 16
				o.Accounts = []*Account{a}
				o.Users = []*User{{Username: "a", Password: "pwd", Account: a}}
				o.LeafNode.Users = []*User{{Username: "peer", Password: "pwd", Account: a}}
				s := RunServer(o)
				defer s.Shutdown()
				receiver := parserIngressTCP(t, s, CLIENT, 7)
				receiver.roundTrip(t, "CONNECT {\"verbose\":false,\"headers\":true,\"user\":\"a\",\"pass\":\"pwd\"}\r\nSUB foo 1\r\n")
				peer := parserIngressTCP(t, s, LEAF, width)
				parserIngressPeerConnect(t, peer, s, LEAF)
				checkLeafNodeConnected(t, s)
				op, size := "LMSG", "16"
				if header != "" {
					op, size = "HMSG", "4 16"
				}
				payload := strings.Repeat("A", 16-len(header))
				peer.roundTrip(t, op+" foo "+size+"\r\n"+header+payload+"\r\n")
				receiver.message(t, "foo", "1", "", header, payload)
				if header != "" {
					size = "4 17"
				} else {
					size = "17"
				}
				peer.write(t, op+" foo "+size+"\r\n")
				peer.rejected(t, "Maximum Payload Violation")
				checkLeafNodeConnectedCount(t, s, 0)
				receiver.roundTrip(t, "")
			})
		}
	}
}

func TestParserPreConnectAuthenticationIngress(t *testing.T) {
	for _, restriction := range []string{"unrestricted", "websocket-only", "proxy-required"} {
		t.Run(restriction, func(t *testing.T) {
			o := parserIngressOptions()
			o.Websocket = testWSOptions().Websocket
			o.NoAuthUser = "foo"
			user := &User{Username: "foo", Password: "pwd"}
			if restriction == "websocket-only" {
				user.AllowedConnectionTypes = map[string]struct{}{jwt.ConnectionTypeWebsocket: {}}
			}
			if restriction == "proxy-required" {
				user.ProxyRequired = true
			}
			o.Users = []*User{user}
			o.Cluster.Username, o.Cluster.Password = "peer", "pwd"
			o.LeafNode.Username, o.LeafNode.Password = "peer", "pwd"
			o.Gateway.Name, o.Gateway.Host, o.Gateway.Port = "parser-local", "127.0.0.1", -1
			o.Gateway.Username, o.Gateway.Password = "peer", "pwd"
			o.SystemAccount = "SYS"
			o.Accounts = []*Account{NewAccount(o.SystemAccount)}
			s := RunServer(o)
			defer s.Shutdown()
			t.Run("TCP", func(t *testing.T) {
				p := parserIngressTCP(t, s, CLIENT, 1)
				if restriction != "unrestricted" {
					p.write(t, "PING\r\n")
					p.rejected(t, "Authorization Violation")
					return
				}
				p.roundTrip(t, "")
				p.roundTrip(t, "SUB marker 1\r\n")
				p.write(t, "PUB marker 2\r\nok\r\n")
				p.message(t, "marker", "1", "", "", "ok")
				p.roundTrip(t, "")
			})
			t.Run("WebSocket", func(t *testing.T) {
				conn, reader, _ := testWSCreateClientGetInfo(t, false, false, o.Websocket.Host, o.Websocket.Port)
				defer conn.Close()
				require_NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
				send := func(protocol string) {
					t.Helper()
					_, err := conn.Write(testWSCreateClientMsg(wsBinaryMessage, 1, true, false, []byte(protocol)))
					require_NoError(t, err)
				}
				send("PING\r\n")
				frame := testWSReadFrame(t, reader)
				if restriction == "proxy-required" {
					require_True(t, bytes.Contains(frame, []byte("Authorization Violation")))
					return
				}
				require_Equal(t, string(frame), "PONG\r\n")
				send("SUB marker 1\r\nPUB marker 2\r\nok\r\nPING\r\n")
				var received []byte
				for range 10 {
					received = append(received, testWSReadFrame(t, reader)...)
					if bytes.Contains(received, []byte("PONG\r\n")) {
						break
					}
				}
				require_Equal(t, string(received), "MSG marker 1 2\r\nok\r\nPONG\r\n")
			})
			for _, kind := range []int{LEAF, ROUTER, GATEWAY} {
				t.Run(fmt.Sprintf("peer-%d", kind), func(t *testing.T) {
					pending := parserIngressTCP(t, s, kind, 1)
					pending.write(t, "PING\r\n")
					pending.rejected(t, "Authorization Violation")
					established := parserIngressTCP(t, s, kind, 1)
					parserIngressPeerConnect(t, established, s, kind)
					established.roundTrip(t, "")
				})
			}
		})
	}
}

func TestParserPongKeepsConnectionAliveIngress(t *testing.T) {
	o := parserIngressOptions()
	o.DisableShortFirstPing = true
	o.PingInterval = 50 * time.Millisecond
	o.MaxPingsOut = 2
	s := RunServer(o)
	defer s.Shutdown()
	for _, width := range []int{1, 7} {
		t.Run(fmt.Sprintf("read-width-%d", width), func(t *testing.T) {
			p := parserIngressTCP(t, s, CLIENT, width)
			p.roundTrip(t, "CONNECT {\"verbose\":false}\r\n")
			for range 5 {
				require_Equal(t, p.line(t), "PING\r\n")
				p.write(t, "PONG  \r  \n")
			}
			p.roundTrip(t, "SUB marker 1\r\n")
			p.write(t, "PUB marker 2\r\nok\r\n")
			p.message(t, "marker", "1", "", "", "ok")
			p.roundTrip(t, "")
		})
	}
}

func TestParserMalformedDiagnosticIngress(t *testing.T) {
	s := RunServer(parserIngressOptions())
	defer s.Shutdown()
	logger := &captureErrorLogger{errCh: make(chan string, 8)}
	s.SetLogger(logger, false, false)
	for _, width := range []int{1, 64} {
		t.Run(fmt.Sprintf("read-width-%d", width), func(t *testing.T) {
			p := parserIngressTCP(t, s, CLIENT, width)
			p.roundTrip(t, "CONNECT {\"verbose\":false}\r\n")
			p.write(t, "xabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			p.rejected(t, "Unknown Protocol Operation")
			select {
			case log := <-logger.errCh:
				require_True(t, strings.Contains(log, "parser ERROR"))
				_, snippet, ok := strings.Cut(log, "proto='")
				require_True(t, ok)
				snippet, _, ok = strings.Cut(snippet, "...'")
				require_True(t, ok)
				decoded, err := strconv.Unquote(snippet)
				require_NoError(t, err)
				require_True(t, len(decoded) <= PROTO_SNIPPET_SIZE)
				if width == 1 {
					require_Equal(t, decoded, "")
				}
			case <-time.After(time.Second):
				t.Fatal("missing production parser diagnostic")
			}
		})
	}
}

// Compact handshakes fit the non-client 16x bound even with an 8-byte client limit.
func parserIngressCompactConnect(t *testing.T, p *parserIngressWire, kind int) {
	t.Helper()
	switch kind {
	case CLIENT, LEAF:
		p.roundTrip(t, "CONNECT {}\r\n")
	case ROUTER:
		p.roundTrip(t, "CONNECT {\"name\":\"P\",\"cluster\":\"abc\"}\r\nINFO {\"server_id\":\"P\",\"cluster\":\"abc\",\"route_pool_size\":1}\r\n")
	case GATEWAY:
		p.roundTrip(t, "CONNECT {\"name\":\"P\",\"gateway\":\"remote\"}\r\nINFO {\"server_id\":\"P\",\"gateway\":\"remote\"}\r\n")
	}
}

func TestParserControlLineIngress(t *testing.T) {
	for _, kind := range []int{CLIENT, LEAF, ROUTER, GATEWAY} {
		for _, width := range []int{1, 64} {
			t.Run(fmt.Sprintf("kind-%d/read-width-%d", kind, width), func(t *testing.T) {
				o := parserIngressOptions()
				o.MaxControlLine = 8
				o.Gateway.Name, o.Gateway.Host, o.Gateway.Port = "local", "127.0.0.1", -1
				o.SystemAccount = "SYS"
				o.Accounts = []*Account{NewAccount(o.SystemAccount)}
				s := RunServer(o)
				defer s.Shutdown()
				receiver := parserIngressTCP(t, s, CLIENT, 1)
				parserIngressCompactConnect(t, receiver, CLIENT)
				receiver.roundTrip(t, "SUB > 1\r\n")
				peer := parserIngressTCP(t, s, kind, width)
				parserIngressCompactConnect(t, peer, kind)
				protocol := "PUB foo.bar.baz 2\r\nok\r\n"
				switch kind {
				case LEAF:
					protocol = "LMSG foo.bar.baz 2\r\nok\r\n"
				case ROUTER, GATEWAY:
					protocol = "RMSG $G foo.bar.baz 2\r\nok\r\n"
				}
				if kind == CLIENT {
					peer.write(t, protocol)
					peer.rejected(t, ErrMaxControlLine.Error())
				} else {
					peer.roundTrip(t, protocol)
					receiver.message(t, "foo.bar.baz", "1", "", "", "ok")
				}
				receiver.roundTrip(t, "")
			})
		}
	}
}

func TestParserPeerControlLineBoundaryIngress(t *testing.T) {
	for _, kind := range []int{LEAF, ROUTER, GATEWAY} {
		for _, width := range []int{7, 64} {
			for _, offset := range []int{-1, 0, 1} {
				t.Run(fmt.Sprintf("kind-%d/read-width-%d/offset-%d", kind, width, offset), func(t *testing.T) {
					o := parserIngressOptions()
					o.MaxControlLine = MAX_CONTROL_LINE_SIZE
					o.Gateway.Name, o.Gateway.Host, o.Gateway.Port = "local", "127.0.0.1", -1
					o.SystemAccount = "SYS"
					o.Accounts = []*Account{NewAccount(o.SystemAccount)}
					s := RunServer(o)
					defer s.Shutdown()
					receiver := parserIngressTCP(t, s, CLIENT, 7)
					receiver.roundTrip(t, "CONNECT {\"verbose\":false}\r\nSUB > 1\r\n")
					peer := parserIngressTCP(t, s, kind, width)
					parserIngressCompactConnect(t, peer, kind)
					op, account := "LMSG ", ""
					if kind != LEAF {
						op, account = "RMSG ", "$G "
					}
					subject := strings.Repeat("x", MAX_CONTROL_LINE_SIZE*16+offset-len(account)-len(" 2"))
					args := account + subject + " 2"
					if offset > 0 {
						// No newline: rejection must happen while production Reads accumulate args.
						peer.write(t, op+args)
						peer.rejected(t, ErrMaxControlLine.Error())
					} else {
						peer.roundTrip(t, op+args+"\r\nok\r\n")
						receiver.message(t, subject, "1", "", "", "ok")
					}
					receiver.roundTrip(t, "")
				})
			}
		}
	}
}
