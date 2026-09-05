//go:build sandboxvm && linux

package vmqual

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestQualificationNTPReply(t *testing.T) {
	request := make([]byte, 48)
	request[0] = 4<<3 | 3
	sent := time.Date(2026, 9, 4, 12, 30, 0, 123000000, time.UTC)
	putNTPTime(request[40:48], sent)
	receive := sent.Add(time.Millisecond)
	transmit := receive.Add(time.Microsecond)
	reply := qualificationNTPReply(request, receive, transmit, 2*time.Millisecond)
	if len(reply) != 48 || reply[0] != 4<<3|4 || reply[1] != 14 || !bytes.Equal(reply[24:32], request[40:48]) {
		t.Fatalf("invalid reply: %x", reply)
	}
	if binary.BigEndian.Uint32(reply[40:44]) != uint32(transmit.Unix()+2208988800) || binary.BigEndian.Uint32(reply[8:12]) == 0 {
		t.Fatalf("missing time or uncertainty: %x", reply)
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:47] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { b[0] = 4<<3 | 6; return b },
		func(b []byte) []byte { b[0] = 2<<3 | 3; return b },
		func(b []byte) []byte { clear(b[40:]); return b },
	} {
		if reply := qualificationNTPReply(mutate(bytes.Clone(request)), receive, transmit, 0); reply != nil {
			t.Fatal("malformed or unsupported request accepted")
		}
	}
}
