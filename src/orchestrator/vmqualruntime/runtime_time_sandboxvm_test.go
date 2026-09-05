//go:build sandboxvm && linux

package vmqualruntime

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
	reply := qualificationNTPReply(request, receive, transmit, 2*time.Millisecond, 0)
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
		if reply := qualificationNTPReply(mutate(bytes.Clone(request)), receive, transmit, 0, 0); reply != nil {
			t.Fatal("malformed or unsupported request accepted")
		}
	}
}

func TestQualificationNTPAdvertisesFullHostUncertaintyAndLeap(t *testing.T) {
	request := make([]byte, 48)
	request[0] = 4<<3 | 3
	now := time.Date(2026, 9, 4, 12, 30, 0, 0, time.UTC)
	putNTPTime(request[40:], now)
	for _, uncertainty := range []time.Duration{631500 * time.Microsecond, 748500 * time.Microsecond, 16 * time.Second, time.Nanosecond} {
		for leap := uint8(0); leap <= 2; leap++ {
			reply := qualificationNTPReply(request, now, now, uncertainty, leap)
			if len(reply) != 48 || reply[0]>>6 != leap {
				t.Fatalf("missing truthful leap/response: %x", reply)
			}
			encoded := binary.BigEndian.Uint32(reply[8:12])
			if uint64(encoded)*uint64(time.Second) < uint64(uncertainty)*65536 || uint64(encoded-1)*uint64(time.Second) >= uint64(uncertainty)*65536 {
				t.Fatalf("dispersion %d does not round up observed %s", encoded, uncertainty)
			}
		}
	}
	for _, invalid := range []time.Duration{-1, 65536 * time.Second} {
		if reply := qualificationNTPReply(request, now, now, invalid, 0); reply != nil {
			t.Fatal("unrepresentable uncertainty accepted")
		}
	}
	if reply := qualificationNTPReply(request, now, now, 0, 3); reply != nil {
		t.Fatal("unsynchronized leap alarm accepted")
	}
}
