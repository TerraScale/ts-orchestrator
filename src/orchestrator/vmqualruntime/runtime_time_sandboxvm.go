//go:build sandboxvm && linux

package vmqualruntime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// qualificationTimeService exports the synchronized host clock exclusively to
// the estate's declared uplinks. It never contacts an upstream server itself.
type qualificationTimeService struct {
	conn *net.UDPConn
	done chan struct{}
	once sync.Once
}

func startQualificationTimeService(plan vmnet.NetworkPlan) (*qualificationTimeService, error) {
	listener, ok := plan.Listener("ntp")
	if !ok || listener.Protocol != vmnet.UDP || listener.Port != 18123 {
		return nil, errors.New("vmqual: missing bounded NTP endpoint")
	}
	address, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(listener.Address, strconv.Itoa(int(listener.Port))))
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", address)
	if err != nil {
		return nil, fmt.Errorf("vmqual: bind NTP listener: %w", err)
	}
	allowed := make(map[netip.Addr]bool)
	for _, uplink := range plan.Uplinks {
		addr, err := netip.ParseAddr(uplink.RegionAddress)
		if err != nil {
			conn.Close()
			return nil, err
		}
		allowed[addr] = true
	}
	service := &qualificationTimeService{conn: conn, done: make(chan struct{})}
	go service.serve(allowed)
	return service, nil
}

func (service *qualificationTimeService) serve(allowed map[netip.Addr]bool) {
	defer close(service.done)
	// One fixed buffer and no per-datagram goroutines bound resource use.
	packet := make([]byte, 512)
	last := make(map[netip.Addr]time.Time)
	for {
		n, peer, err := service.conn.ReadFromUDPAddrPort(packet)
		if err != nil {
			return
		}
		received := time.Now()
		if !allowed[peer.Addr()] || received.Sub(last[peer.Addr()]) < 10*time.Millisecond {
			continue
		}
		last[peer.Addr()] = received
		clock, clockErr := vmqual.SynchronizedHostTime()
		if clockErr != nil {
			continue
		} // A stale or unsynchronized host never advertises valid time.
		reply := qualificationNTPReply(packet[:n], received, time.Now(), clock.MaximumError, clock.LeapIndicator)
		if reply != nil {
			_ = service.conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = service.conn.WriteToUDPAddrPort(reply, peer)
		}
	}
}

func (service *qualificationTimeService) Close() error {
	if service == nil {
		return nil
	}
	var err error
	service.once.Do(func() { err = service.conn.Close(); <-service.done })
	return err
}

func qualificationNTPReply(request []byte, received, transmitted time.Time, uncertainty time.Duration, leapIndicator uint8) []byte {
	if uncertainty < 0 || uncertainty >= 65536*time.Second || leapIndicator > 2 {
		return nil
	}
	if len(request) != 48 || request[0]&7 != 3 || (request[0]>>3)&7 < 3 || (request[0]>>3)&7 > 4 || binary.BigEndian.Uint64(request[40:48]) == 0 {
		return nil
	}
	reply := make([]byte, 48)
	reply[0] = leapIndicator<<6 | request[0]&0x38 | 4
	// The kernel exposes synchronization and error, not upstream stratum.
	// Reserve the last usable stratum for the guest; this qualification
	// reference is the disciplined host, not a measured upstream NTP chain.
	reply[1], reply[2], reply[3] = 14, 4, 236
	// Round upward to NTP unsigned 16.16 units; never advertise less than
	// the observed kernel uncertainty. Chrony applies its source-selection limits.
	dispersion := (uint64(uncertainty)*65536 + uint64(time.Second) - 1) / uint64(time.Second)
	if dispersion > uint64(^uint32(0)) {
		return nil
	}
	binary.BigEndian.PutUint32(reply[8:12], uint32(dispersion))
	// No upstream address is known, so leave the reference identifier unset.
	putNTPTime(reply[16:24], received)
	copy(reply[24:32], request[40:48])
	putNTPTime(reply[32:40], received)
	putNTPTime(reply[40:48], transmitted)
	return reply
}

func putNTPTime(dst []byte, instant time.Time) {
	binary.BigEndian.PutUint32(dst[:4], uint32(instant.Unix()+2208988800))
	binary.BigEndian.PutUint32(dst[4:8], uint32(uint64(instant.Nanosecond())*(1<<32)/1000000000))
}
