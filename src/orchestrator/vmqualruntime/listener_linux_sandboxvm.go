//go:build sandboxvm && linux

package vmqualruntime

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Observe bound sockets instead of dialing. UDP has no handshake, and a TCP
// timeout cannot prove that a listener has released its owned address.
func kernelListenerExists(ctx context.Context, address string) (bool, error) {
	target, err := netip.ParseAddrPort(address)
	if err != nil || !target.Addr().Is4() || target.Port() == 0 {
		return false, errors.New("cleanup listener requires a concrete IPv4 address and port")
	}
	for _, protocol := range []string{"tcp", "udp"} {
		file, err := os.Open("/proc/net/" + protocol)
		if err != nil {
			return false, err
		}
		exists, inspectErr := scanKernelListeners(ctx, file, target, protocol)
		closeErr := file.Close()
		if err := errors.Join(inspectErr, closeErr); err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

func scanKernelListeners(ctx context.Context, reader io.Reader, target netip.AddrPort, protocol string) (bool, error) {
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "local_address") {
		return false, errors.New("cleanup socket table has no recognized header")
	}
	for rows := 0; scanner.Scan(); rows++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if rows >= 65536 {
			return false, errors.New("cleanup socket table exceeds observation bound")
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			return false, errors.New("cleanup socket table row is incomplete")
		}
		if protocol == "tcp" && fields[3] != "0A" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 || len(parts[0]) != 8 || len(parts[1]) != 4 {
			return false, errors.New("cleanup socket table address is invalid")
		}
		ip, ipErr := strconv.ParseUint(parts[0], 16, 32)
		port, portErr := strconv.ParseUint(parts[1], 16, 16)
		if err := errors.Join(ipErr, portErr); err != nil {
			return false, fmt.Errorf("cleanup socket table address: %w", err)
		}
		var octets [4]byte
		binary.NativeEndian.PutUint32(octets[:], uint32(ip))
		local := netip.AddrFrom4(octets)
		if uint16(port) == target.Port() && (local == target.Addr() || local.IsUnspecified()) {
			return true, nil
		}
	}
	return false, scanner.Err()
}
