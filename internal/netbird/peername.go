package netbird

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	imdsAddress  = "169.254.169.254:80"
	imdsVNICsURL = "http://169.254.169.254/opc/v2/vnics/"
	imdsTimeout  = 5 * time.Second
	maxVNICBytes = 64 << 10
)

// peerName returns the name NetBird registers a new peer under. Cell slots
// have fixed private IPs, so the configured map gives every revision of a slot
// the same name. NetBird keeps a peer's name after registration; renaming an
// existing peer is a manager operation.
func (e enroller) peerName(ctx context.Context, cfg Config) (string, error) {
	if len(cfg.PeerNames) > 0 {
		ip, err := e.primaryIP(ctx)
		if err != nil {
			return "", errors.New("cannot read the server's primary private IPv4 address from OCI instance metadata")
		}
		if name, ok := cfg.PeerNames[ip.String()]; ok {
			return name, nil
		}
	}
	hostname, err := e.hostname()
	if err != nil || hostname == "" || len(hostname) > 253 || strings.ContainsAny(hostname, "\x00\r\n\t ") {
		return "", errors.New("cannot determine a valid server hostname for NetBird")
	}
	return hostname, nil
}

// readPrimaryPrivateIP reads the primary VNIC's private IPv4 address from OCI
// IMDSv2. OCI lists the primary VNIC first. The transport dials only the
// link-local endpoint and ignores proxies and redirects.
func readPrimaryPrivateIP(ctx context.Context) (netip.Addr, error) {
	dialer := &net.Dialer{Timeout: imdsTimeout}
	client := &http.Client{
		Timeout: imdsTimeout,
		Transport: &http.Transport{
			Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: imdsTimeout,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" {
					return nil, errors.New("unexpected OCI IMDS network")
				}
				return dialer.DialContext(ctx, "tcp4", imdsAddress)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return primaryPrivateIP(ctx, client)
}

func primaryPrivateIP(ctx context.Context, client *http.Client) (netip.Addr, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsVNICsURL, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maxVNICBytes {
		return netip.Addr{}, errors.New("OCI IMDS VNIC response is invalid or too large")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxVNICBytes+1))
	if err != nil || len(wire) > maxVNICBytes {
		return netip.Addr{}, errors.New("OCI IMDS VNIC response is unreadable or too large")
	}
	var vnics []struct {
		PrivateIP string `json:"privateIp"`
	}
	if json.Unmarshal(wire, &vnics) != nil || len(vnics) == 0 {
		return netip.Addr{}, errors.New("OCI IMDS returned no VNICs")
	}
	ip, err := netip.ParseAddr(vnics[0].PrivateIP)
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		return netip.Addr{}, errors.New("OCI IMDS primary VNIC has no private IPv4 address")
	}
	return ip, nil
}
