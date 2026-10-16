package natscell

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// operatorForwarding selects only explicitly forwarded controller URLs while
// retaining their original IP addresses as TLS identities.
func operatorForwarding(cfg Config) (string, map[string]string, error) {
	if cfg.ClientRole != "operator" || cfg.Embedded != nil || len(cfg.OperatorForward) > 5 {
		return "", nil, errors.New("NATS forwarding requires an external production operator")
	}
	configured := make(map[string]struct{})
	selected := make([]string, 0, len(cfg.OperatorForward))
	for _, raw := range strings.Split(cfg.URL, ",") {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Scheme != "tls" || parsed.User != nil || parsed.Path != "" ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
			return "", nil, errors.New("forwarded operator requires exact controller TLS URLs")
		}
		address := parsed.Host
		host, port, err := net.SplitHostPort(address)
		ip, ipErr := netip.ParseAddr(host)
		if err != nil || ipErr != nil || !ip.Is4() || !ip.IsPrivate() ||
			port != "4222" || address != net.JoinHostPort(ip.String(), port) {
			return "", nil, errors.New("forwarded controller URL is not a canonical private IPv4 endpoint on port 4222")
		}
		if _, exists := configured[address]; exists {
			return "", nil, errors.New("forwarded controller URL repeats")
		}
		configured[address] = struct{}{}
		if _, mapped := cfg.OperatorForward[address]; mapped {
			selected = append(selected, "tls://"+address)
		}
	}
	if len(selected) == 0 {
		return "", nil, errors.New("no configured controller has an operator forward")
	}
	forward := make(map[string]string, len(cfg.OperatorForward))
	for original, destination := range cfg.OperatorForward {
		if _, exists := configured[original]; !exists {
			return "", nil, fmt.Errorf("operator forward target %q is not a configured controller", original)
		}
		host, port, err := net.SplitHostPort(destination)
		ip, ipErr := netip.ParseAddr(host)
		number, numberErr := strconv.Atoi(port)
		if err != nil || ipErr != nil || !ip.IsLoopback() || numberErr != nil || number < 1 || number > 65535 ||
			destination != net.JoinHostPort(ip.String(), strconv.Itoa(number)) {
			return "", nil, errors.New("operator forward destination must be a canonical loopback IP and port")
		}
		forward[original] = destination
	}
	return strings.Join(selected, ","), forward, nil
}
