package region

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestNetBirdManagerRulesPermitDynamicPeerUDP(t *testing.T) {
	ingress, egress := netBirdManagerRules()
	stun, peerUDP := 0, 0
	for _, rule := range ingress {
		if rule.IsStateless == nil || *rule.IsStateless || value(rule.Source) != "0.0.0.0/0" || rule.SourceType != core.IngressSecurityRuleSourceTypeCidrBlock {
			t.Fatalf("manager ingress must retain its stateful public source: %+v", rule)
		}
		switch value(rule.Protocol) {
		case "6":
			if rule.TcpOptions == nil || rule.TcpOptions.DestinationPortRange == nil {
				t.Fatal("manager TCP ingress requires a fixed port")
			}
			ports := rule.TcpOptions.DestinationPortRange
			if value(ports.Min) != value(ports.Max) || value(ports.Min) != 80 && value(ports.Min) != 443 {
				t.Fatalf("unexpected public TCP ingress: %+v", ports)
			}
		case "17":
			if rule.UdpOptions == nil || rule.UdpOptions.DestinationPortRange == nil || value(rule.UdpOptions.DestinationPortRange.Min) != 3478 || value(rule.UdpOptions.DestinationPortRange.Max) != 3478 {
				t.Fatal("unsolicited UDP ingress must remain fixed to STUN")
			}
			stun++
		default:
			t.Fatalf("unexpected ingress protocol: %s", value(rule.Protocol))
		}
	}
	for _, rule := range egress {
		if value(rule.Destination) != "0.0.0.0/0" {
			continue
		}
		if rule.IsStateless == nil || *rule.IsStateless || rule.DestinationType != core.EgressSecurityRuleDestinationTypeCidrBlock {
			t.Fatal("Internet egress must admit only stateful responses")
		}
		switch value(rule.Protocol) {
		case "17":
			if rule.UdpOptions != nil || rule.TcpOptions != nil {
				t.Fatal("peer UDP must reach dynamic source and destination ports")
			}
			peerUDP++
		case "6":
			if rule.TcpOptions == nil || rule.TcpOptions.DestinationPortRange == nil || value(rule.TcpOptions.DestinationPortRange.Min) != 443 || value(rule.TcpOptions.DestinationPortRange.Max) != 443 {
				t.Fatal("Internet TCP egress must remain fixed to HTTPS")
			}
		default:
			t.Fatalf("unexpected egress protocol: %s", value(rule.Protocol))
		}
	}
	if stun != 1 || peerUDP != 1 {
		t.Fatalf("STUN ingress=%d dynamic peer UDP egress=%d, want one each", stun, peerUDP)
	}
}
