package geodns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Run implements `ts-orch edge geodns --plan`. It reads DNS and creates nothing.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "geodns" {
		return errors.New("usage: ts-orch edge geodns --plan")
	}
	if !slices.Equal(args[1:], []string{"--plan"}) {
		return errors.New("edge geodns: only --plan exists; the live apply waits for the Q-GEODNS decision")
	}
	var regions []Region
	for _, name := range mesh.Regions() {
		entry, _ := catalog.LookupName(name)
		host := name + "." + mesh.Domain
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("edge geodns: resolve %s: %w", host, err)
		}
		regions = append(regions, Region{Name: name, IP: ips[0].String(), Latitude: entry.Latitude, Longitude: entry.Longitude})
	}
	plans := Build(regions, Hosts)
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(map[string]any{"zone": Zone, "hosts": plans}); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("\nREGION  EDGE IP\n")
	for _, r := range regions {
		fmt.Fprintf(&b, "%-7s %s\n", r.Name, r.IP)
	}
	b.WriteString("\nGEO AREA               FIRST CHOICE\n")
	for _, a := range areas {
		fmt.Fprintf(&b, "%-22s %s\n", a.Name, plans[0].Nearest[a.Name])
	}
	fmt.Fprintf(&b, "no geo match           %s\n", regions[0].Name)
	b.WriteString("\nOCI DNS (would create, nothing created):\n")
	fmt.Fprintf(&b, "  zone %s (PRIMARY)\n", Zone)
	for _, p := range plans {
		fmt.Fprintf(&b, "  monitor %s HTTPS GET /readyz Host=%s every 30s on %d targets\n", p.Monitor.DisplayName, p.Host, len(p.Monitor.Targets))
		fmt.Fprintf(&b, "  policy %s ROUTE_BY_GEO FILTER>HEALTH>PRIORITY>LIMIT 1, attached at %s\n", p.Policy.DisplayName, p.Attachment.DomainName)
	}
	b.WriteString("\nCloudflare terrascale.tech (would change, nothing changed):\n")
	fmt.Fprintf(&b, "  NS %s -> each OCI nameserver of the new zone (DNS only)\n", Zone)
	for _, p := range plans {
		fmt.Fprintf(&b, "  CNAME %s -> %s (DNS only, replaces the current record)\n", p.Host, p.Attachment.DomainName)
	}
	b.WriteString("\nPrerequisite before the switch: every region needs certificates for " + strings.Join(Hosts, ", ") +
		". HTTP-01 challenges then land on any region, so the edge must forward unknown ACME HTTP-01 tokens to peer regions over the mesh (or use DNS-01).\n")
	_, err := io.WriteString(output, b.String())
	return err
}
