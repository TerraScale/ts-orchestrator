package geodns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// Run implements `ts-orch edge geodns [--plan]`. --plan reads DNS and creates
// nothing; without it the OCI objects are created or updated in place.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "geodns" || len(args) > 2 || (len(args) == 2 && args[1] != "--plan") {
		return errors.New("usage: ts-orch edge geodns [--plan]")
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
	hosts, err := Hosts()
	if err != nil {
		return fmt.Errorf("edge geodns: %w", err)
	}
	if len(hosts) == 0 {
		return errors.New("edge geodns: no service declaration serves every region")
	}
	plans := Build(regions, hosts)
	names := make([]string, len(hosts))
	for i, h := range hosts {
		names[i] = h.Name
	}
	if len(args) == 1 {
		return runApply(ctx, plans, output)
	}
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
		fmt.Fprintf(&b, "  monitor %s HTTP GET :80%s Host=%s every 30s on %d targets\n", p.Monitor.DisplayName, p.Monitor.Path, p.Monitor.Headers["Host"], len(p.Monitor.Targets))
		fmt.Fprintf(&b, "  policy %s ROUTE_BY_GEO FILTER>HEALTH>PRIORITY>LIMIT 1, attached at %s\n", p.Policy.DisplayName, p.Attachment.DomainName)
	}
	b.WriteString("\nCloudflare terrascale.tech (would change, nothing changed):\n")
	fmt.Fprintf(&b, "  NS %s -> each OCI nameserver of the new zone (DNS only)\n", Zone)
	for _, p := range plans {
		fmt.Fprintf(&b, "  CNAME %s -> %s (DNS only, replaces the current record)\n", p.Host, p.Attachment.DomainName)
	}
	b.WriteString("\nPrerequisite before the switch: every region serves and holds certificates for " + strings.Join(names, ", ") +
		" (the edge fetches HTTP-01 tokens it does not hold from peer regions).\n")
	_, err = io.WriteString(output, b.String())
	return err
}

// runApply creates or updates the OCI objects with the operator's OCI profile
// and prints them with the Cloudflare records the switch needs.
func runApply(ctx context.Context, plans []HostPlan, output io.Writer) error {
	call, err := operatorCaller()
	if err != nil {
		return fmt.Errorf("edge geodns: OCI operator credentials: %w", err)
	}
	changes, nameservers, err := apply(ctx, call, plans)
	if err != nil {
		return fmt.Errorf("edge geodns: %w", err)
	}
	var b strings.Builder
	for _, c := range changes {
		fmt.Fprintf(&b, "%-9s %-10s %-26s %s\n", c.Action, c.Kind, c.Name, c.ID)
	}
	b.WriteString("\nCloudflare terrascale.tech records for the switch (DNS only):\n")
	for _, ns := range nameservers {
		fmt.Fprintf(&b, "  NS    %s -> %s\n", Zone, ns)
	}
	for _, p := range plans {
		fmt.Fprintf(&b, "  CNAME %s -> %s\n", p.Host, p.Attachment.DomainName)
	}
	_, err = io.WriteString(output, b.String())
	return err
}
