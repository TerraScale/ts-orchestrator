package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
)

func RunCertificateCLI(ctx context.Context, args []string, output io.Writer) error {
	if len(args) < 1 || args[0] != "inventory" || len(args) > 2 {
		return errors.New("usage: ts-orch edge certificates inventory [local|node|all]")
	}
	targets := map[string]string{}
	var nodes []nodelist.Node
	if len(args) == 1 || args[1] != "local" {
		list, err := nodelist.Read("/var/lib/ts-orch")
		if err != nil {
			return fmt.Errorf("certificate inventory node list: %w", err)
		}
		nodes = list.Nodes
	}
	if len(args) == 1 || args[1] == "all" {
		for _, node := range nodes {
			targets[node.Name] = node.MeshIP
		}
	} else if args[1] == "local" {
		iface, err := net.InterfaceByName("wt0")
		if err != nil {
			return err
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return err
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil && ip.To4() != nil && ip.IsPrivate() {
				targets["local"] = ip.String()
				break
			}
		}
		if len(targets) == 0 {
			return errors.New("local mesh address unavailable")
		}
	} else {
		for _, node := range nodes {
			if node.Name == args[1] {
				targets[node.Name] = node.MeshIP
			}
		}
		if len(targets) == 0 {
			return errors.New("node is not in the node list")
		}
	}
	if len(targets) == 0 {
		return errors.New("node list is empty")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	names := []string{}
	for node := range targets {
		names = append(names, node)
	}
	slices.Sort(names)
	failures := []error{}
	for _, node := range names {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(targets[node], "9108")+"/edge/certificates", nil)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: invalid mesh address", node))
			continue
		}
		response, err := client.Do(request)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: inventory unavailable", node))
			continue
		}
		var inventory edge.Inventory
		err = json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&inventory)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || err != nil || inventory.Certificates == nil || inventory.MissingNames == nil || inventory.Errors == nil {
			failures = append(failures, fmt.Errorf("%s: invalid inventory response", node))
			continue
		}
		for _, cert := range inventory.Certificates {
			if _, err := fmt.Fprintf(output, "%s names=%s key=%s issuer=%q serial=%s not_before=%s not_after=%s sha256=%s source=%s valid=%t\n", node, strings.Join(cert.Names, ","), cert.KeyType, cert.Issuer, cert.Serial, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), cert.Fingerprint, cert.Source, cert.Valid); err != nil {
				return err
			}
		}
		if len(inventory.MissingNames) > 0 || len(inventory.Errors) > 0 {
			failures = append(failures, fmt.Errorf("%s: missing=%s errors=%s", node, strings.Join(inventory.MissingNames, ","), strings.Join(inventory.Errors, ",")))
		}
	}
	return errors.Join(failures...)
}
