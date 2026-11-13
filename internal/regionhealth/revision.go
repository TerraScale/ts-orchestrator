package regionhealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func revisionCLI(ctx context.Context, args []string, state string, output io.Writer) error {
	if len(args) != 1 || !regexp.MustCompile("^[0-9a-f]{40}$").MatchString(args[0]) {
		return errors.New("usage: ts-orch status revision <published 40-hex revision>")
	}
	conn, err := mesh.Connect(state)
	if err != nil {
		return fmt.Errorf("revision gate cannot read regional inventories: %w", err)
	}
	defer conn.Close()
	regions := mesh.Regions()
	reports, err := ask(ctx, conn, len(regions), statusWait)
	if err != nil {
		return err
	}
	return revisionGate(output, regions, reports, args[0])
}

func revisionGate(output io.Writer, regions []string, reports map[string]Report, expected string) error {
	failures := 0
	hosts := 0
	fail := func(region, host, reason string) error {
		failures++
		_, err := fmt.Fprintf(output, "%s host %s: %s\n", region, host, reason)
		return err
	}
	for _, region := range regions {
		report, ok := reports[region]
		if !ok {
			if err := fail(region, "inventory", "region did not reply"); err != nil {
				return err
			}
			continue
		}
		if report.HostError != "" {
			if err := fail(region, "inventory", report.HostError); err != nil {
				return err
			}
		}
		if len(report.Hosts) == 0 {
			if err := fail(region, "inventory", "empty registered node inventory"); err != nil {
				return err
			}
		}
		for _, host := range report.Hosts {
			hosts++
			reasons := []string{}
			if host.ID == "" {
				reasons = append(reasons, "registered node has no id")
			}
			if host.Version != expected {
				reasons = append(reasons, fmt.Sprintf("revision %q; expected %s", host.Version, expected))
			}
			if host.Error != "" {
				reasons = append(reasons, host.Error)
			}
			if host.Refusal != nil {
				reasons = append(reasons, fmt.Sprintf("refused %s run %s attempt %s: %s", host.Refusal.SHA, host.Refusal.RunID, host.Refusal.RunAttempt, host.Refusal.Reason))
			}
			if len(reasons) != 0 {
				if err := fail(region, host.Host, strings.Join(reasons, "; ")); err != nil {
					return err
				}
			}
		}
	}
	if failures != 0 || hosts == 0 {
		return fmt.Errorf("revision gate failed: %d failures, %d registered hosts", failures, hosts)
	}
	_, err := fmt.Fprintf(output, "revision %s verified on %d registered hosts\n", expected, hosts)
	return err
}
