package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

func (c command) observedDigests(args []string) error {
	return c.observedDigestsWith(args, deployEnv{storage: operatorObjectStorage, discover: discoverServingCells})
}

func (c command) observedDigestsWith(args []string, env deployEnv) error {
	flags := flag.NewFlagSet("observed-digests", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	namespace := flags.String("namespace", "", "Object Storage namespace of the regions' head buckets")
	var cells stringList
	flags.Var(&cells, "cell", "cell to show; repeatable; default every cell")
	var roles stringList
	flags.Var(&roles, "role", "native service role to show; repeatable; default terrabase and ts-auth")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !validStorageToken(*namespace) || flags.NArg() != 0 {
		return errors.New("observed-digests requires --namespace")
	}
	if len(roles) == 0 {
		roles = stringList{"terrabase", "ts-auth"}
	}
	for _, role := range roles {
		if !validStorageToken(role) {
			return fmt.Errorf("invalid --role %q", role)
		}
	}
	targetCells, err := deploymentCells(c.ctx, cells, env.discover)
	if err != nil {
		return err
	}
	cells = targetCells
	table := tabwriter.NewWriter(c.output, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintf(table, "CELL\tROLE\tSTATE\tADMITTED\tNODE\tRUNNING\tOBSERVED_AT\tMATCH\n"); err != nil {
		return err
	}
	shortDigest := func(digest string) string {
		if digest == "" {
			return "-"
		}
		return digest[:min(12, len(digest))]
	}
	var failed []string
	for _, cell := range cells {
		location, locationErr := channelLocation(env, cell, *namespace)
		if locationErr == nil {
			for _, role := range roles {
				status, found, readErr := releasechannel.ReadServiceStatus(c.ctx, location, role)
				if readErr != nil {
					locationErr = readErr
					break
				}
				if !found {
					if _, err := fmt.Fprintf(table, "%s\t%s\tmissing\t-\t-\t-\t-\tunknown\n", cell, role); err != nil {
						return err
					}
					continue
				}
				if len(status.Replicas) == 0 {
					if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t-\t-\t-\tunknown\n", cell, role,
						status.State, shortDigest(status.Digest)); err != nil {
						return err
					}
					continue
				}
				for _, replica := range status.Replicas {
					running, match := "unknown", "unknown"
					if replica.RunningDigest != "" {
						running = shortDigest(replica.RunningDigest)
						if replica.RunningDigest == status.Digest {
							match = "yes"
						} else {
							match = "no"
						}
					}
					observedAt := replica.ObservedAt.Format("2006-01-02T15:04:05Z07:00")
					if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", cell, role,
						status.State, shortDigest(status.Digest), replica.Node, running, observedAt, match); err != nil {
						return err
					}
				}
			}
		}
		if locationErr != nil {
			if _, err := fmt.Fprintf(table, "%s\t-\terror\t%s\t-\t-\t-\tunknown\n", cell, locationErr.Error()); err != nil {
				return err
			}
			failed = append(failed, cell)
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not read the observed digests of %s", strings.Join(failed, " "))
	}
	return nil
}
