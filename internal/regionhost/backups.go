package regionhost

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const backupsUsage = `Usage: ts-orch region backups CODE [--check|--apply]

Lists every live host, attached boot volume, assigned policy, newest available
backup time (UTC) and age. Uses the operator's ~/.oci/config DEFAULT profile.
Default: read-only inventory. --check: read-only; fails for missing volumes,
policies, backups, or backups older than 8 days. --apply: assigns the regional
ts-boot-weekly-4 policy to unassigned boot volumes; creates that policy if absent.
Existing assignments are preserved. Assignment does not take an immediate backup.
`

func runBackups(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("region backups", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { io.WriteString(out, backupsUsage) }
	check := fs.Bool("check", false, "fail when backup coverage is missing or older than 8 days")
	apply := fs.Bool("apply", false, "assign ts-boot-weekly-4 to unassigned boot volumes")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	code := fs.Arg(0)
	if fs.NArg() > 0 {
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
	}
	entry, ok := catalog.LookupName(code)
	if !ok || fs.NArg() != 0 || *check && *apply {
		return errors.New(backupsUsage)
	}
	r, err := connect(ctx, entry, !*apply, out)
	if err != nil {
		return err
	}
	parent, err := r.oneCompartment(r.tenancy, "TerraScale")
	if err != nil {
		return err
	}
	r.compartment, err = r.oneCompartment(parent, r.cell+"-control")
	if err != nil {
		return err
	}
	if r.compartment == "" {
		return fmt.Errorf("no ACTIVE compartment for %s", code)
	}
	return r.backups(*check, *apply)
}

func (r *run) backups(check, apply bool) error {
	instances, err := r.instances()
	if err != nil {
		return err
	}
	hosts := live(instances)
	if len(hosts) == 0 {
		return fmt.Errorf("no live hosts in %s", r.code)
	}
	slices.SortFunc(hosts, func(a, b core.Instance) int {
		return strings.Compare(deref(a.DisplayName), deref(b.DisplayName))
	})
	if _, err := fmt.Fprintln(r.out, "HOST\tBOOT VOLUME\tPOLICY\tNEWEST BACKUP UTC\tAGE"); err != nil {
		return err
	}
	var failures, missingVolumes []error
	now := time.Now()
	for _, inst := range hosts {
		host := deref(inst.DisplayName)
		volume, err := r.bootVolume(&inst)
		if errors.Is(err, errBootVolumeNotFound) {
			if _, err := fmt.Fprintf(r.out, "%s\tNOT FOUND\tnone\tnone\t-\n", host); err != nil {
				return err
			}
			problem := fmt.Errorf("%s: boot volume NOT FOUND", host)
			failures = append(failures, problem)
			missingVolumes = append(missingVolumes, problem)
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", host, err)
		}
		assigned, err := r.bootBackupAssignment(volume)
		if err != nil {
			return fmt.Errorf("%s: %w", host, err)
		}
		if apply && assigned == "" {
			if err := r.ensureVolumeBootBackup(volume); err != nil {
				return fmt.Errorf("%s: %w", host, err)
			}
			assigned, err = r.bootBackupAssignment(volume)
			if err != nil {
				return err
			}
		}
		policy := "none"
		if assigned != "" {
			read, err := r.storage.GetVolumeBackupPolicy(r.ctx, core.GetVolumeBackupPolicyRequest{PolicyId: &assigned})
			if err != nil {
				return fmt.Errorf("%s: %w", host, err)
			}
			policy = deref(read.DisplayName)
			if policy == "" {
				policy = assigned
			}
		} else {
			failures = append(failures, fmt.Errorf("%s: no backup policy", host))
		}
		newest, err := r.newestBootBackup(volume)
		if err != nil {
			return fmt.Errorf("%s: %w", host, err)
		}
		stamp, age := "none", "-"
		if newest.IsZero() {
			failures = append(failures, fmt.Errorf("%s: no available backup", host))
		} else {
			stamp, age = newest.UTC().Format(time.RFC3339), now.Sub(newest).Round(time.Second).String()
			if now.Sub(newest) > 8*24*time.Hour {
				failures = append(failures, fmt.Errorf("%s: newest backup is %s old (maximum 8 days)", host, age))
			}
		}
		if _, err := fmt.Fprintf(r.out, "%s\t%s\t%s\t%s\t%s\n", host, volume, policy, stamp, age); err != nil {
			return err
		}
	}
	if check {
		return errors.Join(failures...)
	}
	if apply {
		return errors.Join(missingVolumes...)
	}
	return nil
}

func (r *run) newestBootBackup(volume string) (time.Time, error) {
	req := core.ListBootVolumeBackupsRequest{
		CompartmentId: &r.compartment, BootVolumeId: &volume,
		LifecycleState: core.BootVolumeBackupLifecycleStateAvailable,
	}
	var newest time.Time
	for {
		page, err := r.storage.ListBootVolumeBackups(r.ctx, req)
		if err != nil {
			return newest, err
		}
		for _, backup := range page.Items {
			if backup.TimeCreated != nil && backup.TimeCreated.After(newest) {
				newest = backup.TimeCreated.Time
			}
		}
		if page.OpcNextPage == nil {
			return newest, nil
		}
		req.Page = page.OpcNextPage
	}
}
