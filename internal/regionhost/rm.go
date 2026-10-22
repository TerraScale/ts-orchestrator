package regionhost

import (
	"cmp"
	"errors"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

// rm reverses add: it terminates --host NAME, or with confirmed the region
// host, whose DNS record, IAM and pin then go too.
// shortcut: the compartment and network stay (they cost nothing); delete them
// by hand if the region never comes back.
func (r *run) rm(host string, confirmed bool) error {
	name := r.cell + "-control"
	parent, err := r.oneCompartment(r.tenancy, "TerraScale")
	if err != nil {
		return err
	}
	r.parent = parent
	if r.compartment, err = r.oneCompartment(parent, name); err != nil || r.compartment == "" {
		return errors.Join(err, r.report("unchanged", "compartment", name, "-"))
	}
	items, err := r.instances()
	if err != nil {
		return err
	}
	regionHost, err := pick(items, "")
	if err != nil {
		return err
	}
	target := regionHost
	if host != "" {
		if target, err = pick(items, host); err != nil {
			return err
		}
		if target != nil && *target.Id == *regionHost.Id {
			return fmt.Errorf("%s is %s's region host; only `region rm %s --yes` removes it", host, r.code, r.code)
		}
	} else if target != nil && !confirmed {
		return fmt.Errorf("terminating %s's region host %s needs --yes, typed interactively", r.code, deref(target.DisplayName))
	}
	var ip string
	if target == nil {
		err = r.report("unchanged", "instance", cmp.Or(host, "ts-"+r.code+"-1"), "-")
	} else {
		if host == "" {
			if ip, err = r.publicIP(target); err != nil {
				return err
			}
		}
		if !r.dry {
			if _, err := r.compute.TerminateInstance(r.ctx, core.TerminateInstanceRequest{InstanceId: target.Id,
				PreserveBootVolume: new(false)}); err != nil {
				return err
			}
			// The IAM below must no longer see it as live.
			if err := poll(r.ctx, 5*time.Second, 60, func() (bool, error) {
				g, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: target.Id})
				return len(live([]core.Instance{g.Instance})) == 0, err
			}); err != nil {
				return err
			}
		}
		err = r.report("deleted", "instance", deref(target.DisplayName), *target.Id)
	}
	if err != nil || host != "" {
		return err // an extra host leaves the region's IAM, DNS and pin alone
	}
	if err := r.ensureIAM(); err != nil {
		return err
	}
	if err := r.ensureDNS(""); err != nil {
		return err
	}
	return r.ensurePin(ip, true)
}
