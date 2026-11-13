package regionhost

import (
	"cmp"
	"errors"
	"fmt"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

func (r *run) rm(host string, confirmed, deleteVolume bool) error {
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
	volumeHost := cmp.Or(host, "ts-"+r.code+"-1")
	if target != nil {
		volumeHost = deref(target.DisplayName)
	}
	volume, err := r.dataVolume(volumeHost)
	if err != nil {
		return err
	}
	if deleteVolume && volume != nil {
		if _, err := r.dataAttachment(target, volume); err != nil {
			return err
		}
		if !r.dry {
			if err := r.confirmVolumeDeletion(volumeHost); err != nil {
				return err
			}
		}
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
				PreserveBootVolume: new(false), PreserveDataVolumesCreatedAtLaunch: new(true)}); err != nil {
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
	if err != nil {
		return err
	}
	if volume != nil {
		if deleteVolume {
			if err := r.deleteDataVolume(volumeHost, volume); err != nil {
				return err
			}
		} else if err := r.report("unchanged", "kept-data-volume", volumeHost+"-data", deref(volume.Id)); err != nil {
			return err
		}
	}
	if host != "" {
		return nil
	}
	if err := r.ensureIAM(); err != nil {
		return err
	}
	if err := r.ensureDNS(""); err != nil {
		return err
	}
	return r.ensurePin(ip, true)
}
