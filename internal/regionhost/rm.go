package regionhost

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
)

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
	items = slices.DeleteFunc(items, func(i core.Instance) bool {
		return i.LifecycleState == core.InstanceLifecycleStateTerminated
	})
	regionHost, err := pickFrom(items, "")
	if err != nil {
		return err
	}
	target := regionHost
	if host != "" {
		if target, err = pickFrom(items, host); err != nil {
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
	if target != nil && volume == nil {
		expected := target.Metadata[dataVolumeTag]
		if expected != "" {
			return errors.New("the host data volume is missing; refusing to terminate before detachment")
		}
	}
	var ip string
	if target == nil {
		err = r.report("unchanged", "instance", cmp.Or(host, "ts-"+r.code+"-1"), "-")
	} else {
		if host == "" && target.LifecycleState != core.InstanceLifecycleStateTerminating {
			if ip, err = r.publicIP(target); err != nil {
				return err
			}
		}
		if err := r.stopInstance(target); err != nil {
			return err
		}
		if volume != nil {
			if err := r.detachDataVolume(target, volume); err != nil {
				return err
			}
		}
		if err := r.terminateInstance(target); err != nil {
			return err
		}
		err = r.report("deleted", "instance", deref(target.DisplayName), *target.Id)
	}
	if err != nil {
		return err
	}
	if volume != nil {
		if err := r.report("unchanged", "kept-data-volume", volumeHost+"-data", deref(volume.Id)); err != nil {
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

func (r *run) detachDataVolume(instance *core.Instance, volume *core.Volume) error {
	attachment, err := r.dataAttachment(instance, volume)
	if err != nil || attachment == nil {
		return err
	}
	if !r.dry {
		current, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: instance.Id})
		if err != nil {
			return err
		}
		if current.LifecycleState != core.InstanceLifecycleStateStopped {
			return fmt.Errorf("refusing detach of volume %s: instance %s is %s, expected STOPPED", deref(volume.Id), deref(instance.Id), current.LifecycleState)
		}
		if attachment.GetLifecycleState() != core.VolumeAttachmentLifecycleStateDetaching {
			if _, err := r.compute.DetachVolume(r.ctx, core.DetachVolumeRequest{VolumeAttachmentId: attachment.GetId()}); err != nil {
				return err
			}
		}
		if err := poll(r.ctx, 5*time.Second, 120, func() (bool, error) {
			g, err := r.compute.GetVolumeAttachment(r.ctx, core.GetVolumeAttachmentRequest{VolumeAttachmentId: attachment.GetId()})
			return err == nil && g.VolumeAttachment.GetLifecycleState() == core.VolumeAttachmentLifecycleStateDetached, err
		}); err != nil {
			return err
		}
	}
	return r.report("deleted", "data-attachment", deref(instance.DisplayName), deref(volume.Id))
}

func (r *run) finishTerminating(items []core.Instance, host string) error {
	for _, instance := range items {
		if instance.LifecycleState != core.InstanceLifecycleStateTerminating || (host != "" && deref(instance.DisplayName) != host) {
			continue
		}
		if r.dry {
			return fmt.Errorf("host %s is terminating; wait for termination before planning its replacement", deref(instance.DisplayName))
		}
		if err := poll(r.ctx, 5*time.Second, 60, func() (bool, error) {
			g, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: instance.Id})
			return g.LifecycleState == core.InstanceLifecycleStateTerminated, err
		}); err != nil {
			return fmt.Errorf("waiting for terminating host %s: %w", deref(instance.DisplayName), err)
		}
	}
	return nil
}

func (r *run) stopInstance(instance *core.Instance) error {
	if r.dry {
		return r.report("updated", "instance-stop", deref(instance.DisplayName), deref(instance.Id))
	}
	current, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: instance.Id})
	if err != nil {
		return err
	}
	switch current.LifecycleState {
	case core.InstanceLifecycleStateStopped, core.InstanceLifecycleStateTerminating, core.InstanceLifecycleStateTerminated:
		return nil
	case core.InstanceLifecycleStateRunning:
		if _, err := r.compute.InstanceAction(r.ctx, core.InstanceActionRequest{InstanceId: instance.Id, Action: core.InstanceActionActionSoftstop}); err != nil {
			return err
		}
	case core.InstanceLifecycleStateStopping:
	default:
		return fmt.Errorf("cannot stop instance %s in state %s", deref(instance.Id), current.LifecycleState)
	}
	return poll(r.ctx, 5*time.Second, 240, func() (bool, error) {
		state, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: instance.Id})
		return err == nil && state.LifecycleState == core.InstanceLifecycleStateStopped, err
	})
}

func (r *run) terminateInstance(instance *core.Instance) error {
	if r.dry {
		return nil
	}
	current, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: instance.Id})
	if err != nil {
		return err
	}
	if current.LifecycleState != core.InstanceLifecycleStateTerminating && current.LifecycleState != core.InstanceLifecycleStateTerminated {
		if current.LifecycleState != core.InstanceLifecycleStateStopped {
			return fmt.Errorf("refusing termination of instance %s in state %s", deref(instance.Id), current.LifecycleState)
		}
		if _, err := r.compute.TerminateInstance(r.ctx, core.TerminateInstanceRequest{InstanceId: instance.Id, PreserveBootVolume: new(false), PreserveDataVolumesCreatedAtLaunch: new(true)}); err != nil {
			return err
		}
	}
	return poll(r.ctx, 5*time.Second, 60, func() (bool, error) {
		state, err := r.compute.GetInstance(r.ctx, core.GetInstanceRequest{InstanceId: instance.Id})
		return err == nil && state.LifecycleState == core.InstanceLifecycleStateTerminated, err
	})
}
