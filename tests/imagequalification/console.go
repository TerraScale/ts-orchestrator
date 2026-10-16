package imagequalification

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
	"golang.org/x/crypto/ssh"
)

const maxConsoleBytes = 1 << 20

func (j journal) resolved(operation string) bool {
	if operation == "image" {
		return j.ImageID != ""
	}
	if strings.HasPrefix(operation, "console/") {
		return j.ConsoleHistories[operation] != ""
	}
	return j.Hosts[operation] != ""
}

func (c *cloud) ownedInstance(ctx context.Context, j journal, spec HostSpec) (core.Instance, error) {
	id := j.Hosts[spec.Name]
	if id == "" || j.ImageID == "" {
		return core.Instance{}, errors.New("exact instance and image journal IDs are required")
	}
	r, err := c.compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(id)})
	if err != nil {
		return core.Instance{}, err
	}
	i := r.Instance
	if i.Id == nil || *i.Id != id || i.CompartmentId == nil || *i.CompartmentId != c.prepared.approval.Compartment || i.ImageId == nil || *i.ImageId != j.ImageID || i.DisplayName == nil || *i.DisplayName != c.name(spec.Name) || !c.owns(i.FreeformTags) || i.Shape == nil || *i.Shape != spec.Shape || i.ShapeConfig == nil || i.ShapeConfig.Ocpus == nil || *i.ShapeConfig.Ocpus != spec.OCPUs || i.ShapeConfig.MemoryInGBs == nil || *i.ShapeConfig.MemoryInGBs != spec.MemoryGB || i.AvailabilityDomain == nil || *i.AvailabilityDomain != spec.AvailabilityDomain || i.FaultDomain == nil || *i.FaultDomain != spec.FaultDomain {
		return core.Instance{}, errors.New("observed disposable instance scope, image, shape or placement differs")
	}
	return i, nil
}

func (c *cloud) observeHost(ctx context.Context, j journal, spec HostSpec) (hostObservation, error) {
	var result hostObservation
	i, err := c.ownedInstance(ctx, j, spec)
	if err != nil {
		return result, err
	}
	if i.LifecycleState != core.InstanceLifecycleStateRunning {
		return result, errors.New("native disposable host is not RUNNING")
	}
	var vnicID string
	var page *string
	for pages := 0; ; pages++ {
		if pages >= 100 {
			return result, errors.New("host VNIC inventory exceeds bound")
		}
		r, err := c.compute.ListVnicAttachments(ociclient.RequestContext(ctx), core.ListVnicAttachmentsRequest{CompartmentId: new(c.prepared.approval.Compartment), InstanceId: i.Id, Page: page})
		if err != nil {
			return result, err
		}
		for _, attachment := range r.Items {
			if attachment.InstanceId == nil || *attachment.InstanceId != *i.Id || attachment.CompartmentId == nil || *attachment.CompartmentId != c.prepared.approval.Compartment || attachment.SubnetId == nil || *attachment.SubnetId != c.prepared.approval.Subnet || attachment.VnicId == nil || *attachment.VnicId == "" || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || vnicID != "" {
				return result, errors.New("native disposable host requires exactly one approved attached VNIC")
			}
			vnicID = *attachment.VnicId
		}
		if r.OpcNextPage == nil || *r.OpcNextPage == "" {
			break
		}
		page = r.OpcNextPage
	}
	if vnicID == "" {
		return result, errors.New("native disposable host has no VNIC")
	}
	v, err := c.network.GetVnic(ociclient.RequestContext(ctx), core.GetVnicRequest{VnicId: new(vnicID)})
	if err != nil {
		return result, err
	}
	if v.Id == nil || *v.Id != vnicID || v.SubnetId == nil || *v.SubnetId != c.prepared.approval.Subnet || v.PublicIp != nil && *v.PublicIp != "" || v.PrivateIp == nil || v.IsPrimary == nil || !*v.IsPrimary || len(v.NsgIds) != 0 {
		return result, errors.New("observed native VNIC escaped exact private subnet")
	}
	address, err := netip.ParseAddr(*v.PrivateIp)
	peers, _ := netip.ParsePrefix(c.prepared.approval.PeerCIDR)
	if err != nil || !peers.Contains(address) {
		return result, errors.New("native VNIC address differs from approved peer network")
	}
	return hostObservation{Name: spec.Name, InstanceID: *i.Id, ImageID: j.ImageID, PrivateIP: *v.PrivateIp}, nil
}

func (c *cloud) consoleMetadata(ctx context.Context, j journal, spec HostSpec, operation string) (core.ConsoleHistory, error) {
	id := j.ConsoleHistories[operation]
	started, exists := j.Intents[operation]
	if !exists || started.IsZero() {
		return core.ConsoleHistory{}, errors.New("console history lacks durable capture intent")
	}
	if id == "" {
		return core.ConsoleHistory{}, errors.New("console history lacks an exact journal ID")
	}
	r, err := c.compute.GetConsoleHistory(ociclient.RequestContext(ctx), core.GetConsoleHistoryRequest{InstanceConsoleHistoryId: new(id)})
	if err != nil {
		return core.ConsoleHistory{}, err
	}
	h := r.ConsoleHistory
	if h.Id == nil || *h.Id != id || h.InstanceId == nil || *h.InstanceId != j.Hosts[spec.Name] || h.CompartmentId == nil || *h.CompartmentId != c.prepared.approval.Compartment || h.AvailabilityDomain == nil || *h.AvailabilityDomain != spec.AvailabilityDomain || h.TimeCreated == nil || h.TimeCreated.Time.Before(started.Add(-time.Second)) || !c.owns(h.FreeformTags) {
		return core.ConsoleHistory{}, errors.New("console history differs from exact approved instance and capture intent")
	}
	return h, nil
}

// consoleKey retains only an exact public-key marker and a digest, never console
// text, which can contain unrelated cloud-init or guest application secrets.
func (c *cloud) consoleKey(ctx context.Context, path string, spec HostSpec) (hostObservation, string, error) {
	j, err := c.load(path)
	if err != nil {
		return hostObservation{}, "", err
	}
	host, err := c.observeHost(ctx, j, spec)
	if err != nil {
		return host, "", err
	}
	if key := j.HostKeys[spec.Name]; key != "" {
		host.HostKeySHA256, host.ConsoleSHA256 = hashBytes([]byte(key)), j.ConsoleDigests[spec.Name]
		host.ConsoleHistoryID = j.HostConsoleHistory[spec.Name]
		parsed, digest, parseErr := parseConsoleKey(c.prepared.approval.RunID, "TSQUAL_HOSTKEY "+c.prepared.approval.RunID+" "+key+"\n")
		if parseErr != nil || parsed != key || digest != host.ConsoleSHA256 || !validHash(host.ConsoleSHA256) || host.ConsoleHistoryID == "" {
			return host, "", errors.New("retained console key lacks evidence digest")
		}
		return host, key, nil
	}
	for attempt := range 40 {
		operation := fmt.Sprintf("console/%s/%d", spec.Name, attempt)
		if err := c.check(ctx, false); err != nil {
			return host, "", err
		}
		if j.ConsoleHistories[operation] == "" {
			if err := c.intent(path, &j, operation); err != nil {
				return host, "", err
			}
			if _, err := c.ownedInstance(ctx, j, spec); err != nil {
				return host, "", err
			}
			r, err := c.compute.CaptureConsoleHistory(ociclient.RequestContext(ctx), core.CaptureConsoleHistoryRequest{CaptureConsoleHistoryDetails: core.CaptureConsoleHistoryDetails{InstanceId: new(host.InstanceID), DisplayName: new(c.name("console-" + spec.Name)), FreeformTags: c.tags()}, OpcRetryToken: new(c.token(operation))})
			if err != nil {
				return host, "", err
			}
			if r.Id == nil || *r.Id == "" {
				return host, "", errors.New("captured console history has no ID")
			}
			j.ConsoleHistories[operation] = *r.Id
			if err := checkpoint(path, j); err != nil {
				return host, "", err
			}
		}
		for {
			h, err := c.consoleMetadata(ctx, j, spec, operation)
			if err != nil {
				return host, "", err
			}
			if h.LifecycleState == core.ConsoleHistoryLifecycleStateSucceeded {
				break
			}
			if h.LifecycleState != core.ConsoleHistoryLifecycleStateRequested && h.LifecycleState != core.ConsoleHistoryLifecycleStateGettingHistory {
				return host, "", errors.New("console capture failed")
			}
			if err := pauseConsole(ctx); err != nil {
				return host, "", err
			}
		}
		r, err := c.compute.GetConsoleHistoryContent(ociclient.RequestContext(ctx), core.GetConsoleHistoryContentRequest{InstanceConsoleHistoryId: new(j.ConsoleHistories[operation]), Length: new(maxConsoleBytes)})
		if err != nil {
			return host, "", err
		}
		if r.Value == nil || len(*r.Value) > maxConsoleBytes || r.OpcBytesRemaining != nil && *r.OpcBytesRemaining != 0 {
			return host, "", errors.New("console snapshot exceeds bounded complete content")
		}
		key, digest, err := parseConsoleKey(c.prepared.approval.RunID, *r.Value)
		if err != nil {
			return host, "", err
		}
		if key != "" {
			for name, previous := range j.HostKeys {
				if name != spec.Name && previous == key {
					return host, "", errors.New("disposable hosts reused an SSH host key")
				}
			}
			j.HostKeys[spec.Name], j.ConsoleDigests[spec.Name] = key, digest
			j.HostConsoleHistory[spec.Name] = j.ConsoleHistories[operation]
			host.ConsoleHistoryID = j.ConsoleHistories[operation]
			if err := checkpoint(path, j); err != nil {
				return host, "", err
			}
			host.HostKeySHA256, host.ConsoleSHA256 = hashBytes([]byte(key)), digest
			return host, key, nil
		}
		if err := pauseConsole(ctx); err != nil {
			return host, "", err
		}
	}
	return host, "", errors.New("bounded console captures did not expose the approved run host key")
}

func parseConsoleKey(runID, content string) (string, string, error) {
	if !runPattern.MatchString(runID) || len(content) > maxConsoleBytes {
		return "", "", errors.New("invalid run or oversized console content")
	}
	var result string
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, "TSQUAL_HOSTKEY ") {
			continue
		}
		fields := strings.Fields(line)
		if result != "" || len(fields) != 4 || fields[1] != runID {
			return "", "", errors.New("console key marker is duplicated or belongs to another run")
		}
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(fields[2] + " " + fields[3]))
		if err != nil || len(rest) != 0 || key.Type() != ssh.KeyAlgoED25519 {
			return "", "", errors.New("console marker is not one exact Ed25519 host public key")
		}
		result = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	}
	if result == "" {
		return "", "", nil
	}
	return result, hashBytes([]byte("TSQUAL_HOSTKEY " + runID + " " + result + "\n")), nil
}

func pauseConsole(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return nil
	}
}

func (c *cloud) cleanupConsole(ctx context.Context, path string, j *journal) error {
	for operation, id := range j.ConsoleHistories {
		if j.ConsoleDeleted[operation] {
			continue
		}
		parts := strings.Split(operation, "/")
		if len(parts) != 3 || parts[0] != "console" {
			return errors.New("unrecognized console journal operation")
		}
		var spec HostSpec
		for _, candidate := range c.prepared.approval.Hosts {
			if candidate.Name == parts[1] {
				spec = candidate
			}
		}
		if spec.Name == "" {
			return errors.New("unapproved console journal host")
		}
		if _, err := c.consoleMetadata(ctx, *j, spec, operation); err != nil && !isNotFound(err) {
			return err
		} else if err == nil {
			if err := c.check(ctx, true); err != nil {
				return err
			}
			if _, err := c.compute.DeleteConsoleHistory(ociclient.RequestContext(ctx), core.DeleteConsoleHistoryRequest{InstanceConsoleHistoryId: new(id)}); err != nil && !isNotFound(err) {
				return err
			}
		}
		for {
			if err := c.check(ctx, true); err != nil {
				return err
			}
			_, err := c.consoleMetadata(ctx, *j, spec, operation)
			if isNotFound(err) {
				break
			}
			if err != nil {
				return err
			}
			if err := pauseConsole(ctx); err != nil {
				return err
			}
		}
		j.ConsoleDeleted[operation] = true
		if err := checkpoint(path, j); err != nil {
			return err
		}
	}
	return nil
}
