package imagequalification

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/crypto/ssh"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const (
	runTag      = "terrascale-qualification-run"
	approvalTag = "terrascale-qualification-approval"
)

// cloud is intentionally unexported. Production grants cannot reach this
// unsigned-image adapter; only integration fixtures use it until the confined
// principal producer can establish actual effective credential isolation.
type cloud struct {
	prepared Prepared
	compute  core.ComputeClient
	objects  objectstorage.ObjectStorageClient
	network  core.VirtualNetworkClient
	block    core.BlockstorageClient
	uploader imageimport.ObjectUploader
	now      func() time.Time
}

type journal struct {
	RunID              string               `json:"run_id"`
	ApprovalSHA256     string               `json:"approval_sha256"`
	Object             string               `json:"object"`
	ImageID            string               `json:"image_id"`
	Hosts              map[string]string    `json:"hosts"`
	Terminated         map[string]bool      `json:"terminated"`
	ImageDeleted       bool                 `json:"image_deleted"`
	ObjectDeleted      bool                 `json:"object_deleted"`
	ConsoleHistories   map[string]string    `json:"console_histories"`
	ConsoleDeleted     map[string]bool      `json:"console_deleted"`
	HostKeys           map[string]string    `json:"host_keys"`
	HostConsoleHistory map[string]string    `json:"host_console_history"`
	ConsoleDigests     map[string]string    `json:"console_digests"`
	Intents            map[string]time.Time `json:"intents"`
}

func newCloud(prepared Prepared, factory *ociclient.Factory, endpoint string) (*cloud, error) {
	if err := prepared.approval.validate(); err != nil {
		return nil, err
	}
	a := prepared.approval
	if factory == nil || factory.Region() != a.OCIRegion {
		return nil, errors.New("disposable factory region differs")
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return nil, err
	}
	principal, err := factory.Provider().UserOCID()
	if err != nil {
		return nil, err
	}
	if tenancy != a.Tenancy || principal != a.Principal {
		return nil, errors.New("disposable credential principal or tenancy differs")
	}
	compute, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		return nil, err
	}
	network, err := factory.Network()
	if err != nil {
		return nil, err
	}
	block, err := factory.Blockstorage()
	if err != nil {
		return nil, err
	}
	ociclient.PinHost(&block.BaseClient, endpoint)
	ociclient.ConfigureRequestCancellation(&block.BaseClient)
	work, err := factory.WorkRequests()
	if err != nil {
		return nil, err
	}
	ociclient.PinHost(&work.BaseClient, endpoint)
	ociclient.ConfigureRequestCancellation(&work.BaseClient)
	ociclient.PinHost(&compute.BaseClient, endpoint)
	ociclient.PinHost(&objects.BaseClient, endpoint)
	ociclient.PinHost(&network.BaseClient, endpoint)
	ociclient.ConfigureRequestCancellation(&compute.BaseClient)
	ociclient.ConfigureRequestCancellation(&objects.BaseClient)
	ociclient.ConfigureRequestCancellation(&network.BaseClient)
	return &cloud{prepared: prepared, compute: compute, objects: objects, network: network, block: block, uploader: imageimport.NewClientFromSDK(compute, objects, work), now: time.Now}, nil
}

func (c *cloud) check(ctx context.Context, cleanup bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	expires := c.prepared.expires
	if cleanup {
		expires = c.prepared.approval.CleanupUntil
	}
	if !c.now().Before(expires) {
		return errors.New("disposable operation authority expired")
	}
	return nil
}

func (c *cloud) tags() map[string]string {
	return map[string]string{runTag: c.prepared.approval.RunID, approvalTag: c.prepared.approvalSHA256,
		imageimport.SHA256Tag: c.prepared.approval.Candidate.ArtifactSHA256}
}

func (c *cloud) owns(tags map[string]string) bool {
	for key, value := range c.tags() {
		if tags[key] != value {
			return false
		}
	}
	return true
}

func (c *cloud) name(host string) string {
	return "ts-qualification-" + c.prepared.approval.RunID + "-" + host
}

func (c *cloud) load(path string) (journal, error) {
	a := c.prepared.approval
	j := journal{RunID: a.RunID, ApprovalSHA256: c.prepared.approvalSHA256,
		Object:             "qualification/" + a.RunID + "/" + a.Candidate.ArtifactSHA256 + ".qcow2",
		HostConsoleHistory: map[string]string{}, ConsoleHistories: map[string]string{}, ConsoleDeleted: map[string]bool{}, HostKeys: map[string]string{}, ConsoleDigests: map[string]string{},
		Hosts: map[string]string{}, Terminated: map[string]bool{}, Intents: map[string]time.Time{}}
	wire, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return j, err
	}
	var restored journal
	if err := protocol.DecodeStrict(wire, &restored, 64<<10); err != nil {
		return j, err
	}
	if restored.RunID != j.RunID || restored.ApprovalSHA256 != j.ApprovalSHA256 || restored.Object != j.Object || restored.Hosts == nil || restored.Terminated == nil || restored.Intents == nil {
		return j, errors.New("cleanup journal belongs to a different approved run")
	}
	for name := range restored.Hosts {
		found := false
		for _, host := range a.Hosts {
			if name == host.Name {
				found = true
			}
		}
		if !found {
			return j, errors.New("cleanup journal contains an unapproved host")
		}
	}
	if restored.HostConsoleHistory == nil {
		restored.HostConsoleHistory = map[string]string{}
	}
	if restored.ConsoleHistories == nil {
		restored.ConsoleHistories = map[string]string{}
	}
	if restored.ConsoleDeleted == nil {
		restored.ConsoleDeleted = map[string]bool{}
	}
	if restored.HostKeys == nil {
		restored.HostKeys = map[string]string{}
	}
	if restored.ConsoleDigests == nil {
		restored.ConsoleDigests = map[string]string{}
	}
	return restored, nil
}

func (c *cloud) intent(path string, j *journal, operation string) error {
	started, exists := j.Intents[operation]
	if exists {
		// OCI retry tokens expire after 24 hours; never risk creating a duplicate.
		if c.now().Sub(started) >= 23*time.Hour {
			return errors.New("create retry window expired; retain journal for confined resource recovery")
		}
		return nil
	}
	j.Intents[operation] = c.now()
	return checkpoint(path, j)
}

func checkpoint(path string, value any) error {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".qualification-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(wire, '\n')); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// prepareResources checkpoints intent before every create and reuses a stable
// retry token across process restart. It never adopts by display name or tags.
func (c *cloud) prepareResources(ctx context.Context, path, publicKey string) (journal, error) {
	j, err := c.load(path)
	if err != nil {
		return j, err
	}
	if err := c.check(ctx, false); err != nil {
		return j, err
	}
	key, _, _, rest, keyErr := ssh.ParseAuthorizedKey([]byte(publicKey))
	if keyErr != nil || key.Type() != ssh.KeyAlgoED25519 || len(rest) > 0 || strings.ContainsAny(publicKey, "\r\n") {
		return j, errors.New("one ephemeral Ed25519 public key is required")
	}
	publicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	metadata, err := c.launchMetadata(publicKey)
	if err != nil {
		return j, err
	}
	if j.ImageDeleted || j.ObjectDeleted || len(j.Terminated) > 0 {
		return j, errors.New("cleaned run cannot provision again")
	}
	if err := verifyDisk(c.prepared.diskPath, c.prepared.approval); err != nil {
		return j, err
	}
	if err := checkpoint(path, j); err != nil {
		return j, err
	}
	a := c.prepared.approval
	exists, objectMetadata, err := c.uploader.HeadObject(ctx, a.Namespace, a.Bucket, j.Object)
	if err != nil {
		return j, err
	}
	if exists && (objectMetadata["sha256"] != a.Candidate.ArtifactSHA256 || objectMetadata["approval"] != c.prepared.approvalSHA256) {
		return j, errors.New("qualification object is not owned by these exact approved bytes")
	}
	if !exists {
		if err := c.check(ctx, false); err != nil {
			return j, err
		}
		err = c.uploader.UploadObject(ctx, imageimport.UploadRequest{Namespace: a.Namespace, Bucket: a.Bucket, Object: j.Object,
			Path: c.prepared.diskPath, SHA256: a.Candidate.ArtifactSHA256,
			Metadata: map[string]string{"sha256": a.Candidate.ArtifactSHA256, "approval": c.prepared.approvalSHA256}, PartSize: 32 << 20, Parallelism: 2})
		if err != nil {
			return j, err
		}
	}
	if j.ImageID == "" {
		if err := c.check(ctx, false); err != nil {
			return j, err
		}
		if err := c.intent(path, &j, "image"); err != nil {
			return j, err
		}
		response, err := c.compute.CreateImage(ociclient.RequestContext(ctx), core.CreateImageRequest{CreateImageDetails: core.CreateImageDetails{
			CompartmentId: new(a.Compartment), DisplayName: new(c.name("image")), FreeformTags: c.tags(),
			LaunchMode: core.CreateImageDetailsLaunchModeParavirtualized,
			ImageSourceDetails: core.ImageSourceViaObjectStorageTupleDetails{NamespaceName: new(a.Namespace), BucketName: new(a.Bucket),
				ObjectName: new(j.Object), SourceImageType: core.ImageSourceDetailsSourceImageTypeQcow2,
				OperatingSystem: new("Custom"), OperatingSystemVersion: new("Custom")}}, OpcRetryToken: new(c.token("image"))})
		if err != nil {
			return j, err
		}
		if response.Id == nil || *response.Id == "" {
			return j, errors.New("created qualification image has no ID")
		}
		j.ImageID = *response.Id
		if err := checkpoint(path, j); err != nil {
			return j, err
		}
	}
	if err := c.waitImage(ctx, j.ImageID); err != nil {
		return j, err
	}
	for _, host := range a.Hosts {
		if j.Hosts[host.Name] != "" {
			continue
		}
		if err := c.check(ctx, false); err != nil {
			return j, err
		}
		if err := c.intent(path, &j, host.Name); err != nil {
			return j, err
		}
		response, err := c.compute.LaunchInstance(ociclient.RequestContext(ctx), core.LaunchInstanceRequest{LaunchInstanceDetails: core.LaunchInstanceDetails{
			AvailabilityDomain: new(host.AvailabilityDomain), FaultDomain: new(host.FaultDomain), CompartmentId: new(a.Compartment),
			DisplayName: new(c.name(host.Name)), Shape: new(host.Shape), FreeformTags: c.tags(),
			ShapeConfig:       &core.LaunchInstanceShapeConfigDetails{Ocpus: new(host.OCPUs), MemoryInGBs: new(host.MemoryGB)},
			SourceDetails:     core.InstanceSourceViaImageDetails{ImageId: new(j.ImageID), BootVolumeSizeInGBs: new(host.BootGB)},
			CreateVnicDetails: &core.CreateVnicDetails{SubnetId: new(a.Subnet), AssignPublicIp: new(false), AssignIpv6Ip: new(false)},
			InstanceOptions:   &core.InstanceOptions{AreLegacyImdsEndpointsDisabled: new(true)},
			Metadata:          metadata},
			OpcRetryToken: new(c.token(host.Name))})
		if err != nil {
			return j, err
		}
		if response.Id == nil || *response.Id == "" {
			return j, errors.New("created qualification host has no ID")
		}
		j.Hosts[host.Name] = *response.Id
		if err := checkpoint(path, j); err != nil {
			return j, err
		}
	}
	return j, nil
}

func (c *cloud) token(operation string) string {
	return hashBytes([]byte(c.prepared.approvalSHA256 + "/" + operation))[:32]
}

// Network and principal isolation must already exist before boot: cloud-init
// masking is additional protection, never the authority boundary.
const isolatedBoot = `units="$(systemctl list-unit-files --no-legend 'terrascale-*' 'netbird*' | awk '{print $1}')"
mkdir -p /run/ts-qualification-units
for unit in $units; do
  target="/etc/systemd/system/$unit"
  if [ -f "$target" ] && [ ! -L "$target" ]; then cp -p "$target" "/run/ts-qualification-units/$unit"; fi
  ln -sfn /dev/null "$target"
done
systemctl daemon-reload
if [ -n "$units" ]; then systemctl stop $units; fi`

func (c *cloud) launchMetadata(publicKey string) (map[string]string, error) {
	script := isolatedBoot + "\nprintf '%s\\n' '" + c.prepared.approval.RunID + "' > /run/ts-native-disposable\nchmod 600 /run/ts-native-disposable\n"
	marker := fmt.Sprintf(`ssh-keygen -A; printf 'TSQUAL_HOSTKEY %%s %%s\n' '%s' "$(awk '{print $1 " " $2}' /etc/ssh/ssh_host_ed25519_key.pub)" > /dev/console`, c.prepared.approval.RunID)
	config := map[string]any{"disable_root": false, "ssh_pwauth": false,
		"users":       []any{"default", map[string]any{"name": "root", "ssh_authorized_keys": []string{publicKey}}},
		"bootcmd":     [][]string{{"sh", "-eu", "-c", script}},
		"runcmd":      [][]string{{"sh", "-eu", "-c", marker}},
		"write_files": []map[string]string{{"path": "/etc/ssh/sshd_config.d/00-ts-qualification.conf", "permissions": "0600", "content": "PermitRootLogin prohibit-password\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"}}}
	wire, err := json.Marshal(config, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	return map[string]string{"ssh_authorized_keys": publicKey, "user_data": base64.StdEncoding.EncodeToString(append([]byte("#cloud-config\n"), wire...))}, nil
}

func (c *cloud) image(ctx context.Context, id string) (core.Image, error) {
	r, err := c.compute.GetImage(ociclient.RequestContext(ctx), core.GetImageRequest{ImageId: new(id)})
	if err != nil {
		return core.Image{}, err
	}
	if r.Id == nil || *r.Id != id || r.CompartmentId == nil || *r.CompartmentId != c.prepared.approval.Compartment ||
		r.DisplayName == nil || *r.DisplayName != c.name("image") || !c.owns(r.FreeformTags) {
		return core.Image{}, errors.New("qualification image ownership differs; refusing operation")
	}
	return r.Image, nil
}

func (c *cloud) waitImage(ctx context.Context, id string) error {
	for {
		if err := c.check(ctx, false); err != nil {
			return err
		}
		image, err := c.image(ctx, id)
		if err != nil {
			return err
		}
		if image.LifecycleState == core.ImageLifecycleStateAvailable {
			return nil
		}
		if image.LifecycleState != core.ImageLifecycleStateImporting && image.LifecycleState != core.ImageLifecycleStateProvisioning {
			return fmt.Errorf("qualification image entered %s", image.LifecycleState)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

func isNotFound(err error) bool {
	service, ok := common.IsServiceError(err)
	return ok && service.GetHTTPStatusCode() == 404
}

func (c *cloud) cleanup(ctx context.Context, path string) error {
	j, err := c.load(path)
	if err != nil {
		return err
	}
	if err := c.check(ctx, true); err != nil {
		return err
	}
	a := c.prepared.approval
	unresolved := false
	for operation := range j.Intents {
		if !j.resolved(operation) {
			unresolved = true
		}
	}
	if err := c.cleanupConsole(ctx, path, &j); err != nil {
		return err
	}
	var pending []HostSpec
	for _, host := range a.Hosts {
		id := j.Hosts[host.Name]
		if id == "" || j.Terminated[host.Name] {
			continue
		}
		response, err := c.compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(id)})
		if err != nil && !isNotFound(err) {
			return err
		}
		if err == nil {
			if response.Id == nil || *response.Id != id || response.CompartmentId == nil || *response.CompartmentId != a.Compartment ||
				response.DisplayName == nil || *response.DisplayName != c.name(host.Name) || !c.owns(response.FreeformTags) || response.ImageId == nil || *response.ImageId != j.ImageID {
				return errors.New("qualification host ownership differs; refusing termination")
			}
			if response.LifecycleState != core.InstanceLifecycleStateTerminated {
				if err := c.check(ctx, true); err != nil {
					return err
				}
				_, err = c.compute.TerminateInstance(ociclient.RequestContext(ctx), core.TerminateInstanceRequest{InstanceId: new(id), PreserveBootVolume: new(false)})
				if err != nil && !isNotFound(err) {
					return err
				}
				pending = append(pending, host)
				continue
			}
		}
		j.Terminated[host.Name] = true
		if err := checkpoint(path, j); err != nil {
			return err
		}
	}
	for len(pending) > 0 {
		if err := c.check(ctx, true); err != nil {
			return err
		}
		var next []HostSpec
		for _, host := range pending {
			r, err := c.compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(j.Hosts[host.Name])})
			if err != nil && !isNotFound(err) {
				return err
			}
			if err == nil && r.LifecycleState != core.InstanceLifecycleStateTerminated {
				next = append(next, host)
				continue
			}
			j.Terminated[host.Name] = true
			if err := checkpoint(path, j); err != nil {
				return err
			}
		}
		pending = next
		if len(pending) > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
	}
	if unresolved {
		return errors.New("unresolved create intent: known hosts terminated; retain journal, image and object until authenticated resource recovery")
	}
	if j.ImageID != "" && !j.ImageDeleted {
		_, err := c.image(ctx, j.ImageID)
		if err != nil && !isNotFound(err) {
			return err
		}
		if err == nil {
			if err := c.check(ctx, true); err != nil {
				return err
			}
			if _, err := c.compute.DeleteImage(ociclient.RequestContext(ctx), core.DeleteImageRequest{ImageId: new(j.ImageID)}); err != nil && !isNotFound(err) {
				return err
			}
			for {
				if err := c.check(ctx, true); err != nil {
					return err
				}
				image, err := c.image(ctx, j.ImageID)
				if isNotFound(err) || err == nil && image.LifecycleState == core.ImageLifecycleStateDeleted {
					break
				}
				if err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(3 * time.Second):
				}
			}
		}
		j.ImageDeleted = true
		if err := checkpoint(path, j); err != nil {
			return err
		}
	}
	if !j.ObjectDeleted {
		exists, metadata, err := c.uploader.HeadObject(ctx, a.Namespace, a.Bucket, j.Object)
		if err != nil {
			return err
		}
		if exists {
			if metadata["sha256"] != a.Candidate.ArtifactSHA256 || metadata["approval"] != c.prepared.approvalSHA256 {
				return errors.New("qualification object ownership differs; refusing deletion")
			}
			if err := c.check(ctx, true); err != nil {
				return err
			}
			if _, err := c.objects.DeleteObject(ctx, objectstorage.DeleteObjectRequest{NamespaceName: new(a.Namespace), BucketName: new(a.Bucket), ObjectName: new(j.Object)}); err != nil && !isNotFound(err) {
				return err
			}
		}
		j.ObjectDeleted = true
		return checkpoint(path, j)
	}
	return nil
}
