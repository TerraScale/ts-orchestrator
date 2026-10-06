// Package workloadspec is the generic workload spec: the fields that TS-563's
// apps and machine configs gain so that any service, TerraScale's own or a
// third party's, deploys with its own requirements and no orchestrator code
// change. MachineSpec extends a machine config and AppSpec an app. The
// package imports no orchestrator package, so the model, the scheduler and
// the host agent can all use it. See docs/generic-workloads.md.
package workloadspec

import (
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"
)

var ErrInvalid = errors.New("invalid workload spec")

var (
	// tokenRE matches internal/machines' names, so a volume or app named
	// here is a valid name there.
	tokenRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	// imageRE is a fully qualified OCI repository: a registry's DNS name, so
	// the runtime never resolves a short name through a search list or
	// reads its local store, and lower-case path components.
	imageRE = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)(?::[0-9]{1,5})?` +
		`(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+$`)
	// pathRE keeps paths free of characters that a systemd directive or a
	// podman mount option would read as syntax.
	pathRE = regexp.MustCompile(`^/?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)
	// kernelPaths are the kernel's filesystems, which no file or volume may
	// cover.
	kernelPaths = []string{"/dev", "/proc", "/sys"}
)

const (
	maxListed     = 64
	maxArgBytes   = 4096
	maxImageBytes = 255
	// maxEncodedBytes keeps a machine record, which carries its config,
	// well inside a NATS message.
	maxEncodedBytes = 128 << 10
	// maxMachines matches machines.MaxMachines.
	maxMachines = 256
	// maxDrainSeconds leaves the host agent unit's 90 s stop timeout room
	// to stop the agent itself once its machines have drained.
	maxDrainSeconds = 60
)

// Artifact is what a machine's admitted artifact is, and so which driver runs
// it. Empty means a binary.
type Artifact string

const (
	// ArtifactBinary is a static executable: the machine runs it.
	ArtifactBinary Artifact = "binary"
	// ArtifactTarball is a gzipped tar archive; the machine runs the
	// command's first entry, a path inside it.
	ArtifactTarball Artifact = "tarball"
	// ArtifactImage is an OCI image whose manifest digest is the machine
	// config's digest.
	ArtifactImage Artifact = "image"
)

// Driver is the host runtime that runs a machine.
type Driver string

const (
	// DriverNative runs a binary or tarball as a sandboxed native process.
	DriverNative Driver = "native"
	// DriverOCI runs an image in a rootless OCI container.
	DriverOCI Driver = "oci"
)

// Driver returns the runtime that runs the artifact.
func (a Artifact) Driver() Driver {
	if a == ArtifactImage {
		return DriverOCI
	}
	return DriverNative
}

// MachineSpec is what a machine config adds for a generic workload.
type MachineSpec struct {
	Artifact Artifact `json:"artifact,omitempty"`
	// Image is the image's repository, such as ghcr.io/acme/web. The
	// machine config's digest pins the manifest, so the runtime pulls
	// <image>@sha256:<digest> and no tag is ever trusted.
	Image string `json:"image,omitempty"`
	// Command replaces the artifact's entrypoint; the config's args follow
	// it. A binary takes none, a tarball needs one whose first entry is a
	// path inside it, an image may have one.
	Command   []string  `json:"command,omitempty"`
	Files     []File    `json:"files,omitempty"`
	Mounts    []Mount   `json:"mounts,omitempty"`
	Lifecycle Lifecycle `json:"lifecycle,omitzero"`
}

// File is a UTF-8 configuration file the runtime places, read-only, in the
// machine before it starts.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Mount places a volume in the machine. The volume itself, its size,
// placement and snapshots, belongs to managed volumes (TS-567).
type Mount struct {
	Volume string `json:"volume"`
	Path   string `json:"path"`
}

// Lifecycle hooks run inside the machine. A hook's first entry is an
// absolute path in the machine, a path inside a tarball, or a name the
// image's PATH resolves. A failing post-start hook fails the start, so
// health rollback sees it; a failing pre-stop hook does not stop the stop.
type Lifecycle struct {
	PostStart []string `json:"post_start,omitempty"`
	PreStop   []string `json:"pre_stop,omitempty"`
	// DrainSeconds is how long a stopping machine has, pre-stop hook
	// included, before it is killed; zero kills it at once.
	DrainSeconds int `json:"drain_seconds,omitzero"`
}

// Validate checks the spec in isolation.
func (m MachineSpec) Validate() error {
	switch m.Artifact {
	case "", ArtifactBinary:
		if m.Image != "" || len(m.Command) != 0 {
			return fmt.Errorf("%w: a binary takes no image or command", ErrInvalid)
		}
	case ArtifactTarball:
		if m.Image != "" || len(m.Command) == 0 || !relativePath(m.Command[0]) {
			return fmt.Errorf("%w: a tarball needs a command whose first entry is a path inside it, and no image", ErrInvalid)
		}
	case ArtifactImage:
		if !validImage(m.Image) {
			return fmt.Errorf("%w: image %q must be a registry's repository without a tag or digest", ErrInvalid, m.Image)
		}
	default:
		return fmt.Errorf("%w: artifact %q", ErrInvalid, m.Artifact)
	}
	for _, argv := range [][]string{m.Command, m.Lifecycle.PostStart, m.Lifecycle.PreStop} {
		if len(argv) > maxListed || slices.ContainsFunc(argv, func(arg string) bool {
			return len(arg) > maxArgBytes || strings.ContainsRune(arg, 0)
		}) || len(argv) != 0 && !m.entrypoint(argv[0]) {
			return fmt.Errorf("%w: command or hook %q", ErrInvalid, argv)
		}
	}
	if m.Lifecycle.DrainSeconds < 0 || m.Lifecycle.DrainSeconds > maxDrainSeconds {
		return fmt.Errorf("%w: drain must be within 0..%d seconds", ErrInvalid, maxDrainSeconds)
	}
	if len(m.Files) > maxListed || len(m.Mounts) > maxListed {
		return fmt.Errorf("%w: too many files or mounts", ErrInvalid)
	}
	// Files and mounts share one namespace: no path may hold another.
	paths := slices.Clone(kernelPaths)
	var volumes []string
	for _, file := range m.Files {
		if !placedPath(file.Path) || slices.ContainsFunc(paths, nests(file.Path)) {
			return fmt.Errorf("%w: file path %q", ErrInvalid, file.Path)
		}
		paths = append(paths, file.Path)
	}
	for _, mount := range m.Mounts {
		if !tokenRE.MatchString(mount.Volume) || slices.Contains(volumes, mount.Volume) {
			return fmt.Errorf("%w: volume %q", ErrInvalid, mount.Volume)
		}
		if !placedPath(mount.Path) || slices.ContainsFunc(paths, nests(mount.Path)) {
			return fmt.Errorf("%w: mount path %q", ErrInvalid, mount.Path)
		}
		paths, volumes = append(paths, mount.Path), append(volumes, mount.Volume)
	}
	// Marshal also refuses text that is not UTF-8.
	encoded, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if len(encoded) > maxEncodedBytes {
		return fmt.Errorf("%w: spec exceeds %d bytes", ErrInvalid, maxEncodedBytes)
	}
	return nil
}

func validImage(image string) bool {
	match := imageRE.FindStringSubmatch(image)
	if len(image) > maxImageBytes || match == nil {
		return false
	}
	// An address would reach a host by IP, such as the instance metadata
	// service, rather than a registry by name.
	_, err := netip.ParseAddr(match[1])
	return err != nil
}

// entrypoint reports whether name may start a process in the machine.
func (m MachineSpec) entrypoint(name string) bool {
	switch {
	case path.IsAbs(name):
		return placedPath(name)
	case m.Artifact == ArtifactTarball:
		return relativePath(name)
	case m.Artifact == ArtifactImage:
		return pathRE.MatchString(name) && !strings.Contains(name, "/") && name != "." && name != ".."
	}
	return false
}

// relativePath is a clean path inside an unpacked artifact.
func relativePath(p string) bool {
	return len(p) <= maxArgBytes && pathRE.MatchString(p) && !path.IsAbs(p) && path.Clean(p) == p &&
		p != "." && p != ".." && !strings.HasPrefix(p, "../")
}

// placedPath is a clean absolute path below the machine's root.
func placedPath(p string) bool {
	return len(p) <= maxArgBytes && pathRE.MatchString(p) && path.IsAbs(p) && path.Clean(p) == p
}

// nests reports whether a path equals p or one of them contains the other.
func nests(p string) func(string) bool {
	return func(other string) bool {
		return other == p || strings.HasPrefix(p, other+"/") || strings.HasPrefix(other, p+"/")
	}
}

// AppSpec is what an app adds for a generic workload. Region pinning and the
// node pool stay on the app; scaling belongs to autoscaling (TS-565).
type AppSpec struct {
	Placement Placement `json:"placement,omitzero"`
	Update    Update    `json:"update,omitzero"`
	Stateful  *Stateful `json:"stateful,omitempty"`
	// DependsOn names apps that must have a started machine in a region
	// before this app's machines first start there.
	DependsOn []string `json:"depends_on,omitempty"`
}

// Placement only tightens the scheduler's own rules, which always keep one
// machine of an app per host.
type Placement struct {
	// MaxPerFailureDomain caps the app's machines in one failure domain of
	// a region; zero leaves spreading to the scheduler.
	MaxPerFailureDomain int `json:"max_per_failure_domain,omitzero"`
}

// Strategy is how an update replaces running machines.
type Strategy string

const (
	// AllAtOnce updates every machine together. It is the default of a
	// stateless app.
	AllAtOnce Strategy = "all-at-once"
	// Rolling updates at most MaxUnavailable machines at a time. It is the
	// default, and the only strategy, of a stateful app.
	Rolling Strategy = "rolling"
)

// Update is how a new version replaces running machines. Every strategy
// rolls back to the previous version when the new one fails its health
// checks.
type Update struct {
	Strategy Strategy `json:"strategy,omitempty"`
	// MaxUnavailable is how many machines a rolling update stops at once;
	// zero means one.
	MaxUnavailable int `json:"max_unavailable,omitzero"`
}

// Stateful marks an app whose machines own data. Quorum is how many of its
// machines in a region must stay started through updates and scale-in.
type Stateful struct {
	Quorum int `json:"quorum"`
}

// Strategy returns the update strategy in effect.
func (a AppSpec) Strategy() Strategy {
	switch {
	case a.Update.Strategy != "":
		return a.Update.Strategy
	case a.Stateful != nil:
		return Rolling
	default:
		return AllAtOnce
	}
}

// Validate checks the spec of the app named app in isolation.
func (a AppSpec) Validate(app string) error {
	if a.Placement.MaxPerFailureDomain < 0 || a.Placement.MaxPerFailureDomain > maxMachines {
		return fmt.Errorf("%w: max per failure domain", ErrInvalid)
	}
	switch a.Update.Strategy {
	case "", AllAtOnce, Rolling:
	default:
		return fmt.Errorf("%w: update strategy %q", ErrInvalid, a.Update.Strategy)
	}
	if a.Update.MaxUnavailable < 0 || a.Update.MaxUnavailable > maxMachines ||
		a.Update.MaxUnavailable != 0 && a.Strategy() != Rolling {
		return fmt.Errorf("%w: max unavailable needs a rolling update within 0..%d", ErrInvalid, maxMachines)
	}
	if a.Stateful != nil {
		if a.Stateful.Quorum < 1 || a.Stateful.Quorum > maxMachines {
			return fmt.Errorf("%w: quorum must be within 1..%d", ErrInvalid, maxMachines)
		}
		// Updating every member together would drop the quorum.
		if a.Strategy() != Rolling {
			return fmt.Errorf("%w: a stateful app updates rolling", ErrInvalid)
		}
	}
	if len(a.DependsOn) > maxListed {
		return fmt.Errorf("%w: too many dependencies", ErrInvalid)
	}
	for index, dependency := range a.DependsOn {
		if !tokenRE.MatchString(dependency) || dependency == app || slices.Contains(a.DependsOn[:index], dependency) {
			return fmt.Errorf("%w: dependency %q", ErrInvalid, dependency)
		}
	}
	return nil
}
