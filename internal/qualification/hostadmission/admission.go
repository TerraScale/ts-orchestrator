package hostadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// StartupReader has no public constructor except independently verified admission.
// It contains no production identity, grant, session or mutation authority.
type StartupReader struct{ state *readerState }
type readerState struct {
	verified verified
	wire     []byte
	roots    trust.Keyring
	factory  *ociclient.Factory
	observer *bootstrapstart.OCIInstanceObserver
	pid      int
}

// ReadAdmission accepts only original purpose-specific signed authority on the
// running imported candidate. No caller can substitute an endpoint or provider.
func ReadAdmission(ctx context.Context, proofWire []byte) (StartupReader, error) {
	if ctx == nil || os.Geteuid() != 0 {
		return StartupReader{}, ErrAdmission
	}
	roots, err := bootstrapstart.LoadImageRoots()
	if err != nil {
		return StartupReader{}, errors.Join(ErrAdmission, err)
	}
	v, err := verifyProof(proofWire, roots, time.Now())
	if err != nil {
		return StartupReader{}, err
	}
	state := &readerState{verified: v, wire: append([]byte(nil), proofWire...), roots: roots, pid: os.Getpid()}
	if err := state.localGuard(ctx); err != nil {
		return StartupReader{}, err
	}
	if catalog.OCIRegion(v.approval.Candidate.Cell) != v.approval.OCIRegion {
		return StartupReader{}, ErrAdmission
	}
	factory, err := ociclient.InstancePrincipal(v.approval.OCIRegion)
	if err != nil {
		return StartupReader{}, err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != v.approval.Tenancy {
		return StartupReader{}, ErrAdmission
	}
	observer, err := bootstrapstart.NewOCIInstanceObserver(oci.Region(v.approval.Candidate.Cell), factory.Provider())
	if err != nil {
		return StartupReader{}, err
	}
	state.factory = factory
	state.observer = observer
	reader := StartupReader{state: state}
	if err := reader.Guard(ctx); err != nil {
		return StartupReader{}, err
	}
	return reader, nil
}

func (s *readerState) localGuard(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || s == nil || os.Geteuid() != 0 || os.Getpid() != s.pid ||
		time.Now().Before(s.verified.issuedAt) || !time.Now().Before(s.verified.deadline) {
		return ErrAdmission
	}
	v, err := verifyProof(s.wire, s.roots, time.Now())
	if err != nil || v.digest != s.verified.digest {
		return ErrAdmission
	}
	a := v.approval
	if runtime.GOARCH != a.Candidate.Architecture || hashFile("/proc/self/exe") != a.BinarySHA256 {
		return ErrAdmission
	}
	var uts unix.Utsname
	if unix.Uname(&uts) != nil {
		return ErrAdmission
	}
	kernel := unix.ByteSliceToString(uts.Release[:])
	if kernel != a.KernelRelease || filepath.Base(kernel) != kernel || hashFile("/boot/vmlinuz-"+kernel) != a.KernelSHA256 {
		return ErrAdmission
	}
	return nil
}

// Guard rechecks original authority, live own IMDS/SDK placement, image and
// authenticated namespace. APP additionally checks its exact supervised child.
func (r StartupReader) Guard(ctx context.Context) error {
	if r.state == nil || r.state.localGuard(ctx) != nil {
		return ErrAdmission
	}
	s := r.state
	bounded, cancel := context.WithDeadline(ctx, s.verified.deadline)
	defer cancel()
	current, err := s.observeCurrent(bounded)
	if err != nil || current.InstanceOCID != s.verified.host.InstanceID {
		return errors.Join(ErrAdmission, err)
	}
	if _, err := s.observeImage(bounded); err != nil {
		return err
	}
	objects, err := s.factory.ObjectStorage()
	if err != nil {
		return err
	}
	response, err := objects.GetNamespace(ociclient.RequestContext(ociclient.WithAuthority(bounded, s.localGuard)), objectstorage.GetNamespaceRequest{CompartmentId: new(s.verified.approval.Tenancy)})
	if err != nil || response.Value == nil || *response.Value != s.verified.approval.Namespace {
		return errors.Join(ErrAdmission, err)
	}
	return s.localGuard(ctx)
}

func (s *readerState) observeCurrent(ctx context.Context) (bootstrapstart.InstanceObservation, error) {
	id, err := bootstrapstart.NewIMDSClient().FetchInstanceID(ctx)
	if err != nil || id != s.verified.host.InstanceID {
		return bootstrapstart.InstanceObservation{}, ErrAdmission
	}
	observation, err := s.observer.ObserveInstance(ctx, id)
	if err != nil || s.matchHost(observation, s.verified.host) != nil {
		return bootstrapstart.InstanceObservation{}, errors.Join(ErrAdmission, err)
	}
	return observation, nil
}

func (s *readerState) matchHost(observation bootstrapstart.InstanceObservation, h BoundHost) error {
	a := s.verified.approval
	for _, spec := range a.Hosts {
		if spec.Name == h.Name {
			if observation.InstanceOCID == h.InstanceID && observation.ImageOCID == h.ImageID && observation.CompartmentOCID == a.Compartment &&
				observation.PrimaryPrivateIP == h.PrivateIP && observation.SubnetOCID == a.Subnet && observation.PrimaryVNIC && len(observation.NSGOCIDs) == 0 &&
				observation.AvailabilityDomain == spec.AvailabilityDomain && observation.FaultDomain == spec.FaultDomain && observation.Shape == spec.Shape && observation.LifecycleState == "RUNNING" {
				return nil
			}
			return ErrAdmission
		}
	}
	return ErrAdmission
}

func (s *readerState) observeImage(ctx context.Context) (core.Image, error) {
	compute, err := s.factory.Compute()
	if err != nil {
		return core.Image{}, err
	}
	response, err := compute.GetImage(ociclient.RequestContext(ociclient.WithAuthority(ctx, s.localGuard)), core.GetImageRequest{ImageId: new(s.verified.host.ImageID)})
	a := s.verified.approval
	i := response.Image
	if err != nil || i.Id == nil || *i.Id != s.verified.host.ImageID || i.CompartmentId == nil || *i.CompartmentId != a.Compartment || i.LifecycleState != core.ImageLifecycleStateAvailable ||
		i.FreeformTags["terrascale-qualification-run"] != a.RunID || i.FreeformTags["terrascale-qualification-approval"] != fingerprint(s.verified.proof.Approval) ||
		i.FreeformTags[imageimport.SHA256Tag] != a.Candidate.ArtifactSHA256 {
		return core.Image{}, errors.Join(ErrAdmission, err)
	}
	return i, nil
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
func (r StartupReader) ExpiresAt() time.Time {
	if r.state == nil {
		return time.Time{}
	}
	return r.state.verified.deadline
}
func (r StartupReader) BindingSHA256() string {
	if r.state == nil {
		return ""
	}
	return r.state.verified.digest
}
func (r StartupReader) BinarySHA256() string {
	if r.state == nil {
		return ""
	}
	return r.state.verified.approval.BinarySHA256
}
func (r StartupReader) InstanceID() string {
	if r.state == nil {
		return ""
	}
	return r.state.verified.host.InstanceID
}
func (r StartupReader) ImageID() string {
	if r.state == nil {
		return ""
	}
	return r.state.verified.host.ImageID
}
func (r StartupReader) NamespaceSHA256() string {
	if r.state == nil {
		return ""
	}
	return fingerprint([]byte(r.state.verified.approval.Namespace))
}
func (r StartupReader) Candidate() release.ProductionExpectation {
	if r.state == nil {
		return release.ProductionExpectation{}
	}
	return r.state.verified.approval.Candidate
}
