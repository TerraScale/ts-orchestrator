package testorigin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"golang.org/x/sys/unix"
)

const materialProducerCommand = "test-origin-material"
const materialProducerInputLimit = 4 << 10
const materialProducerParent = "/var/lib/terrascale-orchestrator-testorigin"
const materialProducerSource = materialProducerParent + "/material-source"

type materialProducerRequest struct {
	SchemaVersion int    `json:"schemaVersion"`
	DeploymentID  string `json:"deploymentId"`
	ClusterID     string `json:"clusterId"`
}

type materialProducerReply struct {
	SchemaVersion int                       `json:"schemaVersion"`
	Status        string                    `json:"status"`
	Stage         string                    `json:"stage"`
	Record        *bootstrapmaterial.Record `json:"record,omitzero"`
	RecordSHA256  string                    `json:"recordSha256,omitzero"`
}

// This command produces a local source only; Vault publication, original
// source/writer authority, compiled genesis and installed custody stay absent.
func runMaterialProducer(ctx context.Context, input io.Reader, output io.Writer) int {
	reply, err := produceMaterial(ctx, input)
	wire, encodeErr := json.Marshal(reply)
	if encodeErr != nil || len(wire) > fixtureOutputLimit {
		return 1
	}
	wire = append(wire, '\n')
	if n, writeErr := output.Write(wire); writeErr != nil || n != len(wire) || err != nil {
		return 1
	}
	return 0
}

func produceMaterial(ctx context.Context, input io.Reader) (reply materialProducerReply, err error) {
	reply = materialProducerReply{SchemaVersion: 1, Status: "failed", Stage: "request"}
	if ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return reply, errors.New("material source requires the original root context")
	}
	deadline, bounded := ctx.Deadline()
	remaining := time.Until(deadline)
	if !bounded || remaining <= 0 || remaining > 120*time.Second {
		return reply, errors.New("material source requires a finite original deadline")
	}
	if closer, ok := input.(io.Closer); ok {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stop()
	}
	wire, err := io.ReadAll(io.LimitReader(input, materialProducerInputLimit+1))
	defer clear(wire)
	var request materialProducerRequest
	if err != nil || len(wire) == 0 || protocol.DecodeStrict(wire, &request, materialProducerInputLimit) != nil || request.SchemaVersion != 1 {
		return reply, errors.New("invalid material source input")
	}
	cfg := bootstrapmaterial.Config{Environment: "production", Region: "sa-saopaulo-1", Cell: "gru",
		DeploymentID: request.DeploymentID, ClusterID: request.ClusterID, SubnetCIDR: "10.251.0.0/24", ValidityHours: 24,
		Slots: []bootstrapmaterial.Slot{
			{Name: "controller-a", PrivateIP: "10.251.0.10"},
			{Name: "controller-b", PrivateIP: "10.251.0.11"},
			{Name: "controller-c", PrivateIP: "10.251.0.12"},
		}}
	if err := cfg.Validate(); err != nil {
		return reply, err
	}
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	reply.Stage = "private-parent"
	parent, err := openMaterialProducerParent()
	if err != nil {
		return reply, err
	}
	defer func() {
		if closeErr := parent.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			reply.Status, reply.Stage, reply.Record, reply.RecordSHA256 = "failed", "parent-close", nil, ""
		}
	}()
	parentInfo, err := parent.Stat()
	if err != nil {
		return reply, err
	}
	// An exclusive retained claim prevents Generate's normal replay behavior
	// from crediting a source created by another invocation as this fresh birth.
	reply.Stage = "fresh-source-claim"
	var sourceInfo unix.Stat_t
	if statErr := unix.Fstatat(int(parent.Fd()), filepath.Base(materialProducerSource), &sourceInfo, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, unix.ENOENT) {
		return reply, errors.New("material source must be absent")
	}
	claimFD, err := unix.Openat(int(parent.Fd()), "material-source.claim", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return reply, errors.New("material source requires a fresh exclusive claim")
	}
	claim := os.NewFile(uintptr(claimFD), "test-origin-material-source-claim")
	var claimInfo unix.Stat_t
	if unix.Fstat(claimFD, &claimInfo) != nil || claimInfo.Uid != 0 || claimInfo.Gid != 0 ||
		claimInfo.Mode&unix.S_IFMT != unix.S_IFREG || claimInfo.Mode&0o7777 != 0o600 || claimInfo.Nlink != 1 {
		_ = claim.Close()
		return reply, errors.New("material source claim custody is unsafe")
	}
	claimDigest := sha256.Sum256(wire)
	claimWire := []byte(hex.EncodeToString(claimDigest[:]) + "\n")
	n, writeErr := claim.Write(claimWire)
	claimErr := errors.Join(writeErr, claim.Sync(), claim.Close(), unix.Fsync(int(parent.Fd())))
	if n != len(claimWire) || claimErr != nil {
		return reply, errors.New("material source claim did not durably complete")
	}
	if statErr := unix.Fstatat(int(parent.Fd()), filepath.Base(materialProducerSource), &sourceInfo, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(statErr, unix.ENOENT) {
		return reply, errors.New("material source appeared after its exclusive claim")
	}
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	reply.Stage = "production-generate"
	record, err := bootstrapmaterial.Generate(materialProducerSource, cfg, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return reply, err
	}
	reply.Stage = "production-load-and-validate"
	loaded, err := bootstrapmaterial.Load(materialProducerSource)
	if err != nil || !reflect.DeepEqual(record, loaded) || !reflect.DeepEqual(cfg, loaded.Config) {
		return reply, errors.New("material source readback differs from its original generation")
	}
	if err := bootstrapmaterial.ValidateLive(materialProducerSource, loaded); err != nil {
		return reply, err
	}
	currentParent, err := os.Lstat(materialProducerParent)
	var currentParentInfo unix.Stat_t
	if err != nil || !os.SameFile(parentInfo, currentParent) || currentParent.Mode().Perm() != 0o700 || !currentParent.IsDir() {
		return reply, errors.New("material source parent changed during production")
	}
	if unix.Fstat(int(parent.Fd()), &currentParentInfo) != nil || currentParentInfo.Uid != 0 || currentParentInfo.Gid != 0 || currentParentInfo.Mode&0o7777 != 0o700 {
		return reply, errors.New("material source parent ownership changed during production")
	}
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	publicWire, err := protocol.EncodeJSON(loaded)
	if err != nil {
		return reply, err
	}
	publicDigest := sha256.Sum256(publicWire)
	reply.Record, reply.RecordSHA256 = &loaded, hex.EncodeToString(publicDigest[:])
	reply.Status, reply.Stage = "local-material-produced", "complete"
	return reply, nil
}

func openMaterialProducerParent() (_ *os.File, err error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = unix.Close(fd)
		}
	}()
	for component := range strings.SplitSeq(strings.TrimPrefix(materialProducerParent, "/"), "/") {
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return nil, errors.New("private material parent is absent")
		}
		_ = unix.Close(fd)
		fd = next
		var info unix.Stat_t
		if unix.Fstat(fd, &info) != nil || info.Uid != 0 || info.Gid != 0 || info.Mode&0o022 != 0 {
			return nil, errors.New("private material parent ancestry is unsafe")
		}
	}
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&0o7777 != 0o700 {
		return nil, errors.New("private material parent requires mode0700")
	}
	return os.NewFile(uintptr(fd), "test-origin-material-parent"), nil
}
