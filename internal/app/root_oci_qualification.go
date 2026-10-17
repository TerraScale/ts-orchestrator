package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nativerootoci"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/hostadmission"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

const rootOCIQualificationProofLimit = 256 << 10

type rootOCIQualificationChild struct {
	ImageID string `json:"image_id"`
}

// RunRootOCIQualification consumes only the separately signed nonproduction
// admission. It cannot construct a production accepted identity or host session.
func RunRootOCIQualification(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if os.Geteuid() != 0 || len(args) != 0 {
		return errors.New("root-oci-qualification requires root and accepts no arguments")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	wire, err := io.ReadAll(io.LimitReader(input, rootOCIQualificationProofLimit+1))
	if err != nil || len(wire) == 0 || len(wire) > rootOCIQualificationProofLimit {
		return errors.New("root OCI qualification proof is missing or oversized")
	}
	admission, err := hostadmission.ReadAdmission(ctx, wire)
	if err != nil {
		return err
	}
	ctx, stop := context.WithDeadline(ctx, admission.ExpiresAt())
	defer stop()
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	parent, err := rootoci.CaptureProcess(os.Getpid())
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := verifyRootOCIQualificationBinary(parent, admission.BinarySHA256()); err != nil {
		return err
	}
	service, err := rootoci.NewQualificationService(admission)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	var child *rootoci.ProcessWitness
	authorize := func(request context.Context, peer nativerootoci.Peer, operation rootoci.Operation) (rootoci.Lease, error) {
		mu.Lock()
		defer mu.Unlock()
		if child == nil || peer != child.Peer() || peer.UID != uid || peer.GID != gid || !operation.ReadOnly() || ctx.Err() != nil ||
			child.ParentPID() != os.Getpid() || child.Cgroup() != parent.Cgroup() || parent.Verify() != nil || child.Verify() != nil {
			return rootoci.Lease{}, rootoci.ErrUnauthorized
		}
		// A backend may carry its SDK guard; this independent proof must not recurse.
		deadline := admission.ExpiresAt()
		if original, ok := request.Deadline(); ok && original.Before(deadline) {
			deadline = original
		}
		verify, finish := context.WithDeadline(context.Background(), deadline)
		stopRequest := context.AfterFunc(request, finish)
		stopPhase := context.AfterFunc(ctx, finish)
		defer func() { stopRequest(); stopPhase(); finish() }()
		if admission.Guard(verify) != nil || verifyRootOCIQualificationBinary(child, admission.BinarySHA256()) != nil ||
			parent.Verify() != nil || verify.Err() != nil || ctx.Err() != nil {
			return rootoci.Lease{}, rootoci.ErrUnauthorized
		}
		return rootoci.Lease{Context: ctx, Deadline: admission.ExpiresAt(),
			Binding: child.Binding() + ":qualification:" + admission.BindingSHA256()}, nil
	}
	listener, err := rootoci.ListenQualification(ctx, service, authorize, gid)
	if err != nil {
		return err
	}
	defer listener.Close()
	call, err := rootoci.RootCall(ctx)
	if err != nil {
		return err
	}
	local, err := admission.ObserveLocalInstance(ctx, call)
	if err != nil || local.InstanceOCID != admission.InstanceID() || local.ImageOCID != admission.ImageID() || admission.NamespaceSHA256() == "" {
		return errors.New("root qualification local instance or namespace differs from signed proof")
	}
	register := func(pid int) (func(), error) {
		witness, err := rootoci.CaptureProcess(pid)
		if err != nil {
			return nil, err
		}
		if witness.Peer().UID != uid || witness.Peer().GID != gid || witness.ParentPID() != os.Getpid() || witness.Cgroup() != parent.Cgroup() ||
			verifyRootOCIQualificationBinary(witness, admission.BinarySHA256()) != nil || parent.Verify() != nil {
			_ = witness.Close()
			return nil, rootoci.ErrUnauthorized
		}
		mu.Lock()
		child = witness
		mu.Unlock()
		return func() {
			mu.Lock()
			defer mu.Unlock()
			child = nil
			_ = witness.Close()
		}, nil
	}
	readWire, err := runRootOCIQualificationChild(ctx, "root-oci-qualification-read", uid, gid,
		rootOCIQualificationChild{ImageID: admission.ImageID()}, register)
	if err != nil {
		return err
	}
	var result RootOCIQualificationResult
	if json.Unmarshal(readWire, &result, json.RejectUnknownMembers(true)) != nil {
		return errors.New("qualification reader child returned invalid observations")
	}
	probeWire, err := runRootOCIQualificationChild(ctx, "root-oci-qualification-probe", uid, gid,
		rootOCIQualificationChild{}, nil)
	if err != nil {
		return err
	}
	var probes RootOCIQualificationDenials
	if json.Unmarshal(probeWire, &probes, json.RejectUnknownMembers(true)) != nil || !probes.SameUIDProcessDenied || !probes.IMDSDenied ||
		!result.Negative.ProtectedWriteDenied || !result.Negative.RawSignDenied {
		return errors.New("ordinary root OCI qualification probes did not refuse access")
	}
	result.SchemaVersion, result.RootUID, result.PeerUID = 1, uint32(os.Geteuid()), uid
	result.InstanceID, result.ImageID = admission.InstanceID(), admission.ImageID()
	result.BinarySHA256, result.NamespaceSHA256 = admission.BinarySHA256(), admission.NamespaceSHA256()
	result.SourceSHA256, result.Socket = admission.BindingSHA256(), rootoci.SocketPath
	result.Negative.SameUIDProcessDenied, result.Negative.IMDSDenied = probes.SameUIDProcessDenied, probes.IMDSDenied
	if err := admission.Guard(ctx); err != nil || parent.Verify() != nil {
		return errors.New("root qualification authority changed before publication")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}

func verifyRootOCIQualificationBinary(witness *rootoci.ProcessWitness, expected string) error {
	if witness.Verify() != nil || len(expected) != 64 {
		return rootoci.ErrUnauthorized
	}
	file, err := os.Open(witness.ExecutablePath())
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, release.MaxArtifactBytes+1))
	if err != nil || count <= 0 || count > release.MaxArtifactBytes || hex.EncodeToString(hash.Sum(nil)) != expected || witness.Verify() != nil {
		return rootoci.ErrUnauthorized
	}
	return nil
}

func runRootOCIQualificationChild(ctx context.Context, command string, uid, gid uint32, request rootOCIQualificationChild,
	register func(int) (func(), error),
) ([]byte, error) {
	wire, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	child := exec.CommandContext(childCtx, "/proc/self/exe", command)
	child.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	child.Stderr = os.Stderr
	var response bytes.Buffer
	child.Stdout = &identityRekeyBoundedOutput{buffer: &response, remaining: 64 << 10}
	child.Cancel = func() error {
		if err := syscall.Kill(-child.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	child.WaitDelay = time.Second
	stdin, err := child.StdinPipe()
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	if err := child.Start(); err != nil {
		return nil, err
	}
	if register != nil {
		unregister, err := register(child.Process.Pid)
		if err != nil {
			cancel()
			_ = child.Wait()
			return nil, err
		}
		defer unregister()
	}
	if _, err := stdin.Write(wire); err != nil {
		cancel()
		_ = child.Wait()
		return nil, err
	}
	if err := stdin.Close(); err != nil {
		cancel()
		_ = child.Wait()
		return nil, err
	}
	if err := child.Wait(); err != nil {
		return nil, fmt.Errorf("root qualification child failed: %w", err)
	}
	return response.Bytes(), nil
}

// RunRootOCIQualificationReader is an ordinary-UID finite client. An independently
// launched copy has no permission because it is absent from root's private map.
func RunRootOCIQualificationReader(ctx context.Context, command string, args []string, input io.Reader, output io.Writer) error {
	uid, gid, err := controllerServiceIdentity()
	if err != nil || len(args) != 0 || os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return rootoci.ErrUnauthorized
	}
	wire, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(wire) > 4096 {
		return rootoci.ErrInvalid
	}
	var request rootOCIQualificationChild
	if json.Unmarshal(wire, &request, json.RejectUnknownMembers(true)) != nil {
		return rootoci.ErrInvalid
	}
	client := rootoci.NewClient(rootoci.Expectations{})
	var result any
	switch command {
	case "root-oci-qualification-read":
		observed := RootOCIQualificationResult{}
		readers := []struct {
			read func() (any, error)
			into *RootOCIQualificationObservation
		}{
			{func() (any, error) { return client.Inventory(ctx) }, &observed.Readers.Inventory},
			{func() (any, error) { return client.ObserveLocalInstance(ctx) }, &observed.Readers.LocalInstance},
			{func() (any, error) { return client.ObserveFleet(ctx) }, &observed.Readers.Fleet},
			{func() (any, error) { return client.Costs(ctx) }, &observed.Readers.Costs},
			{func() (any, error) { return client.ObserveImage(ctx, rootoci.ImageRequest{ImageID: request.ImageID}) }, &observed.Readers.Image},
			{func() (any, error) { return client.ReleaseChannel(ctx) }, &observed.Readers.ReleaseChannel},
		}
		for _, reader := range readers {
			value, err := reader.read()
			if err != nil {
				return err
			}
			canonical, err := json.Marshal(value, json.Deterministic(true))
			if err != nil {
				return err
			}
			sum := sha256.Sum256(canonical)
			*reader.into = RootOCIQualificationObservation{SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(canonical))}
		}
		_, err := client.ReconcileFoundation(ctx, rootoci.ReconcileFoundationRequest{Cell: "GRU"})
		observed.Negative.ProtectedWriteDenied = errors.Is(err, rootoci.ErrInvalid) || errors.Is(err, rootoci.ErrUnauthorized)
		observed.Negative.RawSignDenied = rootOCIQualificationSigningRefused(ctx)
		if !observed.Negative.ProtectedWriteDenied || !observed.Negative.RawSignDenied {
			return errors.New("qualification child obtained a protected capability")
		}
		result = observed
	case "root-oci-qualification-probe":
		_, err := client.Inventory(ctx)
		denials := RootOCIQualificationDenials{SameUIDProcessDenied: errors.Is(err, rootoci.ErrUnauthorized), IMDSDenied: rootOCIQualificationIMDSRefused(ctx)}
		if !denials.SameUIDProcessDenied || !denials.IMDSDenied {
			return errors.New("unregistered ordinary process retained root or IMDS access")
		}
		result = denials
	default:
		return rootoci.ErrInvalid
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = output.Write(append(encoded, '\n'))
	return err
}

func rootOCIQualificationSigningRefused(ctx context.Context) bool {
	connection, err := new(net.Dialer).DialContext(ctx, "unix", rootoci.SocketPath)
	if err != nil {
		return false
	}
	defer connection.Close()
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		return false
	}
	peer, err := nativerootoci.PeerCredential(socket)
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		return false
	}
	if socket.SetDeadline(time.Now().Add(5*time.Second)) != nil || nativerootoci.WriteBoundedFrame(socket,
		[]byte(`{"version":1,"operation":"raw_sign","expected":{},"payload":{"message":"qualification signing refusal"}}`), 4096) != nil {
		return false
	}
	wire, err := nativerootoci.ReadBoundedFrame(socket, 4096)
	if err != nil {
		return false
	}
	var response struct {
		Version   uint64 `json:"version"`
		Operation string `json:"operation"`
		Status    string `json:"status"`
	}
	return json.Unmarshal(wire, &response, json.RejectUnknownMembers(true)) == nil && response.Version == 1 &&
		response.Operation == "raw_sign" && response.Status == "invalid"
}

func rootOCIQualificationIMDSRefused(ctx context.Context) bool {
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probe, http.MethodGet, "http://169.254.169.254/opc/v2/identity/cert.pem", nil)
	if err != nil {
		return false
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return ctx.Err() == nil
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized
}
