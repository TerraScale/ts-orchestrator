package vmqualruntime

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

type networkController struct {
	mu          sync.Mutex
	plan        vmnet.NetworkPlan
	runner      vmnet.Runner
	journalPath string
	services    qualificationServices
}

// DynamicNetworkController is the live fault surface implemented by the real
// qualification network. The base Stack interface remains lifecycle-only.
type DynamicNetworkController interface {
	vmqual.NetworkController
	Partition(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
	Heal(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
	SetNetem(context.Context, vmnet.FaultSpec) error
	ClearNetem(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
}

func NewNetworkController(config vmnet.Config, runner vmnet.Runner, journalPath string) (vmqual.NetworkController, error) {
	if runner == nil {
		return nil, errors.New("vmqual: network runner is required")
	}
	if journalPath != "" && (!filepath.IsAbs(journalPath) || filepath.Clean(journalPath) == string(filepath.Separator)) {
		return nil, errors.New("vmqual: network journal path must be an absolute file path")
	}
	plan, err := vmnet.Plan(config)
	if err != nil {
		return nil, err
	}
	return &networkController{plan: plan, runner: runner, journalPath: journalPath}, nil
}
func (n *networkController) Apply(ctx context.Context) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	if ctx == nil {
		return errors.New("vmqual: network context is nil")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	var err error
	if n.journalPath != "" {
		err = n.plan.ApplyWithJournal(ctx, n.runner, networkJournalWriter{path: n.journalPath})
	} else {
		err = n.plan.Apply(ctx, n.runner)
	}
	if err != nil {
		return err
	}
	if n.services == nil {
		return nil
	}
	if err := n.services.Start(ctx); err != nil {
		serviceErr := n.services.Close(context.WithoutCancel(ctx))
		cleanupErr := n.plan.CleanupPlan().Run(context.WithoutCancel(ctx), n.runner)
		return errors.Join(fmt.Errorf("vmqual: start qualification services: %w", err), serviceErr, cleanupErr)
	}
	return nil
}
func (n *networkController) Cleanup(ctx context.Context) error {
	if n == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	cleanCtx := context.WithoutCancel(ctx)
	var serviceErr error
	if n.services != nil {
		serviceErr = n.services.Close(cleanCtx)
	}
	planErr := n.plan.CleanupPlan().Run(cleanCtx, n.runner)
	var journalErr error
	if serviceErr == nil && planErr == nil && n.journalPath != "" {
		journalErr = vmqual.RemoveFileAndSync(n.journalPath)
	}
	return errors.Join(serviceErr, planErr, journalErr)
}

func (n *networkController) Partition(ctx context.Context, from, to vmnet.RegionCode) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.Partition(ctx, n.runner, from, to)
}

func (n *networkController) Heal(ctx context.Context, from, to vmnet.RegionCode) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.Heal(ctx, n.runner, from, to)
}

func (n *networkController) SetNetem(ctx context.Context, fault vmnet.FaultSpec) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.SetNetem(ctx, n.runner, fault)
}

func (n *networkController) ClearNetem(ctx context.Context, from, to vmnet.RegionCode) error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.plan.ClearNetem(ctx, n.runner, from, to)
}
func (n *networkController) writeJournal() error {
	if n == nil {
		return errors.New("vmqual: nil network controller")
	}
	return writeNetworkJournal(n.journalPath, n.plan.Journal)
}
func (n *networkController) Plan() vmnet.NetworkPlan {
	if n == nil {
		return vmnet.NetworkPlan{}
	}
	return n.plan
}
func (n *networkController) Journal() vmnet.Journal {
	if n == nil {
		return vmnet.Journal{}
	}
	return n.plan.Journal
}

// ProveGuestExchange sends one random frame through the exact planned smoke
// forward. The host peer binds only the run-owned listener, accepts one
// connection, and closes after returning the same bytes.
func (n *networkController) ProveGuestExchange(ctx context.Context, vm vmqual.VM) error {
	if n == nil || vm == nil {
		return errors.New("vmqual: network exchange requires a controller and VM")
	}
	if ctx == nil {
		return errors.New("vmqual: network exchange context is nil")
	}
	requester, ok := vm.(interface {
		NetworkExchange(context.Context, string, []byte) ([]byte, error)
	})
	if !ok {
		return errors.New("vmqual: guest network-exchange channel is not configured")
	}
	observation, err := vm.Inspect(ctx)
	if err != nil {
		return fmt.Errorf("vmqual: inspect network-exchange guest: %w", err)
	}
	if !observation.Running || !observation.Ready || observation.Region == "" {
		return errors.New("vmqual: network-exchange guest is not ready")
	}

	n.mu.Lock()
	plan := n.plan
	n.mu.Unlock()
	listenerPlan, ok := plan.Listener("smoke")
	if !ok || listenerPlan.Protocol != vmnet.TCP || listenerPlan.Port == 0 {
		return errors.New("vmqual: smoke listener is absent from the network plan")
	}
	endpoint, ok := plan.Endpoint(observation.Region, "smoke")
	if !ok || endpoint.Protocol != vmnet.TCP || endpoint.GuestPort == 0 ||
		endpoint.HostAddress != listenerPlan.Address || endpoint.HostPort != listenerPlan.Port {
		return errors.New("vmqual: smoke endpoint differs from its planned listener")
	}
	expectedSource := ""
	for _, region := range plan.Regions {
		if region.Code == observation.Region {
			expectedSource = region.Uplink.RegionAddress
			break
		}
	}
	if expectedSource == "" {
		return errors.New("vmqual: smoke endpoint Region is absent from the network plan")
	}

	exchangeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hostAddress := net.JoinHostPort(listenerPlan.Address, strconv.Itoa(int(listenerPlan.Port)))
	listener, err := (&net.ListenConfig{}).Listen(exchangeCtx, "tcp4", hostAddress)
	if err != nil {
		return fmt.Errorf("vmqual: bind planned smoke listener: %w", err)
	}
	defer listener.Close()
	stopListener := context.AfterFunc(exchangeCtx, func() { _ = listener.Close() })
	defer stopListener()

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("vmqual: create network challenge: %w", err)
	}
	defer zeroBytes(challenge)
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- serveSmokeExchange(exchangeCtx, listener, expectedSource, challenge)
	}()
	guestAddress := net.JoinHostPort(endpoint.GuestAddress, strconv.Itoa(int(endpoint.GuestPort)))
	response, requestErr := requester.NetworkExchange(exchangeCtx, guestAddress, challenge)
	if requestErr != nil {
		_ = listener.Close()
	}
	peerErr := <-peerResult
	if requestErr != nil || peerErr != nil {
		return errors.Join(requestErr, peerErr)
	}
	if !equalNetworkBytes(response, challenge) {
		return errors.New("vmqual: guest network exchange changed the challenge")
	}
	return nil
}

func serveSmokeExchange(ctx context.Context, listener net.Listener, expectedSource string, challenge []byte) error {
	connection, err := listener.Accept()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("vmqual: accept smoke exchange: %w", err)
	}
	_ = listener.Close()
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
	}
	host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
	if err != nil || host != expectedSource {
		return errors.New("vmqual: smoke exchange arrived outside the planned Region uplink")
	}
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return fmt.Errorf("vmqual: read smoke challenge frame: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > vmguest.MaxNetworkBytes || int(length) != len(challenge) {
		return errors.New("vmqual: smoke challenge frame length is invalid")
	}
	payload := make([]byte, int(length))
	defer zeroBytes(payload)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return fmt.Errorf("vmqual: read smoke challenge: %w", err)
	}
	if !equalNetworkBytes(payload, challenge) {
		return errors.New("vmqual: smoke peer received the wrong challenge")
	}
	binary.BigEndian.PutUint32(header[:], uint32(len(challenge)))
	if err := writeNetworkFrame(connection, header[:]); err != nil {
		return fmt.Errorf("vmqual: write smoke response frame: %w", err)
	}
	if err := writeNetworkFrame(connection, challenge); err != nil {
		return fmt.Errorf("vmqual: write smoke response: %w", err)
	}
	return nil
}

func writeNetworkFrame(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if written < 0 || written > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func equalNetworkBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func (n *networkController) VerifyNoOwnedResources(ctx context.Context) error {
	if n == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("vmqual: network verification context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	plan, services, journalPath := n.plan, n.services, n.journalPath
	n.mu.Unlock()
	var errs []error
	if services != nil {
		errs = append(errs, services.VerifyStopped())
	}
	// Namespace teardown can return before the kernel releases its peer veth
	// and sysfs entry. Observe disappearance within one bounded cleanup window.
	settleCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for _, region := range plan.Regions {
		for _, path := range []string{region.NamespacePath, filepath.Join("/sys/class/net", region.Uplink.RootDevice)} {
			if err := awaitNetworkResourceRemoval(settleCtx, path); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if journalPath != "" {
		if _, err := os.Lstat(journalPath); err == nil {
			errs = append(errs, errors.New("vmqual: network cleanup journal remains"))
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func awaitNetworkResourceRemoval(ctx context.Context, path string) error {
	for {
		_, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("vmqual: owned network resource remains: %s: %w", path, ctx.Err())
		case <-timer.C:
		}
	}
}

type networkJournalWriter struct{ path string }

func (w networkJournalWriter) WriteJournal(_ context.Context, journal vmnet.Journal) error {
	return writeNetworkJournal(w.path, journal)
}
func writeNetworkJournal(path string, journal vmnet.Journal) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("vmqual: network journal path must be absolute")
	}
	if err := vmqual.ValidateNetworkJournal(journal); err != nil {
		return err
	}
	b, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write network journal: %w", err)
	}
	tmp := f.Name()
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("secure network journal: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write network journal: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync network journal: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close network journal: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		syncErr := dir.Sync()
		_ = dir.Close()
		if syncErr != nil {
			return fmt.Errorf("sync network journal directory: %w", syncErr)
		}
	}
	return nil
}

var _ DynamicNetworkController = (*networkController)(nil)
