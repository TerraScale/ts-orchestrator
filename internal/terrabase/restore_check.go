package terrabase

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/storage/hostvolume"
	"golang.org/x/sys/unix"
)

// restoreBodyLimit bounds every response body restore-check reads.
const restoreBodyLimit = 1 << 20

var (
	documentPathRE = regexp.MustCompile(`^/v1/projects/([^/]+)/databases/([^/]+)/collections/([^/]+)/documents/([^/]+)$`)
	pathSegmentRE  = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
)

// restoreCheckRequest is one resolved restore-check command; it is printed
// as is without --apply.
type restoreCheckRequest struct {
	Step            string `json:"step"`
	Apply           bool   `json:"apply"`
	Plan            string `json:"plan"`
	Compartment     string `json:"compartment"`
	Device          string `json:"device"`
	ScratchInstance string `json:"scratch_instance"`
	RestoredVolume  string `json:"restored_volume"`
	Binary          string `json:"binary"`
	DatabaseID      string `json:"database_id"`
	Document        string `json:"document"`
	ReadyPath       string `json:"ready_path"`
	organization    string
	project         string
	id              string
	wait            time.Duration
}

// runRestoreCheck proves an OCI volume backup restorable: on a scratch host
// with the restored volume attached it mounts the volume, starts the release
// binary on it as a single member and reads one known document through a
// read-only API key.
func runRestoreCheck(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("terrabase restore-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	plan := flags.String("plan", "", "cell plan that scopes the restored volume's OCI reads")
	compartment := flags.String("compartment", "", "workload compartment OCID; defaults to the plan's resource_ids.workload_compartment")
	binary := flags.String("binary", "", "terrabase-linux-<arch> release asset with its .sha256 asset beside it")
	organization := flags.String("organization", "", "organization ID that owns --document")
	database := flags.String("database", "", "database ID that owns --document; the URL uses its name")
	document := flags.String("document", "", "/v1/projects/P/databases/D/collections/C/documents/ID that must exist in the backup")
	scratch := flags.String("scratch-instance", "", "OCID of this scratch instance, as restore-volume printed it")
	restored := flags.String("restored-volume", "", "exact restored copy volume_id printed by restore-volume")
	readyPath := flags.String("ready-path", "/readyz", "client HTTPS path that answers 200 once the member serves requests")
	wait := flags.Duration("wait", 2*time.Minute, "how long the member may take to answer --ready-path")
	apply := flags.Bool("apply", false, "mount the device and start the binary; without it only print the plan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *plan == "" || *binary == "" || *organization == "" || *database == "" || *document == "" || *scratch == "" || *restored == "" {
		return errors.New("restore-check requires --plan, --binary, --organization, --database, --document, --scratch-instance and --restored-volume")
	}
	request, err := resolveRestoreCheck(*binary, *organization, *database, *document, *scratch, *restored, *readyPath, *wait, *apply)
	if err != nil {
		return err
	}
	if _, err := VerifyRelease(request.Binary, request.Binary+".sha256"); err != nil {
		return err
	}
	config, err := restoreVolumeConfig(*plan, *compartment)
	if err != nil {
		return err
	}
	request.Plan, request.Compartment = *plan, config.CompartmentID
	var result any = request
	if request.Apply {
		volumes, err := oci.NewOperatorMemberVolumes(config)
		if err != nil {
			return err
		}
		etag, err := applyRestoreCheck(ctx, request, volumes.VerifyRestoredAttachment)
		if err != nil {
			return err
		}
		result = struct {
			Step      string `json:"step"`
			ReadyPath string `json:"ready_path"`
			Document  string `json:"document"`
			VolumeID  string `json:"volume_id"`
			ETag      string `json:"etag"`
		}{"verified", request.ReadyPath, request.Document, request.RestoredVolume, etag}
	}
	wire, err := json.Marshal(result)
	if err == nil {
		_, err = fmt.Fprintf(output, "%s\n", wire)
	}
	return err
}

func restoreVolumeConfig(planPath, compartment string) (oci.MemberVolumeConfig, error) {
	wire, err := os.ReadFile(planPath)
	if err != nil {
		return oci.MemberVolumeConfig{}, err
	}
	var plan cellPlan
	if err := json.Unmarshal(wire, &plan); err != nil {
		return oci.MemberVolumeConfig{}, fmt.Errorf("decode cell plan: %w", err)
	}
	if compartment == "" {
		compartment = plan.ResourceIDs.WorkloadCompartment
	}
	region := oci.Region(plan.Cell)
	if _, err := region.OCIRegion(); err != nil {
		return oci.MemberVolumeConfig{}, err
	}
	if compartment == "" || plan.AvailabilityDomain == "" {
		return oci.MemberVolumeConfig{}, errors.New("restore-check needs the plan's availability_domain and a workload compartment (--compartment until the plan records it)")
	}
	return oci.MemberVolumeConfig{Region: region, CompartmentID: compartment, AvailabilityDomain: plan.AvailabilityDomain, VPUsPerGB: plan.VPUsPerGB}, nil
}

func resolveRestoreCheck(binary, organization, database, document, scratch, restored, readyPath string, wait time.Duration, apply bool) (restoreCheckRequest, error) {
	match := documentPathRE.FindStringSubmatch(document)
	if match == nil || !entityid.Valid(match[1]) || !pathSegment(match[2]) || !pathSegment(match[3]) || !entityid.Valid(match[4]) {
		return restoreCheckRequest{}, fmt.Errorf("--document %q is not /v1/projects/P/databases/D/collections/C/documents/ID", document)
	}
	if !entityid.Valid(organization) {
		return restoreCheckRequest{}, fmt.Errorf("--organization %q is not a canonical ULID", organization)
	}
	if !entityid.Valid(database) {
		return restoreCheckRequest{}, fmt.Errorf("--database %q is not a canonical ULID", database)
	}
	if !strings.HasPrefix(scratch, "ocid1.instance.") || strings.ContainsAny(scratch, " \t\r\n/") {
		return restoreCheckRequest{}, fmt.Errorf("--scratch-instance %q is not an instance OCID", scratch)
	}
	if !strings.HasPrefix(restored, "ocid1.volume.") || strings.ContainsAny(restored, " \t\r\n/") {
		return restoreCheckRequest{}, fmt.Errorf("--restored-volume %q is not a volume OCID", restored)
	}
	if !strings.HasPrefix(readyPath, "/") {
		return restoreCheckRequest{}, fmt.Errorf("--ready-path %q is not an absolute path", readyPath)
	}
	for _, segment := range strings.Split(readyPath[1:], "/") {
		if !pathSegment(segment) {
			return restoreCheckRequest{}, fmt.Errorf("--ready-path %q is not a plain path", readyPath)
		}
	}
	if wait <= 0 {
		return restoreCheckRequest{}, errors.New("--wait must be positive")
	}
	// A bare asset name would make exec search PATH instead of running the
	// file VerifyRelease checked.
	binary, err := filepath.Abs(binary)
	if err != nil {
		return restoreCheckRequest{}, err
	}
	return restoreCheckRequest{Step: "plan", Apply: apply, Device: oci.RestoreVolumeDevice, ScratchInstance: scratch, RestoredVolume: restored, Binary: binary, Document: document,
		ReadyPath: readyPath, DatabaseID: database, organization: organization, project: match[1], id: match[4], wait: wait}, nil
}

func pathSegment(segment string) bool {
	return pathSegmentRE.MatchString(segment) && segment != "." && segment != ".."
}

// applyRestoreCheck mounts the device on a temporary member layout, starts
// the binary on it and verifies the document. It always stops the binary,
// unmounts the device and removes the layout, joining any cleanup error.
func applyRestoreCheck(ctx context.Context, request restoreCheckRequest, verifyAttachment func(context.Context, string, string) (oci.Attachment, error)) (etag string, err error) {
	if err := requireScratchInstance(ctx, request.ScratchInstance); err != nil {
		return "", err
	}
	device, err := admitRestoredDevice(request.Device)
	if err != nil {
		return "", err
	}
	defer unix.Close(device)
	root, err := os.MkdirTemp("", "terrabase-restore-check-")
	if err != nil {
		return "", err
	}
	layout := Layout(root)
	mounted := false
	defer func() {
		if mounted {
			if unmountErr := unix.Unmount(layout.Data(), 0); unmountErr != nil {
				// Removing root now would delete the restored volume's data.
				err = errors.Join(err, fmt.Errorf("unmount %s: %w; %s is left in place", layout.Data(), unmountErr, root))
				return
			}
		}
		err = errors.Join(err, os.RemoveAll(root))
	}()
	for _, dir := range []string{layout.Data(), layout.Bundle(), layout.TLS()} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return "", err
		}
	}
	if err := mountRestoredDevice(ctx, request, device, layout, verifyAttachment); err != nil {
		return "", err
	}
	mounted = true
	if _, err := writeRestoreIdentity(layout, time.Now()); err != nil {
		return "", err
	}
	return checkMountedRestore(ctx, request, device, layout, verifyAttachment)
}

// mountRestoredDevice re-reads OCI provenance immediately before mounting the
// pinned device. An attachment swapped after restore-volume fails here.
func mountRestoredDevice(ctx context.Context, request restoreCheckRequest, device int, layout Layout,
	verifyAttachment func(context.Context, string, string) (oci.Attachment, error)) error {
	if err := verifyRestoredDevice(ctx, request, device, verifyAttachment); err != nil {
		return fmt.Errorf("verify restored volume before mount: %w", err)
	}
	// Never formatted: a device that does not mount as ext4 fails the check.
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", device), layout.Data(), storage.FileSystemExt4, hostvolume.MountFlags,
		hostvolume.FilesystemData(storage.FileSystemExt4)); err != nil {
		return fmt.Errorf("mount %s: %w", request.Device, err)
	}
	return nil
}

func checkMountedRestore(ctx context.Context, request restoreCheckRequest, device int, layout Layout,
	verifyAttachment func(context.Context, string, string) (oci.Attachment, error)) (string, error) {
	if err := verifyRestoredDevice(ctx, request, device, verifyAttachment); err != nil {
		return "", fmt.Errorf("verify restored volume before starting terrabase: %w", err)
	}
	return checkRestoreInNamespace(ctx, layout, request)
}

func verifyRestoredDevice(ctx context.Context, request restoreCheckRequest, device int,
	verifyAttachment func(context.Context, string, string) (oci.Attachment, error)) error {
	if _, err := verifyAttachment(ctx, request.ScratchInstance, request.RestoredVolume); err != nil {
		return err
	}
	// OCI requests can take seconds. Re-open the current consistent path after
	// them so a replaced local device cannot slip past the earlier admission.
	current, err := unix.Open(request.Device, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("re-open restored device %s: %w", request.Device, err)
	}
	defer unix.Close(current)
	var pinnedStat, currentStat unix.Stat_t
	if err := unix.Fstat(device, &pinnedStat); err != nil {
		return err
	}
	if err := unix.Fstat(current, &currentStat); err != nil {
		return err
	}
	if pinnedStat.Dev != currentStat.Dev || pinnedStat.Ino != currentStat.Ino || pinnedStat.Rdev != currentStat.Rdev ||
		pinnedStat.Mode&unix.S_IFMT != currentStat.Mode&unix.S_IFMT {
		return fmt.Errorf("restored device %s changed during OCI verification", request.Device)
	}
	return nil
}

// checkRestoreMember runs only in the helper's loopback-only network namespace.
// Both the member and all readiness, admin and document traffic inherit it.
func checkRestoreMember(ctx context.Context, layout Layout, request restoreCheckRequest) (etag string, err error) {
	caPEM, err := os.ReadFile(layout.CA())
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	adminPort, clientPort, err := freeLoopbackPorts()
	if err != nil {
		return "", err
	}

	verifyCtx, cancelVerify := context.WithCancelCause(ctx)
	defer cancelVerify(nil)
	processCtx, stop := context.WithCancel(ctx)
	defer stop()
	command := exec.CommandContext(processCtx, request.Binary)
	command.Env = restoreCheckEnv(layout, adminPort, clientPort)
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.Stdout, command.Stderr = os.Stderr, os.Stderr
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 45 * time.Second
	if err := command.Start(); err != nil {
		return "", err
	}
	exited := make(chan error, 1)
	go func() {
		exit := command.Wait()
		cancelVerify(fmt.Errorf("terrabase exited: %v", exit))
		exited <- exit
	}()
	defer func() {
		stop()
		// A member that drains after SIGTERM reports the cancellation.
		if exit := <-exited; exit != nil && !errors.Is(exit, context.Canceled) {
			err = errors.Join(err, fmt.Errorf("stop terrabase: %w", exit))
		}
	}()

	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	return verifyRestore(verifyCtx, client, "http://127.0.0.1:"+strconv.Itoa(adminPort),
		"https://127.0.0.1:"+strconv.Itoa(clientPort), request)
}

// restoreCheckEnv is the single member's environment: the host's base
// environment, the layout's host-owned paths and the loopback ports. It has
// no peer settings; the binary then runs without replication.
func restoreCheckEnv(layout Layout, adminPort, clientPort int) []string {
	return []string{"HOME=/", "LANG=C", "PATH=/usr/bin:/bin",
		EnvDataDirectory + "=" + layout.Data(),
		EnvBundleExtract + "=" + layout.Bundle(),
		EnvAdminPort + "=" + strconv.Itoa(adminPort),
		EnvClientPort + "=" + strconv.Itoa(clientPort),
		EnvClientCertificate + "=" + layout.Certificate(),
		EnvClientPrivateKey + "=" + layout.Key()}
}

// writeRestoreIdentity writes a throwaway member key and a certificate for
// 127.0.0.1 to the layout's TLS directory and returns the PEM of the
// throwaway CA that issued it. The CA key is deleted once it has signed.
func writeRestoreIdentity(layout Layout, now time.Time) ([]byte, error) {
	caPEM, caKey, err := NewCA("restore-check", now)
	if err != nil {
		return nil, err
	}
	caKeyPath := filepath.Join(layout.TLS(), "ca.key")
	if err := os.WriteFile(caKeyPath, caKey, 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(caKeyPath)
	if err := os.WriteFile(layout.CA(), caPEM, 0o600); err != nil {
		return nil, err
	}
	ca, err := LoadCA(layout.CA(), caKeyPath)
	if err != nil {
		return nil, err
	}
	key, csr, err := NewMemberKey()
	if err != nil {
		return nil, err
	}
	certificate, err := ca.Issue(csr, Peer{Name: "restore-check", Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)}, now)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(layout.Key(), key, 0o600); err != nil {
		return nil, err
	}
	return caPEM, os.WriteFile(layout.Certificate(), certificate, 0o600)
}

// freeLoopbackPorts returns two distinct loopback TCP ports that were free a
// moment ago.
func freeLoopbackPorts() (int, int, error) {
	var ports [2]int
	for i := range ports {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, 0, err
		}
		defer listener.Close()
		ports[i] = listener.Addr().(*net.TCPAddr).Port
	}
	return ports[0], ports[1], nil
}

// verifyRestore waits until the client HTTPS listener at clientURL answers the
// ready path, creates a read-only API key for the document's database and
// reads the document from the client listener at clientURL. It returns the
// document's ETag; the key's secret never leaves this function.
func verifyRestore(ctx context.Context, client *http.Client, adminURL, clientURL string, request restoreCheckRequest) (string, error) {
	if err := waitRestoreReady(ctx, client, clientURL, request.ReadyPath, request.wait); err != nil {
		return "", err
	}
	body, err := json.Marshal(struct {
		Name           string   `json:"name"`
		Scopes         []string `json:"scopes"`
		OrganizationID string   `json:"organizationId"`
		ProjectID      string   `json:"projectId"`
		DatabaseID     string   `json:"databaseId"`
	}{"restore-check", []string{"documents:read"}, request.organization, request.project, request.DatabaseID})
	if err != nil {
		return "", err
	}
	response, data, err := restoreCall(ctx, client, http.MethodPost, adminURL+"/admin/api-keys", "", body)
	if err != nil {
		return "", fmt.Errorf("create restore-check API key: %w", err)
	}
	if response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create restore-check API key: HTTP %d %q", response.StatusCode, snippet(data))
	}
	var key struct {
		Secret string `json:"secret"`
	}
	// The decode error is dropped: it could quote the secret.
	if json.Unmarshal(data, &key) != nil || key.Secret == "" {
		return "", errors.New("create restore-check API key: the response has no secret")
	}
	response, data, err = restoreCall(ctx, client, http.MethodGet, clientURL+request.Document, key.Secret, nil)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", request.Document, err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read %s: HTTP %d %q", request.Document, response.StatusCode, snippet(data))
	}
	var document struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return "", fmt.Errorf("read %s: %w", request.Document, err)
	}
	if document.ID != request.id {
		return "", fmt.Errorf("read %s: the document has id %q", request.Document, document.ID)
	}
	return response.Header.Get("ETag"), nil
}

func waitRestoreReady(ctx context.Context, client *http.Client, clientURL, readyPath string, wait time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	for {
		response, data, err := restoreCall(ctx, client, http.MethodGet, clientURL+readyPath, "", nil)
		if err == nil && response.StatusCode == http.StatusOK {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("HTTP %d %q", response.StatusCode, snippet(data))
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("terrabase did not answer %s with HTTP 200 within %s: %w (last: %v)", readyPath, wait, context.Cause(ctx), err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// restoreCall sends one request, with a bearer secret when one is given,
// and returns the response with its body read up to restoreBodyLimit.
func restoreCall(ctx context.Context, client *http.Client, method, url, secret string, body []byte) (*http.Response, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, restoreBodyLimit))
	return response, data, err
}

func snippet(data []byte) string {
	return strings.TrimSpace(string(data[:min(len(data), 512)]))
}

// orchestratorHostConfig marks a host the orchestrator manages; restore-check
// runs only on a scratch host, never next to a member's live data.
const orchestratorHostConfig = "/etc/terrascale-orchestrator/host.json"

// admitRestoredDevice pins the restored volume's block device and admits it
// only on a scratch host, when it is a whole disk other than the boot disk and
// nothing mounts it. The descriptor it returns is what gets mounted.
func admitRestoredDevice(path string) (int, error) {
	if _, err := os.Lstat(orchestratorHostConfig); !errors.Is(err, os.ErrNotExist) {
		return -1, fmt.Errorf("%s exists: restore-check runs only on a scratch host, never on an orchestrator host", orchestratorHostConfig)
	}
	device, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open %s: %w", path, err)
	}
	var stat unix.Stat_t
	err = unix.Fstat(device, &stat)
	if err == nil && stat.Mode&unix.S_IFMT != unix.S_IFBLK {
		err = fmt.Errorf("%s is not a block device", path)
	}
	if err == nil {
		err = hostvolume.RejectBootOrPartitionDevice(stat.Rdev)
	}
	if err == nil {
		var mounted bool
		if mounted, err = hostvolume.BlockDeviceMounted("/proc/self/mountinfo", stat.Rdev); err == nil && mounted {
			err = fmt.Errorf("%s is mounted; a restored volume is checked only while nothing uses it", path)
		}
	}
	if err != nil {
		unix.Close(device)
		return -1, err
	}
	return device, nil
}

// imdsInstanceIDURL is the OCI instance metadata endpoint of this instance's
// OCID.
var imdsInstanceIDURL = "http://169.254.169.254/opc/v2/instance/id"

// requireScratchInstance binds the check to the instance restore-volume
// verified: it holds only the restored volume, at oci.RestoreVolumeDevice.
func requireScratchInstance(ctx context.Context, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsInstanceIDURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer Oracle")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("read this instance's OCID from instance metadata: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 512))
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("read this instance's OCID from instance metadata: HTTP %d: %v", response.StatusCode, err)
	}
	if got := strings.TrimSpace(string(body)); got != want {
		return fmt.Errorf("this instance is %s, not the scratch instance %s that restore-volume verified", got, want)
	}
	return nil
}
