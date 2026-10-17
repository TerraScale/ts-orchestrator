package rootsecret

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"golang.org/x/sys/unix"
)

// netBirdJournalWriterTLS retains the original key and full installed material
// guard privately; later journal waits must recheck it before every effect.
type netBirdJournalWriterTLS struct {
	config  *tls.Config
	source  NetBirdJournalSource
	store   bootstrapstart.MaterialStore
	expires time.Time
}

func (*netBirdJournalWriterTLS) String() string          { return "NetBird journal writer TLS [redacted]" }
func (writer *netBirdJournalWriterTLS) GoString() string { return writer.String() }

func (writer *netBirdJournalWriterTLS) currentDeadline(ctx context.Context) (time.Time, error) {
	if writer == nil {
		return time.Time{}, ErrDelivery
	}
	return checkNetBirdJournalWriterMaterial(ctx, writer.source, writer.store, writer.expires)
}

func checkNetBirdJournalWriterMaterial(ctx context.Context, s NetBirdJournalSource, store bootstrapstart.MaterialStore, first time.Time) (time.Time, error) {
	if ctx == nil || s.custody == nil || s.manager != nil || os.Geteuid() != 0 || first.IsZero() {
		return time.Time{}, ErrDelivery
	}
	current, err := s.CurrentDeadline(ctx)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	deadline := minDeadline(first, current)
	ctx, stop := netBirdReadContext(ctx, s.original, deadline)
	defer stop()
	inputs, err := bootstrapstart.LoadTrustInputs(s.custody.accepted)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	pins, err := store.RestartPins(s.custody.accepted, inputs.Roots.Historical)
	if err != nil || store.VerifyRestart(ctx, s.custody.accepted, pins) != nil {
		return time.Time{}, ErrDelivery
	}
	if ctx.Err() != nil || s.checkOriginal() != nil || !time.Now().Before(deadline) {
		return time.Time{}, ErrDelivery
	}
	return deadline, nil
}

// openNetBirdJournalWriterTLS loads only the original writer's installed server
// leaf. The listener owner closes all sessions with the retained source context.
func openNetBirdJournalWriterTLS(ctx context.Context, s NetBirdJournalSource) (*netBirdJournalWriterTLS, error) {
	if os.Geteuid() != 0 || ctx == nil || s.custody == nil || s.manager != nil {
		return nil, ErrDelivery
	}
	deadline, err := s.CurrentDeadline(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	ctx, cancel := netBirdReadContext(ctx, s.original, minDeadline(deadline, time.Now().Add(30*time.Second)))
	defer cancel()
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return nil, ErrDelivery
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return nil, ErrDelivery
	}
	store, err := bootstrapstart.NewMaterialStore(nil, uint32(uid), uint32(gid))
	if err != nil {
		return nil, ErrDelivery
	}
	writer := &netBirdJournalWriterTLS{source: s, store: store, expires: deadline}
	fullPins := func(check context.Context) error {
		_, err := writer.currentDeadline(check)
		return err
	}
	if fullPins(ctx) != nil {
		return nil, ErrDelivery
	}
	wires := make(map[string][]byte)
	defer func() {
		for _, wire := range wires {
			clear(wire)
		}
	}()
	for _, name := range []string{"ca.pem", "controller-a-tls-cert.pem", "controller-a-tls-key.pem"} {
		if s.Guard(ctx) != nil {
			return nil, ErrDelivery
		}
		wire, err := readNetBirdJournalWriterTLSFile(name, uint32(uid), uint32(gid))
		wires[name] = wire
		if err != nil || !s.public.matchesFile(name, wire) || s.Guard(ctx) != nil {
			return nil, ErrDelivery
		}
	}
	certificate, err := tls.X509KeyPair(wires["controller-a-tls-cert.pem"], wires["controller-a-tls-key.pem"])
	if err != nil || len(certificate.Certificate) != 2 || !s.public.matchesDER("controller-tls-issuer-cert.pem", certificate.Certificate[1]) {
		return nil, ErrDelivery
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	identity := bootstrapmaterial.ControllerLeafIdentity("GRU", "controller-a", s.underlay.WriterPrivateIP())
	if err != nil || leaf.IsCA || leaf.Subject.CommonName != identity.CommonName || !slices.Equal(leaf.DNSNames, []string{identity.DNSName}) ||
		len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP(identity.IP)) || len(leaf.URIs)+len(leaf.EmailAddresses) != 0 {
		return nil, ErrDelivery
	}
	issuer, err := x509.ParseCertificate(certificate.Certificate[1])
	if err != nil {
		return nil, ErrDelivery
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(wires["ca.pem"]) {
		return nil, ErrDelivery
	}
	intermediates.AddCert(issuer)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: identity.DNSName,
		CurrentTime: time.Now().UTC(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil || len(chains) == 0 {
		return nil, ErrDelivery
	}
	for _, certificate := range chains[0] {
		deadline = minDeadline(deadline, certificate.NotAfter)
	}
	current, err := writer.currentDeadline(ctx)
	deadline = minDeadline(deadline, current)
	if err != nil || ctx.Err() != nil || s.checkOriginal() != nil || !time.Now().Before(deadline) {
		return nil, ErrDelivery
	}
	writer.expires = deadline
	certificate.Leaf = leaf
	config := &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true, Certificates: []tls.Certificate{certificate},
		ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	config.VerifyConnection = func(tls.ConnectionState) error {
		check, stop := netBirdReadContext(s.original, s.original, minDeadline(deadline, time.Now().Add(12*time.Second)))
		defer stop()
		if fullPins(check) != nil || s.checkOriginal() != nil || !time.Now().Before(deadline) {
			return ErrDelivery
		}
		return nil
	}
	writer.config = config
	return writer, nil
}

// All paths and ownership classes are fixed; caller data never names a file.
func readNetBirdJournalWriterTLSFile(name string, serviceUID, serviceGID uint32) ([]byte, error) {
	switch name {
	case "ca.pem", "operator.jwt", "cell.jwt", "controller-tls-issuer-cert.pem", "controller-a-tls-cert.pem":
	case "controller-a-tls-key.pem", "controller-tls-issuer-key.pem", "controller-account-signer.seed":
		serviceUID, serviceGID = 0, 0
	default:
		return nil, ErrDelivery
	}
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrDelivery
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(bootstrapstart.MaterialDirectory, "/"), "/") {
		next, err := unix.Openat(directory, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(directory)
		if err != nil {
			return nil, ErrDelivery
		}
		directory = next
		var stat unix.Stat_t
		if unix.Fstat(directory, &stat) != nil || stat.Uid != 0 || stat.Mode&0o022 != 0 {
			unix.Close(directory)
			return nil, ErrDelivery
		}
	}
	defer unix.Close(directory)
	var stat unix.Stat_t
	if unix.Fstat(directory, &stat) != nil || stat.Gid != 0 || stat.Mode&0o777 != 0o755 {
		return nil, ErrDelivery
	}
	fd, err := unix.Openat(directory, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrDelivery
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != serviceUID || stat.Gid != serviceGID ||
		stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > bootstrap.MaxSecretBytes {
		return nil, ErrDelivery
	}
	wire, err := io.ReadAll(io.LimitReader(file, bootstrap.MaxSecretBytes+1))
	if err != nil || int64(len(wire)) != stat.Size {
		clear(wire)
		return nil, ErrDelivery
	}
	return wire, nil
}
