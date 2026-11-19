package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/ocirelease"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const (
	namespace     = "lane"
	publisherUser = "release-publish"
	publisherPass = "e2e-publisher-secret"
	keyID         = "ocid1.tenancy.oc1..lane/ocid1.user.oc1..lane/aa:bb"
)

var signatureField = regexp.MustCompile(`(\w+)="([^"]*)"`)

type held struct {
	digest  string
	arrived chan struct{}
	release chan struct{}
	once    sync.Once
}

type regionRegistry struct {
	server *httptest.Server
	key    *rsa.PublicKey
	held   atomic.Pointer[held]
	mu     sync.Mutex
	tokens map[string]bool
	issued atomic.Int32
}

func newRegionRegistry(key *rsa.PublicKey, certificate tls.Certificate) *regionRegistry {
	r := &regionRegistry{key: key, tokens: map[string]bool{}}
	backend := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	r.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/20180419/docker/token" {
			r.token(w, request)
			return
		}
		if !r.authorized(request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="lane"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if hold := r.held.Load(); hold != nil && request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/blobs/"+hold.digest) {
			hold.once.Do(func() { close(hold.arrived) })
			select {
			case <-hold.release:
			case <-request.Context().Done():
				return
			}
		}
		backend.ServeHTTP(w, request)
	}))
	r.server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	r.server.StartTLS()
	return r
}

func (r *regionRegistry) hold(binary []byte) *held {
	hold := &held{digest: "sha256:" + hex.EncodeToString(sha256Of(binary)), arrived: make(chan struct{}), release: make(chan struct{})}
	r.held.Store(hold)
	return hold
}

func (r *regionRegistry) repository() string {
	return strings.TrimPrefix(r.server.URL, "https://") + "/" + namespace + "/terrascale/" + ocirelease.Package
}

func (r *regionRegistry) authorized(request *http.Request) bool {
	if user, pass, ok := request.BasicAuth(); ok {
		return user == publisherUser && pass == publisherPass
	}
	token, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	r.mu.Lock()
	defer r.mu.Unlock()
	return ok && r.tokens[token] && (request.Method == http.MethodGet || request.Method == http.MethodHead)
}

func (r *regionRegistry) token(w http.ResponseWriter, request *http.Request) {
	header, ok := strings.CutPrefix(request.Header.Get("Authorization"), "Signature ")
	fields := map[string]string{}
	for _, match := range signatureField.FindAllStringSubmatch(header, -1) {
		fields[match[1]] = match[2]
	}
	lines := []string{}
	for _, name := range strings.Fields(fields["headers"]) {
		switch name {
		case "(request-target)":
			lines = append(lines, "(request-target): "+strings.ToLower(request.Method)+" "+request.URL.RequestURI())
		case "host":
			lines = append(lines, "host: "+request.Host)
		default:
			lines = append(lines, name+": "+request.Header.Get(name))
		}
	}
	signature, err := base64.StdEncoding.DecodeString(fields["signature"])
	digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	date, dateErr := http.ParseTime(request.Header.Get("Date"))
	if !ok || err != nil || dateErr != nil || time.Since(date).Abs() > 5*time.Minute || fields["keyId"] != keyID || !slices.Equal(strings.Fields(fields["headers"]), []string{"date", "(request-target)", "host"}) ||
		request.URL.Query().Get("scope") != "repository:"+namespace+"/terrascale/"+ocirelease.Package+":pull" || rsa.VerifyPKCS1v15(r.key, crypto.SHA256, digest[:], signature) != nil {
		http.Error(w, "request not signed by the instance principal", http.StatusUnauthorized)
		return
	}
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	token := hex.EncodeToString(raw)
	r.mu.Lock()
	r.tokens[token] = true
	r.mu.Unlock()
	r.issued.Add(1)
	must(json.NewEncoder(w).Encode(map[string]any{"token": token, "expires_in": 300}))
}

type offlineGitHub struct {
	server *httptest.Server
	calls  atomic.Int32
}

func newOfflineGitHub() *offlineGitHub {
	g := &offlineGitHub{}
	g.server = httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		g.calls.Add(1)
		panic(http.ErrAbortHandler)
	}))
	g.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	return g
}

func principalKey(work string) (*rsa.PrivateKey, string, tls.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	path := filepath.Join(work, "instance-principal.pem")
	must(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600))
	serving, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lane registry"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &serving.PublicKey, serving)
	must(err)
	must(os.WriteFile(registryCA(path), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return key, path, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: serving}
}

func registryCA(keyFile string) string {
	return filepath.Join(filepath.Dir(keyFile), "registry-ca.pem")
}

func trusting(keyFile string) http.RoundTripper {
	data, err := os.ReadFile(registryCA(keyFile))
	must(err)
	pool := x509.NewCertPool()
	require(pool.AppendCertsFromPEM(data), "the lane registry CA must parse")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	return transport
}

func hostRegional(registryURL, keyFile string, next http.RoundTripper) *ocirelease.Regional {
	return &ocirelease.Regional{Next: next, Discover: func(context.Context) (ocirelease.Registry, error) {
		if registryURL == "-" {
			return ocirelease.Registry{}, errors.New("this lane has no regional release channel")
		}
		data, err := os.ReadFile(keyFile)
		if err != nil {
			return ocirelease.Registry{}, err
		}
		parts := strings.Split(keyID, "/")
		signer := common.DefaultRequestSigner(common.NewRawConfigurationProvider(parts[0], parts[1], "us-sanjose-1", parts[2], string(data), nil))
		trusted := trusting(keyFile)
		client := &appregistry.Client{Host: strings.TrimPrefix(registryURL, "https://"), Namespace: namespace, Prefix: "terrascale", Sign: signer.Sign, Transport: trusted}
		return ocirelease.FromApp(client)
	}}
}

type channelRelease struct {
	published
	signed releaseattest.SignedChannel
	image  ocirelease.Image
}

func (l *lane) verifier() releaseattest.Verifier {
	trusted, err := root.NewTrustedRootFromJSON(l.sigstore.TrustedRoot())
	must(err)
	return releaseattest.Verifier{Root: trusted}
}

func (l *lane) target(ctx context.Context, region string) ocirelease.Target {
	target, err := ocirelease.OpenTarget(ctx, l.registries[region].repository(), &authn.Basic{Username: publisherUser, Password: publisherPass}, trusting(l.keyFile))
	must(err)
	return target
}

func (l *lane) channelRelease(seq uint64, run string, binary, served []byte) channelRelease {
	provenance := l.sigstore.Bundle(sigstore.MainIdentity, l.revision, run, map[string][]byte{asset: binary})
	image := ocirelease.ArtifactImage(map[string][]byte{runtime.GOARCH: served}, provenance)
	document, err := ocirelease.Document(image, l.revision, run, seq, time.Now())
	must(err)
	signed := releaseattest.SignedChannel{Document: document, Bundle: l.sigstore.Bundle(sigstore.MainIdentity, l.revision, run, map[string][]byte{releaseattest.ChannelDocument: document})}
	l.github.mu.Lock()
	l.github.gateBinaries[releaseattest.Tag(l.revision, run)] = map[string]string{runtime.GOARCH: hex.EncodeToString(sha256Of(binary))}
	l.github.mu.Unlock()
	return channelRelease{published: published{tag: releaseattest.Tag(l.revision, run), sha: l.revision, run: run, digest: hex.EncodeToString(sha256Of(binary))}, signed: signed, image: image}
}

func (l *lane) write(ctx context.Context, region string, release channelRelease) time.Time {
	moved, err := ocirelease.Publish(ctx, l.target(ctx, region), l.verifier(), release.image, release.signed, os.Stdout)
	must(err)
	return moved
}

func (l *lane) receive() {
	verifier := releasepush.NewVerifier()
	verifier.JWKSURL = l.github.server.URL + "/jwks"
	l.receivers = map[string]*httptest.Server{}
	for _, region := range []string{"sjc", "fra", "gru"} {
		handler := &releasepush.Handler{Verifier: verifier, Discover: func(ctx context.Context) (releasepush.Discovery, error) {
			return pullrelease.Ask(ctx, l.conn, region)
		}}
		l.receivers[region] = httptest.NewServer(http.HandlerFunc(handler.Announce))
	}
}

func (l *lane) announce(ctx context.Context, region string, release channelRelease) (releasepush.Discovery, error) {
	receiver := l.receivers[region]
	return releasepush.Announce(ctx, receiver.Client(), receiver.URL+releasepush.AnnouncePath, l.github.oidc(l.revision, release.run))
}

func (l *lane) publishChannel(ctx context.Context, release channelRelease) map[string]releasepush.Discovery {
	channel, err := releaseattest.ParseChannel(release.signed.Document)
	must(err)
	discoveries := map[string]releasepush.Discovery{}
	for _, region := range []string{"sjc", "fra", "gru"} {
		moved := l.write(ctx, region, release)
		discovery, err := l.announce(ctx, region, release)
		must(err)
		must(releasepush.Report(discovery, channel.Seq, moved, os.Stdout))
		require(discovery.Owner != "" && discovery.Seq == channel.Seq && discovery.Release == release.tag && discovery.Discovered.Sub(moved) <= 5*time.Second,
			"%s's owner must discover %s within 5s of the registry accepting its channel at %s: %+v", region, release.tag, moved.Format(time.RFC3339Nano), discovery)
		discoveries[region] = discovery
	}
	return discoveries
}

func (l *lane) publishBeforeReceivers(ctx context.Context, release channelRelease) {
	edge := httptest.NewServer(http.NotFoundHandler())
	defer edge.Close()
	channel, err := releaseattest.ParseChannel(release.signed.Document)
	must(err)
	announce := func(ctx context.Context, region string, seq uint64, moved time.Time, output io.Writer) error {
		discovery, err := releasepush.Announce(ctx, edge.Client(), edge.URL+releasepush.AnnouncePath, l.github.oidc(l.revision, release.run))
		if err != nil {
			return err
		}
		return releasepush.Report(discovery, seq, moved, output)
	}
	for _, region := range []string{"sjc", "fra", "gru"} {
		var output bytes.Buffer
		ocirelease.Announced(ctx, announce, region, channel.Seq, l.write(ctx, region, release), io.MultiWriter(os.Stdout, &output))
		require(strings.Contains(output.String(), ocirelease.ErrNoReceiver.Error()), "%s: an edge without the release receiver must leave the publish in place: %s", region, output.String())
	}
}

func (l *lane) pushRaw(ctx context.Context, region string, release channelRelease) releasepush.Discovery {
	target := l.target(ctx, region)
	must(target.Push(release.tag, release.image))
	must(target.Push(ocirelease.Stable, ocirelease.ChannelImage(release.signed)))
	discovery, err := l.announce(ctx, region, release)
	require(discovery.Owner != "" && (err == nil || discovery.Error != ""), "%s's owner must answer the announcement of %s: %+v %v", region, release.tag, discovery, err)
	fmt.Printf("%s: owner %s answered the announcement of %s: seq %d %s %s\n", region, discovery.Owner, release.tag, discovery.Seq, discovery.Release, discovery.Error)
	return discovery
}

func (l *lane) channelReleaseOf(ctx context.Context, region string, release channelRelease) releaseattest.Release {
	resolved, err := ocirelease.Resolve(ctx, l.target(ctx, region).Registry, l.verifier(), release.signed)
	must(err)
	return resolved
}

func (l *lane) seqs(id string) string {
	var metrics bytes.Buffer
	releasepush.WriteReleaseMetrics(&metrics, filepath.Join(l.hosts[id].dir, "state"), filepath.Join(l.hosts[id].dir, "bin", "terrascale-orchestrator"))
	return metrics.String()
}

func (l *lane) channel(ctx context.Context) {
	base := hex.EncodeToString(sha256Of(l.self))
	r100 := l.first
	for _, region := range []string{"sjc", "fra", "gru"} {
		l.waitStatus(ctx, region, region+" records "+r100.tag+" from its channel", complete(r100.published))
	}
	l.requireVersions(ctx, l.revision, base, l.region("sjc", "fra", "gru")...)
	for _, id := range l.region("sjc", "fra", "gru") {
		require(strings.Contains(l.seqs(id), "ts_orch_release_installed_seq 100\n"), "%s must record channel seq 100 for the binary it runs:\n%s", id, l.seqs(id))
	}
	fmt.Println("channel seq 100 names the running binary: every host records seq 100 without a restart")

	padding := make([]byte, 2<<20)
	_, _ = rand.Read(padding)
	large := append(append(bytes.Clone(l.self), padding...), []byte("\nCANDIDATE:c117")...)
	r117 := l.channelRelease(117, "117", large, large)
	forged := r117
	forged.signed.Bundle = l.channelRelease(118, "117", large, large).signed.Bundle
	l.pushRaw(ctx, "sjc", forged)
	unsigned := l.waitStatus(ctx, "sjc", "sjc refuses the channel document its bundle does not sign", func(s pullrelease.Status) bool {
		return strings.Contains(s.Reason, "channel document seq 117 differs from its attestation")
	})
	require(unsigned.Phase == pullrelease.PhaseComplete && unsigned.Target != nil && unsigned.Target.Tag() == r100.tag && unsigned.Seq == 100 && unsigned.Channel == 100 && !slices.Contains(unsigned.Bad, r117.tag),
		"an unsigned channel document must change nothing but the reason: %+v", unsigned)
	fmt.Printf("channel document naming %s with a bundle that does not sign it refused without marking the release: %s\n", r117.tag, unsigned.Reason)

	worker := l.hosts["sjc-w"]
	worker.holdRestart()
	worker.kill()
	l.publishChannel(ctx, r117)
	waiting := l.waitStatus(ctx, "sjc", "an unavailable worker holds the first region", func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseWaiting && s.Target != nil && s.Target.Tag() == r117.tag && strings.Contains(s.Reason, "does not answer")
	})
	l.requireVersions(ctx, l.revision, base, l.region("fra", "gru")...)
	worker.releaseRestart()
	for _, region := range []string{"fra", "gru"} {
		l.waitStatus(ctx, region, region+" completes "+r117.tag+" after the worker returns", complete(r117.published))
	}
	l.requireVersions(ctx, l.revision, r117.digest, l.region("sjc", "fra", "gru")...)
	fmt.Printf("unavailable first-region worker blocks later regions; return permits the ordered rollout\n%s\n", waiting)
	fmt.Printf("release %s with %d MiB of change over the installed binary installed from each region's channel after its forged document was refused\n", r117.tag, len(padding)>>20)

	before := l.starts()
	l.pushRaw(ctx, "sjc", r100)
	replayed := l.waitStatus(ctx, "sjc", "sjc refuses the replayed channel seq 100", func(s pullrelease.Status) bool {
		return strings.Contains(s.Reason, "channel seq 100 ("+r100.tag+") is not newer than the region's seq 117")
	})
	require(replayed.Target != nil && replayed.Target.Tag() == r117.tag && replayed.Channel == 117 && !slices.Contains(replayed.Bad, r100.tag),
		"a replayed channel document must change nothing but the reason: %+v", replayed)
	direct := l.ask(ctx, "gru-w", releasepush.PullRequest{Op: releasepush.PullInstall, Release: l.channelReleaseOf(ctx, "gru", r100)})
	require(direct.Refusal != nil && direct.Refusal.Kind == releasepush.RefusalIntegrity && strings.Contains(direct.Refusal.Reason, "channel seq 100 (") && strings.Contains(direct.Refusal.Reason, "not newer than the installed seq 117"),
		"gru-w must refuse the replayed seq itself, replied %+v", direct)
	fmt.Printf("replayed channel seq 100 refused: region %q; host %q\n", replayed.Reason, direct.Refusal.Reason)

	c119 := l.candidate("c119")
	tampered := l.channelRelease(119, "119", c119, append(bytes.Clone(c119[:len(c119)-1]), c119[len(c119)-1]^1))
	l.pushRaw(ctx, "sjc", tampered)
	status := l.waitStatus(ctx, "sjc", "sjc refuses the tampered artifact", func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseRefused && s.Target != nil && s.Target.Tag() == tampered.tag
	})
	require(strings.Contains(status.Reason, "differs from its attestation"), "the tampered artifact refusal lacks its reason: %s", status.Reason)
	fmt.Printf("tampered artifact refused: %s\n", status.Reason)

	l.requireVersions(ctx, l.revision, r117.digest, l.region("sjc", "fra", "gru")...)
	require(slices.Equal(sortedStarts(before), sortedStarts(l.starts())), "no host may restart for a refused channel document: %v -> %v", before, l.starts())
	for _, id := range l.region("sjc", "fra", "gru") {
		require(strings.Contains(l.seqs(id), "ts_orch_release_installed_seq 117\n"), "%s must report installed seq 117:\n%s", id, l.seqs(id))
	}
	for _, id := range []string{"fra-m", "gru-n"} {
		require(strings.Contains(l.seqs(id), "ts_orch_release_channel_seq 117\n"), "%s must report channel seq 117:\n%s", id, l.seqs(id))
	}
	issued := 0
	for _, region := range []string{"sjc", "fra", "gru"} {
		issued += int(l.registries[region].issued.Load())
	}
	require(issued > 0, "hosts must read their channel with registry tokens from signed requests")
	require(l.offline.calls.Load() == 0, "the channel lane made %d GitHub calls", l.offline.calls.Load())
	fmt.Printf("0 GitHub calls; %d registry tokens issued for instance-principal-signed requests; every host reports installed seq 117\n", issued)
	l.discoverDuringInstall(ctx, r117)
	require(l.offline.calls.Load() == 0, "the channel lane made %d GitHub calls", l.offline.calls.Load())
}

func (l *lane) discoverDuringInstall(ctx context.Context, r117 channelRelease) {
	c120, c121 := l.candidate("c120"), l.candidate("c121")
	r120, r121 := l.channelRelease(120, "120", c120, c120), l.channelRelease(121, "121", c121, c121)
	hold := l.registries["sjc"].hold(c120)
	l.publishChannel(ctx, r120)
	select {
	case <-hold.arrived:
	case <-ctx.Done():
		panic("no sjc host downloaded " + r120.tag)
	}
	installing := l.waitStatus(ctx, "sjc", "sjc's owner waits on its install request for "+r120.tag, func(s pullrelease.Status) bool {
		return s.Phase == pullrelease.PhaseRolling && s.Target != nil && s.Target.Tag() == r120.tag && slices.ContainsFunc(s.Hosts, func(row pullrelease.HostProgress) bool { return row.State == pullrelease.HostInstalling })
	})
	fmt.Printf("sjc's owner %s is inside the install request of %s; the lane holds its download\n", installing.Owner, r120.tag)
	discoveries := l.publishChannel(ctx, r121)
	replayed := l.pushRaw(ctx, "sjc", r117)
	require(replayed.Seq == 117, "sjc's owner must read the replayed channel: %+v", replayed)
	restored := l.pushRaw(ctx, "sjc", r121)
	require(restored.Seq == 121 && restored.Discovered.Equal(discoveries["sjc"].Discovered),
		"a replayed older channel must not re-stamp %s: first seen %s, after the replay %s", r121.tag, discoveries["sjc"].Discovered, restored.Discovered)
	fmt.Printf("an older signed channel replayed and %s restored before adoption keep its first sighting %s\n", r121.tag, restored.Discovered.Format(time.RFC3339Nano))
	close(hold.release)
	done := l.waitStatus(ctx, "sjc", "sjc completes "+r121.tag, complete(r121.published))
	require(done.Discovered.Equal(discoveries["sjc"].Discovered), "sjc's rollout of %s must carry the discovery its owner answered, %s, not %s", r121.tag, discoveries["sjc"].Discovered, done.Discovered)
	for _, region := range []string{"fra", "gru"} {
		l.waitStatus(ctx, region, region+" completes "+r121.tag, complete(r121.published))
	}
	l.requireVersions(ctx, l.revision, r121.digest, l.region("sjc", "fra", "gru")...)
	fmt.Printf("%s discovered while sjc's install of %s was held, then rolled out from the same discovery\n", r121.tag, r120.tag)
}

func sortedStarts(starts map[string]int32) []string {
	rows := []string{}
	for id, count := range starts {
		rows = append(rows, fmt.Sprintf("%s=%d", id, count))
	}
	slices.Sort(rows)
	return rows
}
