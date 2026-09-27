// Command exporter creates one disposable, cryptographically signed two-member
// packet for the managed-member Firecracker qualification driver.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	memberIDs          = [2]string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002"}
	memberIncarnations = [2]string{strings.Repeat("bb", 16), strings.Repeat("cc", 16)}
	memberDNSNames     = [2]string{"member-a.terrabase.test", "member-b.terrabase.test"}
	failureDomains     = [2]string{"FAULT-DOMAIN-1", "FAULT-DOMAIN-2"}
	memberDirs         = [2]string{"/srv/ts-managed/6efe9447512debbf02bcd921c78d666c", "/srv/ts-managed/948d999055329358cc417bcc96edb470"}
	guestIPs           = [2]string{"10.77.39.11", "10.77.39.12"}
	volumeUUIDs        = [2]string{"76f1b43d-7d79-4f41-9a6e-cc1f4aaab102", "76f1b43d-7d79-4f41-9a6e-cc1f4aaab103"}
	lowerSHA256        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fullRevision       = regexp.MustCompile(`^[0-9a-f]{40,64}$`)
)

type inputFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type memberPacket struct {
	Inputs      map[string]inputFile `json:"inputs"`
	GuestConfig map[string]any       `json:"guest_config"`
}

type packetManifest struct {
	Profile       string                  `json:"profile"`
	SourceCommits map[string]string       `json:"source_commits"`
	Inputs        map[string]inputFile    `json:"inputs"`
	Members       map[string]memberPacket `json:"members"`
}

type options struct {
	outputDir, kernel, rootfs, firecracker, goHostTest, tbServer string
	orchestratorRevision, terrabaseRevision, sourceDigest        string
	authoritySeedFile, authorityPublicSHA256                     string
	ephemeralTestSigner                                          bool
}

func main() {
	var cfg options
	flag.StringVar(&cfg.outputDir, "output-dir", "", "new absolute private output directory")
	flag.StringVar(&cfg.kernel, "kernel", "", "pinned Firecracker kernel")
	flag.StringVar(&cfg.rootfs, "rootfs", "", "pinned Firecracker root filesystem")
	flag.StringVar(&cfg.firecracker, "firecracker", "", "pinned Firecracker executable")
	flag.StringVar(&cfg.goHostTest, "go-host-test", "", "pinned host.test executable")
	flag.StringVar(&cfg.tbServer, "tb-server", "", "pinned TerraBase executable")
	flag.StringVar(&cfg.orchestratorRevision, "orchestrator-revision", "", "full source revision of host.test")
	flag.StringVar(&cfg.terrabaseRevision, "terrabase-revision", "", "full source revision of tb-server")
	flag.StringVar(&cfg.sourceDigest, "source-digest", "", "qualified TerraBase source digest for signed desired")
	flag.StringVar(&cfg.authoritySeedFile, "authority-seed-file", "", "protected existing 32-byte Ed25519 authority seed")
	flag.StringVar(&cfg.authorityPublicSHA256, "authority-public-sha256", "", "independent SHA-256 pin of the seed's derived public key")
	flag.BoolVar(&cfg.ephemeralTestSigner, "ephemeral-test-signer", false, "generate and discard an authority signer for disposable local qualification")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "exporter: positional arguments are not accepted")
		os.Exit(2)
	}
	if err := export(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "exporter: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(filepath.Join(cfg.outputDir, "managed-member-serving-manifest.json"))
}

func export(cfg options) (err error) {
	if !filepath.IsAbs(cfg.outputDir) || filepath.Clean(cfg.outputDir) != cfg.outputDir || cfg.outputDir == "/" ||
		!fullRevision.MatchString(cfg.orchestratorRevision) || !fullRevision.MatchString(cfg.terrabaseRevision) ||
		!lowerSHA256.MatchString(cfg.sourceDigest) || (cfg.authoritySeedFile == "") == !cfg.ephemeralTestSigner ||
		(cfg.ephemeralTestSigner && cfg.authorityPublicSHA256 != "") ||
		(cfg.authoritySeedFile != "" && !lowerSHA256.MatchString(cfg.authorityPublicSHA256)) {
		return errors.New("output, source revisions, digest or signer selection is invalid")
	}
	commonPaths := map[string]string{"kernel": cfg.kernel, "rootfs": cfg.rootfs, "firecracker": cfg.firecracker,
		"go_host_test": cfg.goHostTest, "tb_server": cfg.tbServer}
	common := make(map[string]inputFile, len(commonPaths))
	for name, path := range commonPaths {
		common[name], err = record(path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	signer, err := loadAuthoritySigner(cfg)
	if err != nil {
		return err
	}
	defer clear(signer)
	if err := os.Mkdir(cfg.outputDir, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(cfg.outputDir)
		}
	}()
	memberCA, memberCAKey, memberCAPEM, err := newCertificateAuthority("TerraBase managed-member fixture CA")
	if err != nil {
		return err
	}
	clientCA, clientCAKey, clientCAPEM, err := newCertificateAuthority("TerraBase managed-client fixture CA")
	if err != nil {
		return err
	}
	var memberLeaves, clientLeaves [2]memberCertificate
	for index := range memberLeaves {
		memberLeaves[index], err = newLeaf(memberCA, memberCAKey, memberCAPEM, memberDNSNames[index], nil, true)
		if err != nil {
			return err
		}
		clientLeaves[index], err = newLeaf(clientCA, clientCAKey, clientCAPEM, "terrabase-client", net.IPv4(127, 0, 0, 1), false)
		if err != nil {
			return err
		}
	}
	authority, configurationID, schemaDigest, err := signedAuthority(signer, memberLeaves)
	if err != nil {
		return err
	}
	public := signer.Public().(ed25519.PublicKey)
	var keyID [16]byte
	var keySecret [32]byte
	if _, err = rand.Read(keyID[:]); err != nil {
		return err
	}
	if _, err = rand.Read(keySecret[:]); err != nil {
		return err
	}
	defer clear(keySecret[:])
	token := "tbk1." + base64.RawURLEncoding.EncodeToString(keyID[:]) + "." + base64.RawURLEncoding.EncodeToString(keySecret[:])
	verifierInput := append([]byte("TB-APIKEY-V1\x00"), keyID[:]...)
	verifierInput = append(verifierInput, keySecret[:]...)
	verifier := sha256.Sum256(verifierInput)
	registry, err := json.Marshal(map[string]any{"version": 1, "keys": []any{map[string]any{
		"id": base64.RawURLEncoding.EncodeToString(keyID[:]), "verifier_sha256": hex.EncodeToString(verifier[:]),
		"tenant": tenantID, "database": databaseID, "shard": "1", "collections": []string{collectionID},
		"permissions": []string{"read", "write"}, "revoked": false,
	}}})
	if err != nil {
		return err
	}
	manifest := packetManifest{Profile: "managed-member-serving-v1",
		SourceCommits: map[string]string{"orchestrator": cfg.orchestratorRevision, "terrabase": cfg.terrabaseRevision},
		Inputs:        common, Members: make(map[string]memberPacket, 2)}
	for index, name := range []string{"a", "b"} {
		var member memberPacket
		member, err = exportMember(cfg.outputDir, index, authority, public, configurationID, schemaDigest,
			memberLeaves[index], clientLeaves[index], memberCAPEM, clientCAPEM, registry, token, cfg.sourceDigest)
		if err != nil {
			return err
		}
		manifest.Members[name] = member
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeExclusive(filepath.Join(cfg.outputDir, "managed-member-serving-manifest.json"), append(encoded, '\n'))
}

func loadAuthoritySigner(cfg options) (ed25519.PrivateKey, error) {
	if cfg.ephemeralTestSigner {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		return private, err
	}
	if !filepath.IsAbs(cfg.authoritySeedFile) || filepath.Clean(cfg.authoritySeedFile) != cfg.authoritySeedFile {
		return nil, errors.New("authority seed path must be clean and absolute")
	}
	if !lowerSHA256.MatchString(cfg.authorityPublicSHA256) {
		return nil, errors.New("authority public key SHA-256 pin is required")
	}
	info, err := os.Lstat(cfg.authoritySeedFile)
	if err != nil {
		return nil, err
	}
	if err := checkAuthoritySeedInfo(info); err != nil {
		return nil, err
	}
	fd, err := unix.Open(cfg.authoritySeedFile, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), cfg.authoritySeedFile)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("authority seed changed before reading")
	}
	if err := checkAuthoritySeedInfo(opened); err != nil {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := io.ReadFull(file, seed); err != nil {
		return nil, err
	}
	after, err := os.Lstat(cfg.authoritySeedFile)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("authority seed changed while reading")
	}
	if err := checkAuthoritySeedInfo(after); err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(seed)
	publicHash := sha256.Sum256(private.Public().(ed25519.PublicKey))
	pinnedHash, err := hex.DecodeString(cfg.authorityPublicSHA256)
	if err != nil || subtle.ConstantTimeCompare(publicHash[:], pinnedHash) != 1 {
		clear(private)
		return nil, errors.New("authority public key does not match the independent pin")
	}
	return private, nil
}

func checkAuthoritySeedInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode() != 0600 || info.Size() != ed25519.SeedSize {
		return errors.New("authority seed must be a protected 32-byte regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return errors.New("authority seed must be owned by root or the current user")
	}
	return nil
}

func record(path string) (inputFile, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return inputFile{}, errors.New("input path must be clean and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return inputFile{}, err
	}
	if !info.Mode().IsRegular() {
		return inputFile{}, errors.New("input is not a direct regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return inputFile{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return inputFile{}, errors.New("input changed before hashing")
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return inputFile{}, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return inputFile{}, errors.New("input changed while hashing")
	}
	return inputFile{Path: path, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func writeExclusive(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	count, err := file.Write(content)
	if err != nil {
		_ = file.Close()
		return err
	}
	if count != len(content) {
		_ = file.Close()
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func makeVolume(path, uuid string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := file.Truncate(256 << 20); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	command := exec.Command("mkfs.ext4", "-q", "-F", "-U", uuid, path)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("format fixture volume: %w: %s", err, output)
	}
	return nil
}
