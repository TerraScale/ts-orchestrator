// Command fixturegen emits or verifies a host-only production restart packet.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	json "encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/tests/firecracker/production/fixturegen"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fixturegen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fixturegen <emit|verify|production-preflight|stage> [flags]")
	}
	switch args[0] {
	case "serve":
		return serveSimulators(args[1:])
	case "emit":
		flags := flag.NewFlagSet("emit", flag.ContinueOnError)
		manifestPath := flags.String("manifest", "", "versioned packet manifest recipe")
		materialRoot := flags.String("material", "", "root of prepared signed fixture files")
		sourceRoot := flags.String("source-root", "", "repository tree matching source pins")
		privatePath := flags.String("root-key", "", "offline Ed25519 PKCS#8 PEM signing key")
		publicPath := flags.String("root-cert", "", "trusted Ed25519 public key PEM")
		out := flags.String("out", "", "new packet directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *manifestPath == "" || *materialRoot == "" || *sourceRoot == "" || *privatePath == "" ||
			*publicPath == "" || *out == "" {
			return errors.New("emit requires -manifest, -material, -source-root, -root-key, -root-cert, and -out")
		}
		wire, err := os.ReadFile(*manifestPath)
		if err != nil {
			return err
		}
		var manifest fixturegen.Manifest
		if err := json.Unmarshal(wire, &manifest, json.RejectUnknownMembers(true)); err != nil {
			return fmt.Errorf("decode packet recipe: %w", err)
		}
		if err := rejectKeyInsideMaterial(*materialRoot, *privatePath); err != nil {
			return err
		}
		if err := fixturegen.VerifySourcePins(*sourceRoot, manifest.SourcePins); err != nil {
			return err
		}
		material, err := readMaterial(*materialRoot)
		if err != nil {
			return err
		}
		privateKey, err := readPrivateKey(*privatePath)
		if err != nil {
			return err
		}
		roots, err := readRoots(*publicPath)
		if err != nil {
			return err
		}
		packet, err := fixturegen.EmitPacket(*out, *sourceRoot, manifest, material, privateKey, roots,
			manifest.FixtureNow.AddDate(0, 0, 1))
		if err != nil {
			return err
		}
		fmt.Printf("emitted packet: %d files, %d routes\n", len(packet.Manifest().Files), len(packet.Manifest().Routes))
		return nil
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		packetPath := flags.String("packet", "", "packet directory")
		publicPath := flags.String("root-cert", "", "trusted Ed25519 public key PEM")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *packetPath == "" || *publicPath == "" {
			return errors.New("verify requires -packet and -root-cert")
		}
		roots, err := readRoots(*publicPath)
		if err != nil {
			return err
		}
		packet, err := fixturegen.ValidatePacket(*packetPath, roots, time.Now().UTC())
		if err != nil {
			return err
		}
		fmt.Printf("verified packet: %d files, %d routes\n", len(packet.Manifest().Files), len(packet.Manifest().Routes))
		return nil
	case "production-preflight", "stage":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		packetPath := flags.String("packet", "", "signed production packet directory")
		publicPath := flags.String("root-cert", "", "trusted Ed25519 public key PEM")
		sourceRoot := flags.String("source-root", "", "source tree matching packet pins")
		imageOCID := flags.String("image-ocid", "", "reviewed OCI image identity")
		guestRoot := flags.String("guest-root", "", "mounted disposable guest root for stage")
		slot := flags.String("slot", "", "controller slot for stage")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 || *packetPath == "" || *publicPath == "" ||
			*sourceRoot == "" || *imageOCID == "" {
			return fmt.Errorf("%s requires -packet, -root-cert, -source-root and -image-ocid", args[0])
		}
		if args[0] == "stage" && (*guestRoot == "" || *slot == "") ||
			args[0] == "production-preflight" && (*guestRoot != "" || *slot != "") {
			return fmt.Errorf("%s has invalid guest-root or slot flags", args[0])
		}
		roots, err := readRoots(*publicPath)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		packet, err := fixturegen.ValidatePacket(*packetPath, roots, now)
		if err != nil {
			return err
		}
		if err := fixturegen.VerifyCompletedSourcePins(*sourceRoot, packet.Manifest().SourcePins); err != nil {
			return err
		}
		if _, err := fixturegen.VerifyPacketEmbeddedImage(packet, roots, *imageOCID, now); err != nil {
			return err
		}
		if err := packet.ValidateProductionGuests(now); err != nil {
			return err
		}
		if args[0] == "stage" {
			if err := fixturegen.StageGuest(context.Background(), packet, roots,
				*imageOCID, *sourceRoot, *guestRoot, *slot, now); err != nil {
				return err
			}
			fmt.Printf("staged %s from verified production packet\n", *slot)
			return nil
		}
		fmt.Printf("production packet ready: binary=%s controllers=%d routes=%d\n",
			packet.Manifest().Binary.SHA256, len(packet.Manifest().Controllers), len(packet.Manifest().Routes))
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func rejectKeyInsideMaterial(materialRoot, privatePath string) error {
	material, err := filepath.EvalSymlinks(materialRoot)
	if err != nil {
		return err
	}
	material, err = filepath.Abs(material)
	if err != nil {
		return err
	}
	private, err := filepath.EvalSymlinks(privatePath)
	if err != nil {
		return err
	}
	private, err = filepath.Abs(private)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(material, private)
	if err != nil {
		return err
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("offline root signing key must be outside packet material tree")
	}
	return nil
}

func readMaterial(root string) (map[string][]byte, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("material root must be a real directory")
	}
	material := make(map[string][]byte)
	var totalBytes int64
	err = filepath.WalkDir(root, func(name string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == root || item.IsDir() {
			return nil
		}
		if !item.Type().IsRegular() {
			return fmt.Errorf("material contains nonregular file %q", name)
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		if len(material) >= 2048 {
			return errors.New("material file count exceeds packet bound")
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || info.Size() > 512<<20 || totalBytes+info.Size() > 640<<20 {
			return errors.New("material file size or aggregate bytes exceed packet bound")
		}
		totalBytes += info.Size()
		body, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		material[strings.ReplaceAll(rel, string(os.PathSeparator), "/")] = body
		return nil
	})
	return material, err
}

func readRoots(name string) (trust.Keyring, error) {
	wire, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("trusted root must be one PUBLIC KEY PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("trusted root must be Ed25519")
	}
	return trust.ParseKeyring(key)
}

func readPrivateKey(name string) (ed25519.PrivateKey, error) {
	wire, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("offline root key must be one PKCS#8 PRIVATE KEY PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("offline root key must be Ed25519")
	}
	return key, nil
}
