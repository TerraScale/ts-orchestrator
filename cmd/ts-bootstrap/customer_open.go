package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const maxCustomerReplyBytes = 64 << 10
const maxCustomerSpecBytes = 16 << 10

type customerPreparationReply struct {
	Receipt  managedmaterial.PreparationReceipt `json:"receipt"`
	Customer managedmaterial.CustomerEnvelope   `json:"customer"`
}

// openCustomerMaterialAt authenticates the offline operator reply against the
// original spec and independently pinned controller key before opening it.
func openCustomerMaterialAt(args []string) error {
	flags := flag.NewFlagSet("open-customer-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	replyPath := flags.String("reply", "", "operator material-prepare JSON reply")
	specPath := flags.String("spec", "", "original managed material preparation spec JSON")
	controllerPath := flags.String("controller-key", "", "independently pinned controller Ed25519 public key PEM")
	cell := flags.String("cell", "", "expected regional cell")
	recipientPath := flags.String("recipient-key", "", "owner-only recipient X25519 PKCS#8 private key PEM")
	outputPath := flags.String("out", "", "new owner-only JSON output file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *replyPath == "" || *specPath == "" || *controllerPath == "" || *cell == "" ||
		*recipientPath == "" || *outputPath == "" || !filepath.IsAbs(*outputPath) || flags.NArg() != 0 {
		return errors.New("open-customer-material requires --reply, --spec, --controller-key, --cell, --recipient-key, and absolute --out")
	}
	specWire, err := readBoundedRegular(*specPath, maxCustomerSpecBytes)
	if err != nil {
		return fmt.Errorf("read material preparation spec: %w", err)
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(specWire, &spec, maxCustomerSpecBytes); err != nil {
		return fmt.Errorf("decode material preparation spec: %w", err)
	}
	replyWire, err := readBoundedRegular(*replyPath, maxCustomerReplyBytes)
	if err != nil {
		return fmt.Errorf("read material preparation reply: %w", err)
	}
	var reply customerPreparationReply
	if err := protocol.DecodeStrict(replyWire, &reply, maxCustomerReplyBytes); err != nil {
		return fmt.Errorf("decode material preparation reply: %w", err)
	}
	controllerKey, err := readRootPublicKey(*controllerPath)
	if err != nil {
		return fmt.Errorf("read controller trust pin: %w", err)
	}
	if err := managedmaterial.VerifyPreparationReply(reply.Receipt, reply.Customer,
		controllerKey, *cell, spec.PartitionID, spec); err != nil {
		return fmt.Errorf("verify signed material preparation reply: %w", err)
	}
	recipient, err := readOwnerRecipientKey(*recipientPath)
	if err != nil {
		return err
	}
	material, err := managedmaterial.OpenCustomerEnvelope(spec, reply.Customer, recipient)
	if err != nil {
		return err
	}
	output, err := protocol.EncodeJSON(material)
	if err != nil {
		return err
	}
	defer clear(output)
	return writeNewCustomerMaterial(*outputPath, output)
}

func readOwnerRecipientKey(path string) (*ecdh.PrivateKey, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open recipient key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > maxKeyFileBytes ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("recipient key must be a bounded owner-only regular file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("recipient key must be owned by this process user")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maxKeyFileBytes {
		return nil, errors.New("recipient key cannot be read within its size limit")
	}
	defer clear(wire)
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("recipient key must be X25519 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("recipient key must be X25519 PKCS#8 PEM")
	}
	private, ok := parsed.(*ecdh.PrivateKey)
	if !ok || private.Curve() != ecdh.X25519() {
		return nil, errors.New("recipient key must be X25519 PKCS#8 PEM")
	}
	return private, nil
}

// A complete, synced 0600 temporary file becomes visible at the output path
// through a create-only hard link. Failed writes never publish partial JSON.
func writeNewCustomerMaterial(path string, contents []byte) error {
	if len(contents) == 0 {
		return errors.New("customer material output is empty")
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".ts-bootstrap-customer-*")
	if err != nil {
		return fmt.Errorf("create customer material temporary file: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return fmt.Errorf("publish customer material without overwrite: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		_ = os.Remove(path)
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
