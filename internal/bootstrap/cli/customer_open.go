package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const maxCustomerReplyBytes = 64 << 10
const maxCustomerSpecBytes = 16 << 10
const maxCredentialReplyBytes = 512 << 10
const maxCredentialRequestBytes = 16 << 10

type customerPreparationReply struct {
	Receipt  managedmaterial.PreparationReceipt `json:"receipt"`
	Customer managedmaterial.CustomerEnvelope   `json:"customer"`
}

type customerCredentialReply struct {
	Credential managedmaterial.CredentialReply `json:"credential"`
	Status     string                          `json:"status"`
}

// openRotatedCustomerMaterialAt authenticates a pending rotation receipt and
// its original intent before opening the encrypted token for its recipient.
func (c command) openRotatedCustomerMaterialAt(args []string) error {
	flags := flag.NewFlagSet("open-rotated-customer-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	replyPath := flags.String("reply", "", "operator material-credentials JSON reply")
	requestPath := flags.String("request", "", "original credential rotation intent JSON")
	specPath := flags.String("spec", "", "independently retained generation-one material spec JSON")
	controllerPath := flags.String("controller-key", "", "independently pinned controller Ed25519 public key PEM")
	cell := flags.String("cell", "", "expected regional cell")
	recipientPath := flags.String("recipient-key", "", "owner-only rotation recipient X25519 PKCS#8 private key PEM")
	outputPath := flags.String("out", "", "new owner-only JSON output file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *replyPath == "" || *requestPath == "" || *specPath == "" || *controllerPath == "" ||
		*cell == "" || *recipientPath == "" || *outputPath == "" || !filepath.IsAbs(*outputPath) || flags.NArg() != 0 {
		return errors.New("open-rotated-customer-material requires --reply, --request, --spec, --controller-key, --cell, --recipient-key, and absolute --out")
	}
	specWire, err := c.readBoundedRegular(*specPath, maxCustomerSpecBytes)
	if err != nil {
		return fmt.Errorf("read initial material spec: %w", err)
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(specWire, &spec, maxCustomerSpecBytes); err != nil {
		return fmt.Errorf("decode initial material spec: %w", err)
	}
	requestWire, err := c.readBoundedRegular(*requestPath, maxCredentialRequestBytes)
	if err != nil {
		return fmt.Errorf("read credential rotation intent: %w", err)
	}
	var request managedmaterial.CredentialRequest
	if err := protocol.DecodeStrict(requestWire, &request, maxCredentialRequestBytes); err != nil {
		return fmt.Errorf("decode credential rotation intent: %w", err)
	}
	if request.Action != managedmaterial.CredentialRotate {
		return errors.New("credential intent is not a rotation")
	}
	replyWire, err := c.readBoundedRegular(*replyPath, maxCredentialReplyBytes)
	if err != nil {
		return fmt.Errorf("read credential rotation reply: %w", err)
	}
	var reply customerCredentialReply
	if err := protocol.DecodeStrict(replyWire, &reply, maxCredentialReplyBytes); err != nil {
		return fmt.Errorf("decode credential rotation reply: %w", err)
	}
	if reply.Status != "pending" || reply.Credential.Receipt.Customer == nil {
		return errors.New("credential rotation reply has no pending customer token")
	}
	controllerKey, err := readRootPublicKey(*controllerPath)
	if err != nil {
		return fmt.Errorf("read controller trust pin: %w", err)
	}
	if err := managedmaterial.VerifyCredentialReply(reply.Credential, request, controllerKey, *cell); err != nil {
		return fmt.Errorf("verify signed credential rotation reply: %w", err)
	}
	retainedSpecWire, err := protocol.EncodeJSON(reply.Credential.Initial.Spec)
	if err != nil {
		return err
	}
	expectedSpecWire, err := protocol.EncodeJSON(spec)
	if err != nil || !bytes.Equal(retainedSpecWire, expectedSpecWire) {
		return errors.New("retained initial material spec differs from signed receipt")
	}
	recipient, err := managedmaterial.ReadRecipientKey(*recipientPath)
	if err != nil {
		return err
	}
	spec.Recipient = request.Recipient
	material, err := managedmaterial.OpenCustomerEnvelope(spec, *reply.Credential.Receipt.Customer, recipient)
	if err != nil {
		return err
	}
	output, err := protocol.EncodeJSON(material)
	if err != nil {
		return err
	}
	defer clear(output)
	return c.writeNewCustomerMaterial(*outputPath, output)
}

// openCustomerMaterialAt authenticates the offline operator reply against the
// original spec and independently pinned controller key before opening it.
func (c command) openCustomerMaterialAt(args []string) error {
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
	specWire, err := c.readBoundedRegular(*specPath, maxCustomerSpecBytes)
	if err != nil {
		return fmt.Errorf("read material preparation spec: %w", err)
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(specWire, &spec, maxCustomerSpecBytes); err != nil {
		return fmt.Errorf("decode material preparation spec: %w", err)
	}
	replyWire, err := c.readBoundedRegular(*replyPath, maxCustomerReplyBytes)
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
	recipient, err := managedmaterial.ReadRecipientKey(*recipientPath)
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
	return c.writeNewCustomerMaterial(*outputPath, output)
}

// A complete, synced 0600 temporary file becomes visible at the output path
// through a create-only hard link. Failed writes never publish partial JSON.
func (c command) writeNewCustomerMaterial(path string, contents []byte) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
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
	if err := c.ctx.Err(); err != nil {
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
