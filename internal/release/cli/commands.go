package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"debug/buildinfo"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	binaryDomain      = release.BinaryDomain
	imageDomain       = release.ImageDomain
	binarySchema      = release.BinarySchema
	imageSchema       = release.ImageSchema
	defaultGoVersion  = release.DefaultGoVersion
	maxKeyFileBytes   = 16 << 10
	maxReceiptBytes   = 1 << 20
	maxArtifactBytes  = release.MaxArtifactBytes
	defaultValidFor   = release.DefaultReceiptValidity
	imageMagicQcow2   = "QFI\xfb"
	linuxAMD64Machine = "Advanced Micro Devices X86-64"
	linuxARM64Machine = "AArch64"
)

type binaryReceipt = release.BinaryReceipt
type imageReceipt = release.ImageReceipt

func (c command) run(args []string) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "sign-delegation":
		return c.signDelegation(args[1:])
	case "binary-candidate":
		return c.binaryCandidate(args[1:])
	case "sign-binary":
		return c.signBinary(args[1:])
	case "verify-binary":
		return c.verifyBinary(args[1:])
	case "image-candidate":
		return c.imageCandidate(args[1:])
	case "sign-image":
		return c.signImage(args[1:])
	case "verify-image":
		return c.verifyImage(args[1:])
	case "publish":
		return c.publish(args[1:])
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: ts-orch release <sign-delegation|binary-candidate|sign-binary|verify-binary|image-candidate|sign-image|verify-image|publish> [flags]")
}

func (c command) publish(args []string) error {
	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("file", "", "release asset to publish")
	region := flags.String("region", "", "OCI region cell: GRU, SFO, or FRA")
	namespace := flags.String("namespace", "", "Object Storage namespace")
	bucket := flags.String("bucket", "", "pre-provisioned immutable release bucket")
	object := flags.String("object", "", "immutable release object name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || !validRegion(*region) || !validStorageToken(*namespace) || !validStorageToken(*bucket) || !validObjectName(*object) || flags.NArg() != 0 {
		return errors.New("publish requires --file, supported --region, --namespace, --bucket, and safe immutable --object")
	}
	asset, size, digest, err := c.openHashedArtifact(*path, maxArtifactBytes)
	if err != nil {
		return err
	}
	defer asset.Close()
	if err := c.ctx.Err(); err != nil {
		return err
	}
	ociRegion := catalog.OCIRegion(*region)
	provider, err := auth.InstancePrincipalConfigurationProviderForRegion(common.Region(ociRegion))
	if err != nil {
		return fmt.Errorf("create OCI instance-principal provider: %w", err)
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		return fmt.Errorf("create OCI Object Storage client: %w", err)
	}
	client.Host = "objectstorage." + ociRegion + ".oraclecloud.com"
	if err := putImmutable(c.ctx, client, *namespace, *bucket, *object, asset, size, digest); err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "published immutable OCI object region=%s bucket=%s name=%s bytes=%d sha256=%x\n", *region, *bucket, *object, size, digest)
	return err
}

type immutableObjectClient interface {
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
}

func putImmutable(ctx context.Context, client immutableObjectClient, namespace, bucket, name string, source io.ReadSeeker, size int64, digest []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if size <= 0 || size > maxArtifactBytes || len(digest) != sha256.Size {
		return errors.New("immutable object size or SHA-256 digest is invalid")
	}
	if _, err := source.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind release asset: %w", err)
	}
	noOverwrite := "*"
	contentType := "application/octet-stream"
	cacheControl := "public, max-age=31536000, immutable"
	checksum := base64.StdEncoding.EncodeToString(digest)
	if err := ctx.Err(); err != nil {
		return err
	}
	_, putErr := client.PutObject(ctx, objectstorage.PutObjectRequest{
		NamespaceName: common.String(namespace), BucketName: common.String(bucket), ObjectName: common.String(name),
		ContentLength: common.Int64(size), PutObjectBody: io.NopCloser(&boundedReadSeeker{source: source, size: size}),
		IfNoneMatch: common.String(noOverwrite), ContentType: common.String(contentType), CacheControl: common.String(cacheControl),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256, OpcContentSha256: common.String(checksum),
	})
	getErr := getExactObjectDigest(ctx, client, namespace, bucket, name, size, digest)
	if getErr != nil {
		if putErr != nil {
			return errors.Join(fmt.Errorf("create immutable release object: %w", putErr), fmt.Errorf("read back release object: %w", getErr))
		}
		return fmt.Errorf("release object upload succeeded but exact read-back failed: %w", getErr)
	}
	if putErr != nil {
		// Conditional create may lose an acknowledgement or find an identical
		// earlier publication. Exact read-back proves this immutable receipt.
		return nil
	}
	return nil
}

type boundedReadSeeker struct {
	source io.ReadSeeker
	size   int64
}

func (reader *boundedReadSeeker) Read(contents []byte) (int, error) {
	position, err := reader.source.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	if position < 0 || position >= reader.size {
		return 0, io.EOF
	}
	if remaining := reader.size - position; int64(len(contents)) > remaining {
		contents = contents[:remaining]
	}
	return reader.source.Read(contents)
}

func (reader *boundedReadSeeker) Seek(offset int64, whence int) (int64, error) {
	current, err := reader.source.Seek(0, io.SeekCurrent)
	if err != nil {
		return current, err
	}
	var position int64
	switch whence {
	case io.SeekStart:
		position = offset
	case io.SeekCurrent:
		if offset < -current || offset > reader.size-current {
			return current, errors.New("seek is outside the bounded release asset")
		}
		position = current + offset
	case io.SeekEnd:
		if offset < -reader.size || offset > 0 {
			return current, errors.New("seek is outside the bounded release asset")
		}
		position = reader.size + offset
	default:
		return current, errors.New("invalid release asset seek origin")
	}
	if position < 0 || position > reader.size {
		return current, errors.New("seek is outside the bounded release asset")
	}
	return reader.source.Seek(position, io.SeekStart)
}

func getExactObjectDigest(ctx context.Context, client immutableObjectClient, namespace, bucket, name string, expectedBytes int64, expectedDigest []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	response, err := client.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: common.String(namespace), BucketName: common.String(bucket), ObjectName: common.String(name),
	})
	if err != nil {
		return err
	}
	defer response.Content.Close()
	if response.ContentLength != nil && *response.ContentLength != expectedBytes {
		return fmt.Errorf("stored object length %d does not match %d", *response.ContentLength, expectedBytes)
	}
	hash := sha256.New()
	read, err := io.Copy(hash, commandio.Reader(ctx, io.LimitReader(response.Content, expectedBytes+1)))
	if err != nil {
		return err
	}
	if read != expectedBytes {
		return fmt.Errorf("stored object read %d bytes, expected %d", read, expectedBytes)
	}
	if !bytes.Equal(hash.Sum(nil), expectedDigest) {
		return errors.New("release object name already contains different bytes; refusing overwrite")
	}
	return nil
}

func validStorageToken(value string) bool {
	return value != "" && len(value) <= 255 && !strings.ContainsAny(value, "/\\ \t\r\n")
}

func validObjectName(value string) bool {
	if value == "" || len(value) > 1024 || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\ \t\r\n") {
		return false
	}
	for part := range strings.SplitSeq(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func (c command) binaryCandidate(args []string) error {
	flags := flag.NewFlagSet("binary-candidate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	binaryPath := flags.String("binary", "", "static Linux orchestrator binary")
	sourceRevision := flags.String("source-revision", "", "expected exact Git revision")
	qualificationPath := flags.String("qualification", "", "retained CI qualification manifest")
	goVersion := flags.String("go-version", defaultGoVersion, "required Go toolchain version")
	output := flags.String("out", "", "new unsigned JSON receipt path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binaryPath == "" || *sourceRevision == "" || *qualificationPath == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("binary-candidate requires --binary, --source-revision, --qualification, and --out")
	}
	qualification, qualificationDigest, err := readQualification(*qualificationPath)
	if err != nil {
		return err
	}
	receipt, err := c.inspectBinary(*binaryPath, *goVersion, *sourceRevision)
	if err != nil {
		return err
	}
	receipt.QualificationSHA256 = qualificationDigest
	if err := qualification.MatchBinary(receipt, qualificationDigest); err != nil {
		return err
	}
	encoded, err := trust.EncodePayload(receipt)
	if err != nil {
		return err
	}
	return c.writeNew(*output, encoded, 0o644)
}

func (c command) signBinary(args []string) error {
	return c.signBinaryWithCheck(args, c.verifyForgejoQualification, c.inspectBinary)
}

func (c command) signBinaryWithCheck(args []string, check func(release.Qualification, string) error,
	inspect func(string, string, string) (binaryReceipt, error),
) error {
	flags := flag.NewFlagSet("sign-binary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidate := flags.String("candidate", "", "unsigned canonical binary receipt")
	binaryPath := flags.String("binary", "", "retained CI binary matching the candidate")
	qualificationPath := flags.String("qualification", "", "retained CI qualification manifest")
	delegationPath := flags.String("delegation", "", "root-signed release delegation envelope")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	privatePath := flags.String("signing-key", "", "delegated Ed25519 PKCS#8 private key PEM")
	environment := flags.String("environment", "", "production or canary")
	validFor := flags.Duration("valid-for", defaultValidFor, "receipt validity, bounded by delegation expiry")
	output := flags.String("out", "", "new signed envelope path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidate == "" || *binaryPath == "" || *qualificationPath == "" || *delegationPath == "" || *rootPath == "" || *privatePath == "" || !validEnvironment(*environment) || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-binary requires --candidate, --binary, --qualification, --delegation, --root-key, --signing-key, --environment, and --out")
	}
	payload, err := readCanonicalPayload[binaryReceipt](*candidate)
	if err != nil {
		return err
	}
	if err := validateBinaryReceipt(payload); err != nil {
		return err
	}
	qualification, qualificationDigest, err := readQualification(*qualificationPath)
	if err != nil {
		return err
	}
	if err := qualification.MatchBinary(payload, qualificationDigest); err != nil {
		return err
	}
	observed, err := inspect(*binaryPath, payload.GoVersion, payload.SourceRevision)
	if err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	observed.QualificationSHA256 = qualificationDigest
	if observed != payload {
		return errors.New("retained CI binary does not match the qualified candidate")
	}
	if err := check(qualification, qualificationDigest); err != nil {
		return err
	}
	envelope, err := c.signReceiptWithFiles(payload, *environment, *delegationPath, *rootPath, *privatePath, *validFor)
	if err != nil {
		return err
	}
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	return c.writeNew(*output, encoded, 0o644)
}

func (c command) verifyBinary(args []string) error {
	return c.verifyBinaryWithInspect(args, c.inspectBinary)
}

func (c command) verifyBinaryWithInspect(args []string,
	inspect func(string, string, string) (binaryReceipt, error),
) error {
	flags := flag.NewFlagSet("verify-binary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	envelopePath := flags.String("receipt", "", "signed binary receipt envelope")
	delegationPath := flags.String("delegation", "", "root-signed release delegation envelope")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	binaryPath := flags.String("binary", "", "binary whose bytes and ELF metadata are checked")
	qualificationPath := flags.String("qualification", "", "retained CI qualification manifest")
	environment := flags.String("environment", "", "production or canary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *envelopePath == "" || *delegationPath == "" || *rootPath == "" || *binaryPath == "" || *qualificationPath == "" || !validEnvironment(*environment) || flags.NArg() != 0 {
		return errors.New("verify-binary requires --receipt, --delegation, --root-key, --binary, --qualification, and --environment")
	}
	verified, err := verifyBinaryReceiptFiles(*envelopePath, *delegationPath, *rootPath, *environment)
	if err != nil {
		return err
	}
	receipt := verified.Receipt()
	qualification, qualificationDigest, err := readQualification(*qualificationPath)
	if err != nil {
		return err
	}
	if err := qualification.MatchBinary(receipt, qualificationDigest); err != nil {
		return err
	}
	observed, err := inspect(*binaryPath, receipt.GoVersion, receipt.SourceRevision)
	if err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	observed.QualificationSHA256 = qualificationDigest
	if observed != receipt {
		return errors.New("binary bytes or build metadata do not match the signed receipt")
	}
	_, err = fmt.Fprintf(c.output, "verified binary revision=%s arch=%s sha256=%s key_id=%s\n", receipt.SourceRevision, receipt.GOARCH, receipt.SHA256, verified.KeyID())
	return err
}

func (c command) imageCandidate(args []string) error {
	flags := flag.NewFlagSet("image-candidate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	binaryReceiptPath := flags.String("binary-receipt", "", "signed binary receipt envelope")
	binaryPath := flags.String("binary", "", "exact binary included in the image")
	qualificationPath := flags.String("qualification", "", "retained CI qualification manifest")
	delegationPath := flags.String("delegation", "", "root-signed release delegation envelope")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	environment := flags.String("environment", "", "production or canary")
	imageFile := flags.String("image-file", "", "offline OCI image export in QCOW2 format")
	baseImageOCID := flags.String("base-image-ocid", "", "pinned base image OCID")
	baseRegion := flags.String("base-image-region", "", "base image OCI region")
	baseImageFile := flags.String("base-image-file", "", "exact base QCOW2 file used for image assembly")
	kernelRelease := flags.String("kernel-release", "", "guest kernel release")
	kernelFile := flags.String("kernel-file", "", "exact guest kernel file used by the image")
	imageOCID := flags.String("image-ocid", "", "final imported custom image OCID")
	region := flags.String("region", "", "final custom image OCI region")
	guestBinary := flags.String("guest-binary", "/usr/local/bin/terrascale-orchestrator", "binary path inside the QCOW2 guest")
	output := flags.String("out", "", "new unsigned JSON image receipt path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *binaryReceiptPath == "" || *binaryPath == "" || *qualificationPath == "" || *delegationPath == "" || *rootPath == "" || !validEnvironment(*environment) || *imageFile == "" || *baseImageOCID == "" || *baseRegion == "" || *baseImageFile == "" || *kernelRelease == "" || *kernelFile == "" || *imageOCID == "" || *region == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("image-candidate requires a qualified binary receipt/binary, root/delegation inputs, base/image files and OCIDs, region, kernel release, and --out")
	}
	if !validRegion(*baseRegion) || !validRegion(*region) || !validOCIImageIDForRegion(*baseImageOCID, *baseRegion) || !validOCIImageIDForRegion(*imageOCID, *region) || *baseRegion != *region {
		return errors.New("base and custom image OCIDs must belong to the same supported OCI region")
	}
	if !validGuestBinaryPath(*guestBinary) {
		return errors.New("guest binary path must be an absolute, clean guest path")
	}
	verifiedBinary, err := verifyBinaryReceiptFiles(*binaryReceiptPath, *delegationPath, *rootPath, *environment)
	if err != nil {
		return err
	}
	binary := verifiedBinary.Receipt()
	qualification, qualificationDigest, err := readQualification(*qualificationPath)
	if err != nil {
		return err
	}
	if err := qualification.MatchBinary(binary, qualificationDigest); err != nil {
		return err
	}
	observedBinary, err := c.inspectBinary(*binaryPath, binary.GoVersion, binary.SourceRevision)
	if err != nil {
		return err
	}
	observedBinary.QualificationSHA256 = qualificationDigest
	if observedBinary != binary {
		return errors.New("image binary does not match its signed binary receipt")
	}
	imageDigestBefore, imageBytesBefore, err := c.hashQcow2(*imageFile)
	if err != nil {
		return err
	}
	embeddedBinary, err := c.extractGuestBinary(*imageFile, *guestBinary, binary.Bytes)
	if err != nil {
		return err
	}
	defer func() {
		name := embeddedBinary.Name()
		_ = embeddedBinary.Close()
		_ = os.Remove(name)
	}()
	observedEmbedded, err := c.inspectBinary(embeddedBinary.Name(), binary.GoVersion, binary.SourceRevision)
	if err != nil {
		return fmt.Errorf("verify binary extracted from final QCOW2 image: %w", err)
	}
	observedEmbedded.QualificationSHA256 = qualificationDigest
	if observedEmbedded != binary {
		return errors.New("binary embedded in final QCOW2 image does not match its signed receipt")
	}
	imageDigest, imageBytes, err := c.hashQcow2(*imageFile)
	if err != nil {
		return err
	}
	if imageDigest != imageDigestBefore || imageBytes != imageBytesBefore {
		return errors.New("QCOW2 image changed while its embedded binary was being inspected")
	}
	baseDigest, _, err := c.hashQcow2(*baseImageFile)
	if err != nil {
		return fmt.Errorf("inspect pinned base image: %w", err)
	}
	kernelDigest, _, err := c.hashFile(*kernelFile)
	if err != nil {
		return fmt.Errorf("hash guest kernel: %w", err)
	}
	if !validKernelRelease(*kernelRelease) {
		return errors.New("image-candidate has invalid kernel release")
	}
	receipt := imageReceipt{
		Schema: imageSchema, SourceRevision: binary.SourceRevision, GoVersion: binary.GoVersion,
		Architecture: binary.GOARCH, BinaryBytes: binary.Bytes, BinarySHA256: binary.SHA256,
		QualificationSHA256: qualificationDigest,
		BaseImageOCID:       *baseImageOCID, BaseImageRegion: *baseRegion, BaseImageSHA256: baseDigest,
		KernelRelease: *kernelRelease, KernelSHA256: kernelDigest,
		ImageFormat: "qcow2", ImageBytes: imageBytes, ImageSHA256: imageDigest,
		OCIImageOCID: *imageOCID, OCIRegion: *region,
	}
	if *baseRegion != *region {
		return errors.New("custom image region must match pinned base image region")
	}
	encoded, err := trust.EncodePayload(receipt)
	if err != nil {
		return err
	}
	return c.writeNew(*output, encoded, 0o644)
}

func (c command) signImage(args []string) error {
	return c.signImageWithCheck(args, c.verifyForgejoQualification, c.inspectBinary)
}

func (c command) signImageWithCheck(args []string, check func(release.Qualification, string) error,
	inspect func(string, string, string) (binaryReceipt, error),
) error {
	flags := flag.NewFlagSet("sign-image", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidate := flags.String("candidate", "", "unsigned canonical image receipt")
	binaryReceiptPath := flags.String("binary-receipt", "", "current signed qualified binary receipt")
	binaryPath := flags.String("binary", "", "exact retained CI binary embedded in image")
	qualificationPath := flags.String("qualification", "", "retained CI qualification manifest")
	imageFile := flags.String("image-file", "", "final QCOW2 image whose bytes are signed")
	baseImageFile := flags.String("base-image-file", "", "exact pinned base QCOW2 image")
	kernelFile := flags.String("kernel-file", "", "exact guest kernel")
	guestBinary := flags.String("guest-binary", "/usr/local/bin/terrascale-orchestrator", "binary path inside the QCOW2 guest")
	delegationPath := flags.String("delegation", "", "root-signed release delegation envelope")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	privatePath := flags.String("signing-key", "", "delegated Ed25519 PKCS#8 private key PEM")
	environment := flags.String("environment", "", "production or canary")
	validFor := flags.Duration("valid-for", defaultValidFor, "receipt validity, bounded by delegation expiry")
	output := flags.String("out", "", "new signed image envelope path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidate == "" || *binaryReceiptPath == "" || *binaryPath == "" || *qualificationPath == "" || *imageFile == "" || *baseImageFile == "" || *kernelFile == "" || !validGuestBinaryPath(*guestBinary) || *delegationPath == "" || *rootPath == "" || *privatePath == "" || !validEnvironment(*environment) || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-image requires --candidate, --binary-receipt, --binary, --qualification, --image-file, --base-image-file, --kernel-file, --delegation, --root-key, --signing-key, --environment, and --out")
	}
	payload, err := readCanonicalPayload[imageReceipt](*candidate)
	if err != nil {
		return err
	}
	if err := validateImageReceipt(payload); err != nil {
		return err
	}
	verifiedBinary, err := verifyBinaryReceiptFiles(*binaryReceiptPath, *delegationPath, *rootPath, *environment)
	if err != nil {
		return err
	}
	binary := verifiedBinary.Receipt()
	qualification, qualificationDigest, err := readQualification(*qualificationPath)
	if err != nil {
		return err
	}
	if err := qualification.MatchBinary(binary, qualificationDigest); err != nil {
		return err
	}
	observed, err := inspect(*binaryPath, binary.GoVersion, binary.SourceRevision)
	if err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	observed.QualificationSHA256 = qualificationDigest
	if observed != binary || payload.SourceRevision != binary.SourceRevision || payload.GoVersion != binary.GoVersion ||
		payload.Architecture != binary.GOARCH || payload.BinaryBytes != binary.Bytes ||
		payload.BinarySHA256 != binary.SHA256 || payload.QualificationSHA256 != qualificationDigest {
		return errors.New("image candidate does not embed the exact qualified binary")
	}
	if err := check(qualification, qualificationDigest); err != nil {
		return err
	}
	if err := c.verifyImageCandidateFiles(payload, *imageFile, *baseImageFile, *kernelFile, *guestBinary); err != nil {
		return err
	}
	envelope, err := c.signReceiptWithFiles(payload, *environment, *delegationPath, *rootPath, *privatePath, *validFor)
	if err != nil {
		return err
	}
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	return c.writeNew(*output, encoded, 0o644)
}

func (c command) verifyImage(args []string) error {
	flags := flag.NewFlagSet("verify-image", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	envelopePath := flags.String("receipt", "", "signed custom image receipt envelope")
	delegationPath := flags.String("delegation", "", "root-signed release delegation envelope")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	imageFile := flags.String("image-file", "", "offline QCOW2 image whose bytes are checked")
	baseImageFile := flags.String("base-image-file", "", "pinned base QCOW2 file")
	kernelFile := flags.String("kernel-file", "", "exact guest kernel file")
	guestBinary := flags.String("guest-binary", "/usr/local/bin/terrascale-orchestrator", "binary path inside the QCOW2 guest")
	region := flags.String("region", "", "expected OCI region for the signed custom image")
	environment := flags.String("environment", "", "production or canary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *envelopePath == "" || *delegationPath == "" || *rootPath == "" || *imageFile == "" || *baseImageFile == "" || *kernelFile == "" || !validGuestBinaryPath(*guestBinary) || *region == "" || !validRegion(*region) || !validEnvironment(*environment) || flags.NArg() != 0 {
		return errors.New("verify-image requires --receipt, --delegation, --root-key, --image-file, --base-image-file, --kernel-file, supported --region, and --environment")
	}
	verified, err := verifyImageReceiptFiles(*envelopePath, *delegationPath, *rootPath, release.ImageExpectation{
		Environment: *environment, LogicalRegion: *region,
	})
	if err != nil {
		return err
	}
	receipt := verified.Receipt()
	if err := c.verifyImageCandidateFiles(receipt, *imageFile, *baseImageFile, *kernelFile, *guestBinary); err != nil {
		return err
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "verified OCI image=%s region=%s revision=%s arch=%s sha256=%s\n", receipt.OCIImageOCID, receipt.OCIRegion, receipt.SourceRevision, receipt.Architecture, receipt.ImageSHA256)
	return err
}

func (c command) verifyImageCandidateFiles(receipt imageReceipt, imageFile, baseImageFile, kernelFile, guestBinary string) error {
	imageDigestBefore, imageBytesBefore, err := c.hashQcow2(imageFile)
	if err != nil {
		return err
	}
	embeddedBinary, err := c.extractGuestBinary(imageFile, guestBinary, receipt.BinaryBytes)
	if err != nil {
		return err
	}
	defer func() {
		name := embeddedBinary.Name()
		_ = embeddedBinary.Close()
		_ = os.Remove(name)
	}()
	observedEmbedded, err := c.inspectBinary(embeddedBinary.Name(), receipt.GoVersion, receipt.SourceRevision)
	if err != nil {
		return fmt.Errorf("verify binary extracted from final QCOW2 image: %w", err)
	}
	if observedEmbedded.Bytes != receipt.BinaryBytes || observedEmbedded.SHA256 != receipt.BinarySHA256 || observedEmbedded.GOARCH != receipt.Architecture {
		return errors.New("binary embedded in final QCOW2 image does not match the signed image receipt")
	}
	imageDigest, imageBytes, err := c.hashQcow2(imageFile)
	if err != nil {
		return err
	}
	if imageDigest != imageDigestBefore || imageBytes != imageBytesBefore {
		return errors.New("QCOW2 image changed while its embedded binary was being inspected")
	}
	baseDigest, _, err := c.hashQcow2(baseImageFile)
	if err != nil {
		return err
	}
	kernelDigest, _, err := c.hashFile(kernelFile)
	if err != nil {
		return err
	}
	if imageDigest != receipt.ImageSHA256 || imageBytes != receipt.ImageBytes || baseDigest != receipt.BaseImageSHA256 || kernelDigest != receipt.KernelSHA256 {
		return errors.New("image, pinned base image, or kernel bytes do not match the signed receipt")
	}
	return nil
}

func (c command) inspectBinary(path, requiredGoVersion, expectedRevision string) (binaryReceipt, error) {
	if err := c.ctx.Err(); err != nil {
		return binaryReceipt{}, err
	}
	if !release.ValidSourceRevision(expectedRevision) || requiredGoVersion == "" {
		return binaryReceipt{}, errors.New("binary candidate requires a lowercase 40-character source revision and Go version")
	}
	file, err := openRegular(path)
	if err != nil {
		return binaryReceipt{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return binaryReceipt{}, err
	}
	if info.Size() <= 0 || info.Size() > maxArtifactBytes {
		return binaryReceipt{}, errors.New("binary is empty or exceeds the static artifact size limit")
	}
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return binaryReceipt{}, fmt.Errorf("parse binary ELF: %w", err)
	}
	defer elfFile.Close()
	if elfFile.Class != elf.ELFCLASS64 || elfFile.Data != elf.ELFDATA2LSB || elfFile.Type != elf.ET_EXEC && elfFile.Type != elf.ET_DYN {
		return binaryReceipt{}, errors.New("binary must be a 64-bit little-endian Linux executable")
	}
	goarch, machine, err := elfArchitecture(elfFile.Machine)
	if err != nil {
		return binaryReceipt{}, err
	}
	for _, program := range elfFile.Progs {
		if program.Type == elf.PT_INTERP {
			return binaryReceipt{}, errors.New("binary has a dynamic interpreter")
		}
	}
	if needed, err := elfFile.DynString(elf.DT_NEEDED); err == nil && len(needed) != 0 {
		return binaryReceipt{}, errors.New("binary has dynamic library dependencies")
	}
	build, err := buildinfo.ReadFile(path)
	if err != nil {
		return binaryReceipt{}, fmt.Errorf("read Go build metadata: %w", err)
	}
	settings := make(map[string]string, len(build.Settings))
	for _, setting := range build.Settings {
		settings[setting.Key] = setting.Value
	}
	if build.GoVersion != requiredGoVersion || settings["GOOS"] != "linux" || settings["vcs.revision"] != expectedRevision || settings["vcs.modified"] != "false" {
		return binaryReceipt{}, fmt.Errorf("binary build metadata must match go=%s revision=%s with vcs.modified=false", requiredGoVersion, expectedRevision)
	}
	if settings["GOARCH"] != goarch {
		return binaryReceipt{}, errors.New("ELF architecture does not match Go build metadata")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return binaryReceipt{}, err
	}
	digest, _, err := c.hashArtifact(file)
	if err != nil {
		return binaryReceipt{}, err
	}
	return binaryReceipt{
		Schema: binarySchema, SourceRevision: expectedRevision, GoVersion: build.GoVersion,
		GOOS: settings["GOOS"], GOARCH: settings["GOARCH"], ELFMachine: machine, Static: true,
		Bytes: info.Size(), SHA256: hex.EncodeToString(digest),
	}, nil
}

func elfArchitecture(machine elf.Machine) (string, string, error) {
	switch machine {
	case elf.EM_X86_64:
		return "amd64", linuxAMD64Machine, nil
	case elf.EM_AARCH64:
		return "arm64", linuxARM64Machine, nil
	default:
		return "", "", fmt.Errorf("unsupported ELF architecture %s", machine)
	}
}

func binaryScope(receipt binaryReceipt, environment string) trust.Scope {
	return release.BinaryScope(receipt, environment)
}

func imageScope(receipt imageReceipt, environment string) trust.Scope {
	return release.ImageScope(receipt, environment)
}

func (c command) signReceiptWithFiles(payload any, environment, delegationPath, rootPath, privatePath string,
	validFor time.Duration,
) (trust.Envelope, error) {
	if err := c.ctx.Err(); err != nil {
		return trust.Envelope{}, err
	}
	delegation, err := readEnvelope(delegationPath)
	if err != nil {
		return trust.Envelope{}, err
	}
	root, err := readRootPublicKey(rootPath)
	if err != nil {
		return trust.Envelope{}, err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return trust.Envelope{}, err
	}
	private, err := readDelegatedPrivateKey(privatePath)
	if err != nil {
		return trust.Envelope{}, err
	}
	defer clear(private)
	if err := c.ctx.Err(); err != nil {
		return trust.Envelope{}, err
	}
	now := time.Now().UTC()
	switch receipt := payload.(type) {
	case binaryReceipt:
		return release.SignBinaryReceipt(receipt, environment, delegation, roots, private, now, validFor)
	case imageReceipt:
		return release.SignImageReceipt(receipt, environment, delegation, roots, private, now, validFor)
	default:
		return trust.Envelope{}, fmt.Errorf("unsupported release receipt type %T", payload)
	}
}

func verifyBinaryReceiptFiles(envelopePath, delegationPath, rootPath, environment string) (release.VerifiedBinary, error) {
	envelopeWire, delegationWire, roots, err := readReceiptVerificationInputs(envelopePath, delegationPath, rootPath)
	if err != nil {
		return release.VerifiedBinary{}, err
	}
	return release.VerifyBinaryCurrent(envelopeWire, delegationWire, roots,
		release.BinaryExpectation{Environment: environment}, time.Now().UTC())
}

func verifyImageReceiptFiles(envelopePath, delegationPath, rootPath string,
	expected release.ImageExpectation,
) (release.VerifiedImage, error) {
	envelopeWire, delegationWire, roots, err := readReceiptVerificationInputs(envelopePath, delegationPath, rootPath)
	if err != nil {
		return release.VerifiedImage{}, err
	}
	return release.VerifyImageCurrent(envelopeWire, delegationWire, roots, expected, time.Now().UTC())
}

func readReceiptVerificationInputs(envelopePath, delegationPath, rootPath string) ([]byte, []byte, trust.Keyring, error) {
	envelopeWire, err := readBoundedRegular(envelopePath, trust.MaxEnvelopeBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	delegationWire, err := readBoundedRegular(delegationPath, trust.MaxEnvelopeBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	root, err := readRootPublicKey(rootPath)
	if err != nil {
		return nil, nil, nil, err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return nil, nil, nil, err
	}
	return envelopeWire, delegationWire, roots, nil
}

func readCanonicalPayload[T any](path string) (T, error) {
	var value T
	encoded, err := readBoundedRegular(path, maxReceiptBytes)
	if err != nil {
		return value, err
	}
	if err := decodeCanonicalPayload(encoded, &value); err != nil {
		return value, err
	}
	return value, nil
}

func decodeCanonicalPayload(encoded []byte, destination any) error {
	if err := protocol.DecodeStrict(encoded, destination, trust.MaxPayloadBytes); err != nil {
		return err
	}
	canonical, err := trust.EncodePayload(destination)
	if err != nil {
		return err
	}
	if string(canonical) != string(encoded) {
		return errors.New("release receipt payload is not canonical JSON")
	}
	return nil
}

func validateBinaryReceipt(receipt binaryReceipt) error { return receipt.Validate() }

func validateImageReceipt(receipt imageReceipt) error { return receipt.Validate() }

func readEnvelope(path string) (trust.Envelope, error) {
	encoded, err := readBoundedRegular(path, trust.MaxEnvelopeBytes)
	if err != nil {
		return trust.Envelope{}, err
	}
	return trust.DecodeEnvelope(encoded)
}

func readRootPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readBoundedRegular(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	block, rest := pemDecode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("root public key must be a PEM-encoded Ed25519 SubjectPublicKeyInfo")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse root public key: %w", err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("root public key must be Ed25519")
	}
	return public, nil
}

func readDelegatedPrivateKey(path string) (ed25519.PrivateKey, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open delegated signing key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat delegated signing key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("delegated signing key must be a regular owner-only file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("delegated signing key must be owned by this process user")
	}
	if info.Size() < 0 || info.Size() > maxKeyFileBytes {
		return nil, errors.New("delegated signing key exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	block, rest := pemDecode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("delegated signing key must be PEM PKCS#8 Ed25519")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse delegated signing key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("delegated signing key must be Ed25519")
	}
	return private, nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < 0 || info.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", filepath.Base(path), maximum)
	}
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func (c command) openHashedArtifact(path string, maximum int64) (*os.File, int64, []byte, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, 0, nil, err
	}
	file, err := openRegular(path)
	if err != nil {
		return nil, 0, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, nil, err
	}
	if info.Size() <= 0 || info.Size() > maximum {
		file.Close()
		return nil, 0, nil, fmt.Errorf("%s must be between 1 and %d bytes", filepath.Base(path), maximum)
	}
	digest, count, err := c.hashArtifact(io.LimitReader(file, maximum+1))
	if err != nil {
		file.Close()
		return nil, 0, nil, err
	}
	if count != info.Size() {
		file.Close()
		return nil, 0, nil, fmt.Errorf("%s changed while hashing", filepath.Base(path))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, 0, nil, err
	}
	return file, count, digest, nil
}

type cappedWriter struct {
	destination io.Writer
	remaining   int64
}

func (writer *cappedWriter) Write(contents []byte) (int, error) {
	if int64(len(contents)) > writer.remaining {
		written, err := writer.destination.Write(contents[:writer.remaining])
		writer.remaining -= int64(written)
		if err != nil {
			return written, err
		}
		return written, errors.New("extracted guest file exceeds signed size limit")
	}
	written, err := writer.destination.Write(contents)
	writer.remaining -= int64(written)
	return written, err
}

func (c command) extractGuestBinary(imageFile, guestPath string, expectedBytes int64) (*os.File, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	if !validGuestBinaryPath(guestPath) || expectedBytes <= 0 || expectedBytes > maxArtifactBytes {
		return nil, errors.New("guest binary path or signed size is invalid")
	}
	virtCat, err := exec.LookPath("virt-cat")
	if err != nil {
		return nil, errors.New("image verification requires virt-cat from libguestfs-tools")
	}
	output, err := os.CreateTemp("", "ts-release-guest-binary-*")
	if err != nil {
		return nil, fmt.Errorf("create bounded guest extraction file: %w", err)
	}
	cleanup := func(cause error) (*os.File, error) {
		name := output.Name()
		_ = output.Close()
		_ = os.Remove(name)
		return nil, cause
	}
	var stderr boundedBuffer
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, virtCat, "-a", imageFile, guestPath)
	command.Stdout = &cappedWriter{destination: output, remaining: expectedBytes}
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return cleanup(fmt.Errorf("extract %s from QCOW2 image: %w: %s", guestPath, err, strings.TrimSpace(stderr.String())))
	}
	info, err := output.Stat()
	if err != nil {
		return cleanup(fmt.Errorf("stat extracted guest binary: %w", err))
	}
	if info.Size() != expectedBytes {
		return cleanup(fmt.Errorf("extracted guest binary size %d does not match signed size %d", info.Size(), expectedBytes))
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return cleanup(fmt.Errorf("rewind extracted guest binary: %w", err))
	}
	return output, nil
}

type boundedBuffer struct {
	bytes.Buffer
}

func (buffer *boundedBuffer) Write(contents []byte) (int, error) {
	const limit = 4096
	remaining := limit - buffer.Len()
	if remaining > 0 {
		if len(contents) > remaining {
			_, _ = buffer.Buffer.Write(contents[:remaining])
		} else {
			_, _ = buffer.Buffer.Write(contents)
		}
	}
	return len(contents), nil
}

func validGuestBinaryPath(value string) bool {
	return value != "" && strings.HasPrefix(value, "/") && path.Clean(value) == value && !strings.ContainsRune(value, '\x00')
}

func openRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", filepath.Base(path))
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return nil, fmt.Errorf("%s changed while opening", filepath.Base(path))
	}
	return file, nil
}

func (c command) writeNew(path string, contents []byte, mode os.FileMode) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if path == "" || len(contents) == 0 {
		return errors.New("output path and content are required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create output without overwrite: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := c.ctx.Err(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func (c command) hashFile(path string) (string, int64, error) {
	if err := c.ctx.Err(); err != nil {
		return "", 0, err
	}
	file, err := openRegular(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest, bytes, err := c.hashArtifact(file)
	return hex.EncodeToString(digest), bytes, err
}

func (c command) hashQcow2(path string) (string, int64, error) {
	if err := c.ctx.Err(); err != nil {
		return "", 0, err
	}
	file, err := openRegular(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	magic := make([]byte, len(imageMagicQcow2))
	if _, err := io.ReadFull(file, magic); err != nil || string(magic) != imageMagicQcow2 {
		return "", 0, errors.New("image must be a QCOW2 disk")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	digest, bytes, err := c.hashArtifact(file)
	return hex.EncodeToString(digest), bytes, err
}

func (c command) hashArtifact(reader io.Reader) ([]byte, int64, error) {
	hash := sha256.New()
	count, err := io.Copy(hash, commandio.Reader(c.ctx, reader))
	if err != nil {
		return nil, count, err
	}
	return hash.Sum(nil), count, nil
}

func validOCIImageIDForRegion(value, region string) bool {
	return release.ValidOCIImageIDForRegion(value, region)
}

func oracleRegion(region string) string {
	return catalog.OCIRegion(region)
}

func validRegion(value string) bool {
	return release.ValidRegion(value)
}

func validEnvironment(value string) bool {
	return release.ValidEnvironment(value)
}

func validKernelRelease(value string) bool {
	return release.ValidKernelRelease(value)
}

// The wrappers keep PEM parsing behind one import point so input validation
// remains explicit and testable.
func pemDecode(data []byte) (*pem.Block, []byte) { return pem.Decode(data) }
