package cli

// Adapters keep the existing command contract tests intact after extraction.
import (
	"context"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
)

func verifyForgejoQualification(qualification release.Qualification, qualificationSHA256 string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyForgejoQualification(qualification, qualificationSHA256)
}

func extractGuestBinary(imageFile, guestPath string, expectedBytes int64) (*os.File, error) {
	return (command{ctx: context.Background(), output: os.Stdout}).extractGuestBinary(imageFile, guestPath, expectedBytes)
}

func verifyImageCandidateFiles(receipt imageReceipt, imageFile, baseImageFile, kernelFile, guestBinary string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyImageCandidateFiles(receipt, imageFile, baseImageFile, kernelFile, guestBinary)
}

func verifyImage(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyImage(args)
}

func signImageWithCheck(args []string, check func(release.Qualification, string) error,
	inspect func(string, string, string) (binaryReceipt, error),
) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signImageWithCheck(args, check, inspect)
}

func signImage(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signImage(args)
}

func imageCandidate(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).imageCandidate(args)
}

func verifyBinaryWithInspect(args []string,
	inspect func(string, string, string) (binaryReceipt, error),
) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyBinaryWithInspect(args, inspect)
}

func verifyBinary(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyBinary(args)
}

func signBinary(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signBinary(args)
}

func publish(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).publish(args)
}

func run(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).run(args)
}
