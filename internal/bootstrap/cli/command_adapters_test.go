package cli

// Adapters keep the existing command contract tests intact after extraction.
import (
	"context"
	"os"
	"time"
)

func publishSeedCompletionAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).publishSeedCompletionAt(args, now)
}

func reconcileCompletedSeedAfterDeadline(flags *seedInputFlags, reservationPath,
	completionPath, configPath, profile string, now time.Time,
) error {
	return (command{ctx: context.Background(), output: os.Stdout}).reconcileCompletedSeedAfterDeadline(flags, reservationPath, completionPath, configPath, profile, now)
}

func signSeedCompletionAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signSeedCompletionAt(args, now)
}

func observeExternalSeedAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).observeExternalSeedAt(args, now)
}

func publishSeedReservationAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).publishSeedReservationAt(args, now)
}

func signSeedReservationAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signSeedReservationAt(args, now)
}

func signPeerReceiptDelegationAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signPeerReceiptDelegationAt(args, now)
}

func publishInitialFounderSelectionAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).publishInitialFounderSelectionAt(args, now)
}

func signInitialFounderSelectionAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signInitialFounderSelectionAt(args, now)
}

func signFounderPlanAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signFounderPlanAt(args, now)
}

func installOperatorMaterialAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).installOperatorMaterialAt(args, now)
}

func signManifestAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signManifestAt(args, now)
}

func signBootstrapAnchorAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signBootstrapAnchorAt(args, now)
}

func signLedgerDelegationAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).signLedgerDelegationAt(args, now)
}

func verifyBootstrapAnchorAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyBootstrapAnchorAt(args, now)
}

func verifyBootstrapManifestAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyBootstrapManifestAt(args, now)
}

func runAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).runAt(args, now)
}

func run(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).run(args)
}

func provisionControllerMaterialAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).provisionControllerMaterialAt(args, now)
}

func runProvisionControllerMaterial(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).runProvisionControllerMaterial(args)
}

func generateControllerMaterialAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).generateControllerMaterialAt(args, now)
}

func runGenerateControllerMaterial(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).runGenerateControllerMaterial(args)
}

func renderControllerConfigAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).renderControllerConfigAt(args, now)
}

func renderHostEnrollmentPublicAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).renderHostEnrollmentPublicAt(args, now)
}

func renderOperatorConfigAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).renderOperatorConfigAt(args, now)
}

func writeSeedBundle(path string, value any) error {
	return (command{ctx: context.Background(), output: os.Stdout}).writeSeedBundle(path, value)
}
