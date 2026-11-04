package cli

// Adapters keep the existing command contract tests intact after extraction.
import (
	"context"
	"os"
)

func verifyBinary(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).verifyBinary(args)
}
