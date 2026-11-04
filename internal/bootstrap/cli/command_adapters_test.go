package cli

// Adapters keep the existing command contract tests intact after extraction.
// Adapters keep the existing command contract tests intact after extraction.
import (
	"context"
	"os"
	"time"
)

func runAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).runAt(args, now)
}

func run(args []string) error {
	return (command{ctx: context.Background(), output: os.Stdout}).run(args)
}

func renderControllerConfigAt(args []string, now time.Time) error {
	return (command{ctx: context.Background(), output: os.Stdout}).renderControllerConfigAt(args, now)
}
