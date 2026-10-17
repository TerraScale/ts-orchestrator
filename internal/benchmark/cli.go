package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacity"
	"github.com/TerraScale/ts-orchestrator/internal/controlaccess"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type RegionConfig struct {
	Generator struct {
		InstanceID string `json:"instance_id"`
		Address    string `json:"address"`
		User       string `json:"user"`
		WorkerPath string `json:"worker_path"`
	} `json:"generator"`
	Images         map[string]string `json:"images"`
	ClientID       vaultsecret.Ref   `json:"client_id"`
	ClientSecret   vaultsecret.Ref   `json:"client_secret"`
	AuthOrigin     string            `json:"auth_origin"`
	AuthTenant     string            `json:"auth_tenant"`
	StorageOrigin  string            `json:"storage_origin"`
	StorageProject string            `json:"storage_project"`
	StorageKey     vaultsecret.Ref   `json:"storage_key"`
}

type Config struct {
	WorkloadsDirectory string                  `json:"workloads_directory"`
	Regions            map[string]RegionConfig `json:"regions"`
}

func CLI(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		_, err := fmt.Fprintln(out, "Usage: ts-orch bench run --region <gru|sfo> --workload <name> --clients go,dotnet,rust [--config FILE] [--reports reports]")
		return err
	}
	if args[0] == "worker" {
		if len(args) != 1 {
			return errors.New("worker reads one job from stdin")
		}
		// Broken SSH output must return EPIPE so deferred container cleanup runs.
		signal.Ignore(syscall.SIGPIPE)
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer stop()
		return Worker(ctx, os.Stdin, out)
	}
	if args[0] != "run" {
		return errors.New("bench command must be run")
	}
	flags := flag.NewFlagSet("bench run", flag.ContinueOnError)
	flags.SetOutput(out)
	region := flags.String("region", "", "gru or sfo")
	workloadName := flags.String("workload", "", "workload name")
	clientNames := flags.String("clients", "go,dotnet,rust", "comma-separated clients")
	configFile := flags.String("config", "", "benchmark config, default ~/.config/ts-orch/benchmark.json")
	reports := flags.String("reports", "reports", "report directory")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || (*region != "gru" && *region != "sfo") || !namePattern.MatchString(*workloadName) {
		return errors.New("bench run requires region gru/sfo and a workload name")
	}
	clients := strings.Split(*clientNames, ",")
	for i, client := range clients {
		if !contains(languages, client) || contains(clients[:i], client) {
			return errors.New("clients must be distinct go,dotnet,rust")
		}
	}
	if *configFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		*configFile = filepath.Join(home, ".config", "ts-orch", "benchmark.json")
	}
	configData, err := os.ReadFile(*configFile)
	if err != nil {
		return fmt.Errorf("read benchmark config %s: %w", *configFile, err)
	}
	if len(configData) > 1<<20 {
		return errors.New("benchmark config exceeds 1 MiB")
	}
	var config Config
	decoder := json.NewDecoder(strings.NewReader(string(configData)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return err
	}
	settings, ok := config.Regions[*region]
	if !ok {
		return errors.New("benchmark config has no selected region")
	}
	for _, client := range clients {
		if !imagePattern.MatchString(settings.Images[client]) {
			return errors.New("benchmark config needs digest-pinned images for selected clients")
		}
	}
	if config.WorkloadsDirectory == "" {
		return errors.New("benchmark config requires workloads_directory from ts-benchmark")
	}
	workloadData, err := os.ReadFile(filepath.Join(config.WorkloadsDirectory, *workloadName+".json"))
	if err != nil {
		return err
	}
	if len(workloadData) > 64<<10 {
		return errors.New("workload exceeds 64 KiB")
	}
	var workload Workload
	decoder = json.NewDecoder(strings.NewReader(string(workloadData)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&workload); err != nil {
		return err
	}
	if workload.Name != *workloadName {
		return errors.New("workload file name mismatch")
	}
	if err := workload.Validate(); err != nil {
		return err
	}
	preflight, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	access, err := controlaccess.Resolve(preflight, *region)
	if err != nil {
		return err
	}
	storageKey, err := capacity.ReadSecret(preflight, settings.StorageKey)
	if err != nil {
		return err
	}
	usage := capacity.Client{URLs: access.URLs, Token: access.Token}
	// Check that usage is reachable before starting any load. An empty history
	// is allowed; the final report will explicitly say it is unqualified.
	to := time.Now().UTC()
	if _, err := usage.Query(preflight, *region, to.Add(-time.Minute), to); err != nil {
		return err
	}
	repository, err := NewRepository(preflight, settings.StorageOrigin, settings.StorageProject, storageKey)
	if err != nil {
		return err
	}
	generator := SSHGenerator{Address: settings.Generator.Address, User: settings.Generator.User, WorkerPath: settings.Generator.WorkerPath,
		Job: Job{Region: *region, InstanceID: settings.Generator.InstanceID, Images: settings.Images, ClientID: settings.ClientID, ClientSecret: settings.ClientSecret, AuthOrigin: settings.AuthOrigin, AuthTenant: settings.AuthTenant}}
	runner := Runner{Generator: generator, Repository: repository, Usage: usage.Query}
	run, runErr := runner.Execute(ctx, *region, workload, clients, out)
	return finishRun(*reports, out, run, runErr)
}

func finishRun(reports string, out io.Writer, run Run, runErr error) error {
	if run.ID == "" {
		return runErr
	}
	path, reportErr := writeReport(reports, run)
	runErr = errors.Join(runErr, reportErr)
	if errors.Is(runErr, errResultDrainTimeout) || errors.Is(runErr, errResultOutput) {
		return runErr
	}
	runErr = errors.Join(runErr, WriteVerdict(out, run))
	if reportErr == nil {
		_, err := fmt.Fprintln(out, path)
		runErr = errors.Join(runErr, err)
	}
	return runErr
}

func writeReport(root string, run Run) (string, error) {
	dir := filepath.Join(root, run.Region)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, run.Started.UTC().Format("2006-01-02")+"-"+run.Workload.Name+".md")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return "", err
	}
	err = func() error {
		if _, err := fmt.Fprintf(f, "# %s / %s\n\n", run.Region, run.Workload.Name); err != nil {
			return err
		}
		if err := WriteVerdict(f, run); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(f, "\n```json"); err != nil {
			return err
		}
		if err := json.NewEncoder(f).Encode(run); err != nil {
			return err
		}
		_, err := io.WriteString(f, "```\n\n")
		return err
	}()
	return path, errors.Join(err, f.Close())
}
