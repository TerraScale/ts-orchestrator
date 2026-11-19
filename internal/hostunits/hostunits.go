package hostunits

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/hostos"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

const (
	usage        = "usage: ts-orch host-units --dir <absolute directory> [--start]"
	metadataUnit = "terrascale-ts-auth-metadata.service"
	metadataNft  = "/etc/terrascale-orchestrator/ts-auth-metadata.nft"
)

type file struct {
	path string
	data []byte
}

func Run(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("host-units", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", "", "directory that receives the units")
	start := flags.Bool("start", false, "reload systemd and start the units")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || !filepath.IsAbs(*dir) {
		return errors.New(usage)
	}
	*dir = filepath.Clean(*dir)
	if hostos.NixOS() && (*dir == "/etc" || strings.HasPrefix(*dir, "/etc/")) {
		return fmt.Errorf("host-units writes no persistent units on NixOS: %s is under /etc", *dir)
	}
	if *start && *dir != hostos.UnitDirectory() {
		return fmt.Errorf("host-units --start needs --dir %s", hostos.UnitDirectory())
	}
	files, services, err := hostFiles(*dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := install(f); err != nil {
			return err
		}
		fmt.Fprintln(output, f.path)
	}
	if !*start {
		return nil
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		append([]string{"enable", "--runtime", metadataUnit}, services...),
		{"start", metadataUnit},
		append([]string{"--no-block", "start"}, services...),
	} {
		if output, err := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func hostFiles(dir string) ([]file, []string, error) {
	orch, err := m1.Files.ReadFile("ts-orch.service")
	if err != nil {
		return nil, nil, err
	}
	netbirdServer, err := m1.Files.ReadFile("services/netbird-server.service")
	if err != nil {
		return nil, nil, err
	}
	files := []file{
		{filepath.Join(dir, metadataUnit), []byte(tsauth.MetadataUnit())},
		{metadataNft, []byte(tsauth.MetadataRules)},
		{filepath.Join(dir, "ts-orch.service"), orch},
		{filepath.Join(dir, "netbird-server.service"), netbirdServer},
	}
	services := []string{"ts-orch.service", "netbird-server.service"}
	if _, err := os.Stat(releasepush.RecoveryBinary); err == nil {
		for name, text := range releasepush.RecoveryUnits {
			files = append(files, file{filepath.Join(dir, name), []byte(text)})
		}
		services = append(services, releasepush.RecoveryTimer)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	return files, services, nil
}

func install(f file) error {
	if existing, err := os.ReadFile(f.path); err == nil && bytes.Equal(existing, f.data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	next := f.path + ".next"
	if err := os.WriteFile(next, f.data, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(next, 0o644); err != nil {
		return err
	}
	return os.Rename(next, f.path)
}
