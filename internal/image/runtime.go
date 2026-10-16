package image

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"debug/buildinfo"
	"embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

const containerdVersion = "2.4.2"
const runcVersion = "1.5.2"

//go:embed runtime_licenses
var runtimeNotices embed.FS

var runtimeDigests = map[string]struct{ containerd, runc string }{
	"arm64": {"37b84b9534533672528141b9d815f58621a2fe5deee2daa84317800255756689", "d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0"},
	"amd64": {"da656542e754c699a0f438eab925e6ffdbd6346a4428e659f83dc058f04dcffe", "599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488"},
}

const containerdUnit = `[Unit]
Description=TerraScale managed containerd
After=network.target

[Service]
ExecStart=/usr/local/bin/containerd
Restart=always
RestartSec=5s
Delegate=yes
KillMode=process
LimitNOFILE=1048576
TasksMax=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
`

// Runtime binaries are image inputs: hosts never install mutable distribution packages.
func installRuntime(ctx context.Context, g *Guest, architecture, work string, out io.Writer) error {
	pins, ok := runtimeDigests[architecture]
	if !ok {
		return errors.New("unsupported container runtime architecture")
	}
	archive := filepath.Join(work, "containerd.tar.gz")
	if err := fetchRuntime(ctx, "https://github.com/containerd/containerd/releases/download/v"+containerdVersion+"/containerd-static-"+containerdVersion+"-linux-"+architecture+".tar.gz", archive, pins.containerd); err != nil {
		return err
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer z.Close()
	entries := tar.NewReader(z)
	found := map[string]bool{}
	for {
		entry, err := entries.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if entry.Name != "bin/containerd" && entry.Name != "bin/containerd-shim-runc-v2" {
			continue
		}
		if found[entry.Name] || entry.Typeflag != tar.TypeReg || entry.Size <= 0 || entry.Size > client.MaxBinaryBytes {
			return errors.New("invalid pinned containerd archive executable")
		}
		target := filepath.Join(work, filepath.Base(entry.Name))
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
		if err != nil {
			return err
		}
		_, err = io.CopyN(output, entries, entry.Size)
		if err = errors.Join(err, output.Close()); err != nil {
			return err
		}
		found[entry.Name] = true
	}
	if len(found) != 2 {
		return errors.New("pinned containerd archive lacks runtime executables")
	}
	if err := fetchRuntime(ctx, "https://github.com/opencontainers/runc/releases/download/v"+runcVersion+"/runc."+architecture, filepath.Join(work, "runc"), pins.runc); err != nil {
		return err
	}
	for _, name := range []string{"containerd", "containerd-shim-runc-v2", "runc"} {
		source := filepath.Join(work, name)
		actual, err := binaryArchitecture(source)
		if err != nil {
			return err
		}
		if actual != architecture {
			return fmt.Errorf("%s architecture differs from host image", name)
		}
		module, version := "github.com/containerd/containerd/v2", "v"+containerdVersion
		if name == "runc" {
			module, version = "github.com/opencontainers/runc", "v"+runcVersion
		}
		build, err := buildinfo.ReadFile(source)
		if err != nil {
			return fmt.Errorf("read %s runtime build identity: %w", name, err)
		}
		if build.Main.Path != module || build.Main.Version != version {
			return fmt.Errorf("%s runtime module or version differs from the image pin", name)
		}
		settings := map[string]string{}
		for _, setting := range build.Settings {
			settings[setting.Key] = setting.Value
		}
		if settings["GOOS"] != "linux" || settings["GOARCH"] != architecture {
			return fmt.Errorf("%s runtime build platform differs from host image", name)
		}
		destination := "/usr/local/bin/" + name
		if err := g.Upload(source, destination, 0755); err != nil {
			return err
		}
		digest, err := fileHash(source)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "managed runtime executable=%s architecture=%s sha256=%s containerd=%s runc=%s\n", name, architecture, digest, containerdVersion, runcVersion); err != nil {
			return err
		}
	}
	notices, err := runtimeNotices.ReadDir("runtime_licenses")
	if err != nil {
		return err
	}
	if err := g.Directory(AppLib+"/runtime-notices", 0, 0, 0755); err != nil {
		return err
	}
	for _, notice := range notices {
		contents, err := runtimeNotices.ReadFile("runtime_licenses/" + notice.Name())
		if err != nil {
			return err
		}
		source := filepath.Join(work, notice.Name())
		if err := os.WriteFile(source, contents, 0644); err != nil {
			return err
		}
		if err := g.Upload(source, AppLib+"/runtime-notices/"+notice.Name(), 0644); err != nil {
			return err
		}
	}
	for name, contents := range map[string]string{
		"containerd.service": containerdUnit,
		"terrascale-orchestrator-host.service.d/70-containerd.conf":       "[Unit]\nRequires=containerd.service\nAfter=containerd.service\n",
		"terrascale-orchestrator-controller.service.d/70-containerd.conf": "[Unit]\nRequires=containerd.service\nAfter=containerd.service\n",
	} {
		source := filepath.Join(work, filepath.Base(name))
		if err := os.WriteFile(source, []byte(contents), 0644); err != nil {
			return err
		}
		destination := "/etc/systemd/system/" + name
		if err := g.Upload(source, destination, 0644); err != nil {
			return err
		}
	}
	return nil
}

func fetchRuntime(ctx context.Context, url, destination, digest string) (result error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 5 * time.Minute}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch pinned runtime: HTTP %d", response.StatusCode)
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	defer func() {
		if result != nil {
			os.Remove(destination)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(response.Body, 256<<20+1))
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if n > 256<<20 {
		return errors.New("pinned runtime exceeds 256 MiB")
	}
	actual, err := fileHash(destination)
	if err != nil {
		return err
	}
	if actual != digest {
		return errors.New("runtime input SHA-256 differs from the code pin")
	}
	return nil
}
