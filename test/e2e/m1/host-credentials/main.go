package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
)

const unit = "/run/systemd/system/ts-alert-delivery.service"
const prepare = "ExecStartPre=+/usr/local/bin/ts-orch alert-delivery prepare"

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(path, value string) {
	must(os.MkdirAll(filepath.Dir(path), 0o750))
	must(os.WriteFile(path, []byte(value), 0o640))
	if strings.HasPrefix(path, "/run/ts-alert-delivery/") {
		account, err := user.Lookup("ts-alerts")
		must(err)
		gid, err := strconv.Atoi(account.Gid)
		must(err)
		must(os.Chown(filepath.Dir(path), 0, gid))
		must(os.Chown(path, 0, gid))
	}
}

func stop(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func ready(cmd *exec.Cmd, marker string) {
	pipe, err := cmd.StdoutPipe()
	must(err)
	cmd.Stderr = cmd.Stdout
	must(cmd.Start())
	scanner := bufio.NewScanner(pipe)
	last := ""
	for scanner.Scan() {
		last = scanner.Text()
		if strings.Contains(scanner.Text(), marker) {
			go io.Copy(io.Discard, pipe)
			return
		}
	}
	panic("process did not announce " + marker + ": " + last)
}

func relay(ctx context.Context, binary string) {
	keys := []string{"cloudflare_account_id_file", "cloudflare_email_token_file", "ts_alerts_ntfy_topic_file"}
	must(os.MkdirAll("/run/ts-alert-delivery", 0o750))
	account, err := user.Lookup("ts-alerts")
	must(err)
	gid, err := strconv.Atoi(account.Gid)
	must(err)
	must(os.Chown("/run/ts-alert-delivery", 0, gid))
	command := exec.CommandContext(ctx, binary, "alert-delivery")
	output, err := command.CombinedOutput()
	require(err != nil && strings.Contains(string(output), "CLOUDFLARE_ACCOUNT_ID_FILE unavailable"), "relay must refuse startup without credential files")
	fmt.Println("ok relay: startup without files exits non-zero and names the file")
	values := []string{strings.Repeat("a", 32), rand.Text(), rand.Text() + rand.Text()}
	for i, key := range keys {
		write("/run/ts-alert-delivery/"+key, values[i])
	}
	command = exec.CommandContext(ctx, binary, "alert-delivery")
	ready(command, "Alert delivery listener ready")
	defer stop(command)
	check := func(want int, name string) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9094/healthz", nil)
		must(err)
		response, err := http.DefaultClient.Do(request)
		must(err)
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		must(err)
		require(response.StatusCode == want && strings.Contains(string(body), name), "relay health must reflect credential availability")
		for _, value := range values {
			require(!bytes.Contains(body, []byte(value)), "health must never disclose credential contents")
		}
	}
	check(http.StatusOK, "")
	for i, key := range keys {
		path := "/run/ts-alert-delivery/" + key
		must(os.Remove(path))
		check(http.StatusServiceUnavailable, strings.ToUpper(key))
		write(path, "invalid\ncredential")
		check(http.StatusServiceUnavailable, strings.ToUpper(key))
		command := exec.CommandContext(ctx, binary, "alert-delivery")
		output, err := command.CombinedOutput()
		require(err != nil && strings.Contains(string(output), strings.ToUpper(key)), "relay startup must name malformed credential file")
		write(path, values[i])
		check(http.StatusOK, "")
		must(os.Chmod(path, 0o600))
		check(http.StatusServiceUnavailable, strings.ToUpper(key))
		must(os.Chmod(path, 0o640))
		check(http.StatusOK, "")
		must(os.Chown(path, 0, gid+1))
		check(http.StatusServiceUnavailable, strings.ToUpper(key))
		must(os.Chown(path, 0, gid))
		check(http.StatusOK, "")
	}
	fmt.Println("ok relay: health is 503 after each missing, malformed or misprotected file; recovers after repair")
}

func systemctl() {
	data, err := os.ReadFile(unit)
	if strings.Contains(strings.Join(os.Args[1:], " "), "LoadState") {
		if err != nil {
			fmt.Println("not-found")
		} else {
			fmt.Println("loaded")
		}
		return
	}
	if strings.Contains(string(data), prepare) {
		fmt.Println("{ path=/usr/local/bin/ts-orch ; argv[]=/usr/local/bin/ts-orch alert-delivery prepare ; flags=privileged ; start_time=[n/a] ; }")
	}
}

func run(ctx context.Context) {
	binary, work := os.Args[1], os.Args[2]
	currentSystem, systemErr := os.Readlink("/run/current-system")
	must(syscall.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755"))
	if systemErr == nil {
		must(os.Symlink(currentSystem, "/run/current-system"))
	} else if !errors.Is(systemErr, os.ErrNotExist) {
		must(systemErr)
	}
	firmware := filepath.Join(work, "credentials-sys/class/dmi/id")
	write(filepath.Join(firmware, "chassis_asset_tag"), "Local\n")
	must(syscall.Mount(filepath.Join(work, "credentials-sys"), "/sys", "", syscall.MS_BIND, ""))
	path := filepath.Join(work, "credentials-tools")
	must(os.Mkdir(path, 0o700))
	helper, err := os.Executable()
	must(err)
	must(os.Symlink(helper, filepath.Join(path, "systemctl")))
	must(os.Setenv("PATH", path+":"+os.Getenv("PATH")))
	if _, err := user.Lookup("ts-alerts"); err != nil {
		passwd, err := os.ReadFile("/etc/passwd")
		must(err)
		passwd = append(passwd, []byte("\nts-alerts:x:32123:32123:Alert relay:/nonexistent:/usr/sbin/nologin\n")...)
		passwdFile := filepath.Join(work, "credential-passwd")
		must(os.WriteFile(passwdFile, passwd, 0o644))
		must(syscall.Mount(passwdFile, "/etc/passwd", "", syscall.MS_BIND, ""))
	}
	relay(ctx, binary)
	write(unit, "[Service]\nExecStart=/usr/local/bin/ts-orch alert-delivery\n")
	err = secretpreflight.Check(ctx, binary)
	require(err != nil && strings.Contains(err.Error(), "install ts-alert-delivery.service"), "old relay unit must refuse release preflight")
	write(unit, "[Service]\n"+prepare+"\nExecStart=/usr/local/bin/ts-orch alert-delivery\n")
	must(secretpreflight.Check(ctx, binary))
	write(unit, "[Service]\nExecStartPre=/usr/local/bin/ts-orch alert-delivery prepare\n")
	err = secretpreflight.Check(ctx, binary)
	require(err != nil, "unprivileged preparation command must refuse release preflight")
	fmt.Println("ok preflight: old or unprivileged relay unit refused; correct installed unit passes next attempt")
	fmt.Println("host-credentials e2e: PASS")
}

func main() {
	if filepath.Base(os.Args[0]) == "systemctl" {
		systemctl()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	defer func() {
		if failure := recover(); failure != nil {
			fmt.Fprintln(os.Stderr, "host-credentials e2e: FAIL:", failure)
			os.Exit(1)
		}
	}()
	if len(os.Args) != 3 {
		must(errors.New("host credentials e2e needs binary and work directory"))
	}
	run(ctx)
}
