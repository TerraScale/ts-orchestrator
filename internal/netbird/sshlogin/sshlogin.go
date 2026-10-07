// Package sshlogin runs NetBird SSH without a browser. NetBird SSH servers
// accept a session only with an identity-provider JWT, which the client gets
// through an OAuth device flow on the manager's embedded IdP (Dex). This
// command answers that flow's web forms itself, as the automation user whose
// login is kept in OCI Vault.
package sshlogin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/html"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/manager"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// The automation user's login, in the operator-only TerraScale compartment.
const (
	emailSecret    = "gru-1-netbird-ssh-automation-email"
	passwordSecret = "gru-1-netbird-ssh-automation-password"
	loginLimit     = 2 * time.Minute
)

const usage = `Usage: ts-orch netbird ssh --vault-id OCID [--netbird COMMAND] -- [netbird ssh arguments]

Runs "COMMAND ssh --no-browser ARGUMENTS" (COMMAND defaults to netbird). A
user@host destination naming a NetBird peer (gru-1-ctl-1.nb.ts.internal or
gru-1-ctl-1) connects to its NetBird IP from "COMMAND status --json", so it
works on devices with NetBird DNS off. When
NetBird asks for the SSH login, it signs in to the NetBird manager's identity
provider as the automation user: Vault secrets ` + emailSecret + `
and ` + passwordSecret + `, read with the operator's ~/.oci/config.
Standard input and output pass through; a failed session exits unsuccessfully.
`

type credentials func(context.Context) (email, password string, err error)

// Run executes ts-orch netbird ssh.
func Run(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("netbird ssh", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	vaultID := flags.String("vault-id", "", "the Vault OCID holding the automation login")
	netbird := flags.String("netbird", "netbird", "the NetBird client command, split on spaces")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = io.WriteString(stdout, usage)
			return err
		}
		return fmt.Errorf("netbird ssh: %w", err)
	}
	parts := strings.Split(*vaultID, ".")
	if len(parts) < 5 || parts[1] != "vault" || !catalog.IsOCIRegion(parts[3]) {
		return errors.New("netbird ssh needs --vault-id, a regional Vault OCID")
	}
	command := strings.Fields(*netbird)
	if len(command) == 0 || flags.NArg() == 0 {
		return errors.New("netbird ssh needs a NetBird command and the netbird ssh arguments")
	}
	login := func(ctx context.Context) (string, string, error) {
		factory, err := ociclient.OperatorConfig(parts[3])
		if err != nil {
			return "", "", err
		}
		bundles, err := vaultsecret.SecretsClient(factory)
		if err != nil {
			return "", "", err
		}
		email, err := vaultsecret.Read(ctx, bundles, *vaultID, emailSecret)
		if err != nil {
			return "", "", err
		}
		password, err := vaultsecret.Read(ctx, bundles, *vaultID, passwordSecret)
		return email, password, err
	}
	args = flags.Args()
	// A failed status leaves the names as they are; netbird ssh reports them.
	if status, err := exec.CommandContext(ctx, command[0], append(slices.Clone(command[1:]), "status", "--json")...).Output(); err == nil {
		args = withPeerAddress(args, peerAddresses(status))
	}
	argv := append(append(command, "ssh", "--no-browser"), args...)
	return run(ctx, argv, os.Stdin, stdout, os.Stderr, manager.DefaultManagementURL, login)
}

// peerAddresses maps every peer in "netbird status --json" to its NetBird
// IP, by DNS name (gru-1-ctl-1.nb.ts.internal) and by peer name
// (gru-1-ctl-1). Devices that keep NetBird DNS off cannot resolve them.
func peerAddresses(status []byte) map[string]string {
	var parsed struct {
		Peers struct {
			Details []struct {
				FQDN string `json:"fqdn"`
				IP   string `json:"netbirdIp"`
			} `json:"details"`
		} `json:"peers"`
	}
	if json.Unmarshal(status, &parsed) != nil {
		return nil
	}
	addresses := map[string]string{}
	for _, peer := range parsed.Peers.Details {
		if _, err := netip.ParseAddr(peer.IP); err != nil || peer.FQDN == "" {
			continue
		}
		name, _, _ := strings.Cut(peer.FQDN, ".")
		addresses[peer.FQDN], addresses[name] = peer.IP, peer.IP
	}
	return addresses
}

// withPeerAddress puts the NetBird IP in place of the destination's host
// when it names a peer. The destination is the first user@host argument;
// later arguments are the remote command and stay unchanged.
func withPeerAddress(args []string, addresses map[string]string) []string {
	for i, arg := range args {
		user, host, found := strings.Cut(arg, "@")
		if !found {
			continue
		}
		if ip, ok := addresses[host]; ok {
			args = slices.Clone(args)
			args[i] = user + "@" + ip
		}
		break
	}
	return args
}

// run starts the NetBird SSH client and copies its standard error, watching
// for the device-flow verification URL that it prints on a line of its own.
// It signs in once; a failed sign-in stops the client.
func run(ctx context.Context, argv []string, stdin io.Reader, stdout, stderr io.Writer, origin string, login credentials) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = stdin
	// sudo relays SIGTERM to the client; SIGKILL it cannot. podman exec
	// relays neither, so a container's client must not run through it.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	output, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	pipe, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the NetBird client: %w", err)
	}
	copied := make(chan error, 1)
	go func() { copied <- copyOutput(stdout, output) }()
	loginDone := make(chan error, 1)
	asked := false
	lines := bufio.NewReader(pipe)
	for {
		line, readErr := lines.ReadString('\n')
		_, _ = io.WriteString(stderr, line)
		if target := verificationURL(line); target != "" && !asked {
			asked = true
			go func() {
				err := signIn(ctx, origin, target, login)
				if err != nil {
					cancel()
				}
				loginDone <- err
			}()
		}
		if readErr != nil {
			break
		}
	}
	copyErr := <-copied
	waitErr := cmd.Wait()
	// A client that succeeded has its token: a sign-in still reading Dex's
	// final page is cut short without failing the session.
	cancel()
	var loginErr error
	if asked {
		loginErr = <-loginDone
	}
	switch {
	case waitErr == nil:
		return copyErr
	case loginErr != nil && !errors.Is(loginErr, context.Canceled):
		return fmt.Errorf("NetBird SSH login: %w", loginErr)
	default:
		return fmt.Errorf("netbird ssh: %w", waitErr)
	}
}

// authenticated is what NetBird prints on standard output after a fresh
// login, before the session's own output.
const authenticated = "Authentication successful!\n"

// copyOutput copies the session's output without that leading line, so a
// redirected command output stays intact.
func copyOutput(destination io.Writer, source io.Reader) error {
	reader := bufio.NewReader(source)
	if head, _ := reader.Peek(len(authenticated)); string(head) == authenticated {
		_, _ = reader.Discard(len(authenticated))
	}
	_, err := io.Copy(destination, reader)
	return err
}

// verificationURL returns the line as a URL when it is a device-flow
// verification link, which carries the user code.
func verificationURL(line string) string {
	target, err := url.Parse(strings.TrimSpace(line))
	if err != nil || target.Host == "" || target.Query().Get("user_code") == "" {
		return ""
	}
	return target.String()
}

func signIn(ctx context.Context, origin, target string, login credentials) error {
	ctx, cancel := context.WithTimeout(ctx, loginLimit)
	defer cancel()
	email, password, err := login(ctx)
	if err != nil {
		return err
	}
	return deviceLogin(ctx, origin, target, email, password)
}

// deviceLogin does what a person does in the browser: open the verification
// URL, confirm the prefilled device code, and sign in with email and
// password. Dex then redirects to its device callback, which completes the
// flow the NetBird client is polling. Every request stays on origin, so the
// password goes nowhere else; a form shown twice means it was rejected.
func deviceLogin(ctx context.Context, origin, target, email, password string) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(request *http.Request, via []*http.Request) error {
		if !sameOrigin(request.URL, origin) {
			return errors.New("the identity provider redirected outside the NetBird manager")
		}
		if len(via) >= 10 {
			return errors.New("the identity provider redirected too often")
		}
		return nil
	}}
	next, err := url.Parse(target)
	if err != nil || !sameOrigin(next, origin) {
		return fmt.Errorf("refusing a verification URL outside %s", origin)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil)
	if err != nil {
		return err
	}
	answered := map[string]bool{}
	for range 6 {
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		page, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if err != nil {
			return err
		}
		at := response.Request.URL
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("the identity provider answered %s at %s", response.Status, at.Path)
		}
		action, values, found := firstForm(page)
		if !found {
			if strings.HasSuffix(at.Path, "/device/callback") {
				return nil
			}
			return fmt.Errorf("the identity provider page %s has no form", at.Path)
		}
		var step string
		switch {
		case values.Has("totp"):
			return errors.New("the automation user must not require MFA")
		case values.Has("password"):
			step = "password"
			values.Set("login", email)
			values.Set("password", password)
		case values.Has("user_code"):
			step = "device code"
		case values.Get("approval") == "approve":
			step = "approval"
		default:
			return fmt.Errorf("unexpected identity provider form at %s", at.Path)
		}
		if answered[step] {
			return fmt.Errorf("the identity provider rejected the %s", step)
		}
		answered[step] = true
		post, err := at.Parse(action)
		if err != nil || !sameOrigin(post, origin) {
			return errors.New("an identity provider form posts outside the NetBird manager")
		}
		request, err = http.NewRequestWithContext(ctx, http.MethodPost, post.String(), strings.NewReader(values.Encode()))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return errors.New("the identity provider login did not finish")
}

func sameOrigin(target *url.URL, origin string) bool {
	return target.Scheme+"://"+target.Host == origin
}

// firstForm returns the action and named input values of the page's first
// form. Dex's approval page puts its approve form first.
func firstForm(page []byte) (string, url.Values, bool) {
	tokens := html.NewTokenizer(bytes.NewReader(page))
	var action string
	var values url.Values
	for {
		switch tokens.Next() {
		case html.ErrorToken:
			return "", nil, false
		case html.EndTagToken:
			if name, _ := tokens.TagName(); values != nil && string(name) == "form" {
				return action, values, true
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			name, more := tokens.TagName()
			attributes := map[string]string{}
			for more {
				var key, value []byte
				key, value, more = tokens.TagAttr()
				attributes[string(key)] = string(value)
			}
			switch {
			case string(name) == "form" && values == nil:
				action, values = attributes["action"], url.Values{}
			case string(name) == "input" && values != nil && attributes["name"] != "":
				values.Set(attributes["name"], attributes["value"])
			}
		}
	}
}
