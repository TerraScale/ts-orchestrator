package sshlogin

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testEmail    = "ssh-automation@example.test"
	testPassword = "correct horse"
	testCode     = "ABCD-EFGH"
)

// fakeDex serves the embedded IdP pages of a device login: device code,
// email and password, optionally TOTP, then the device callback.
type fakeDex struct {
	*httptest.Server
	mfa       bool
	elsewhere string // when set, the code check redirects there
	approved  atomic.Bool
	posts     atomic.Int32
}

func newFakeDex(t *testing.T) *fakeDex {
	dex := &fakeDex{}
	form := func(w http.ResponseWriter, action, inputs string) {
		fmt.Fprintf(w, `<html><body><a href="/elsewhere">x</a><form method="post" action="%s">%s<button type="submit">Go</button></form></body></html>`, action, inputs)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/device", func(w http.ResponseWriter, r *http.Request) {
		form(w, "/oauth2/device/auth/verify_code", fmt.Sprintf(`<input type="text" name="user_code" value="%s" required>`, r.URL.Query().Get("user_code")))
	})
	mux.HandleFunc("POST /oauth2/device/auth/verify_code", func(w http.ResponseWriter, r *http.Request) {
		dex.posts.Add(1)
		switch {
		case r.FormValue("user_code") != testCode:
			form(w, "/oauth2/device/auth/verify_code", `<input type="text" name="user_code">`)
		case dex.elsewhere != "":
			http.Redirect(w, r, dex.elsewhere, http.StatusFound)
		default:
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "s1", Path: "/"})
			http.Redirect(w, r, "/oauth2/auth?client_id=netbird-cli&state=s1", http.StatusFound)
		}
	})
	mux.HandleFunc("GET /oauth2/auth", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/oauth2/auth/local/login?back=&state="+r.URL.Query().Get("state"), http.StatusFound)
	})
	mux.HandleFunc("GET /oauth2/auth/local/login", func(w http.ResponseWriter, r *http.Request) {
		form(w, "/oauth2/auth/local/login?back=&state=s1", `<input type="hidden" name="csrf" value="c1"><input type="text" name="login"><input type="password" name="password">`)
	})
	mux.HandleFunc("POST /oauth2/auth/local/login", func(w http.ResponseWriter, r *http.Request) {
		dex.posts.Add(1)
		session, err := r.Cookie("session")
		if err != nil || session.Value != "s1" || r.FormValue("csrf") != "c1" || r.URL.Query().Get("state") != "s1" ||
			r.FormValue("login") != testEmail || r.FormValue("password") != testPassword {
			form(w, "/oauth2/auth/local/login?back=&state=s1", `<input type="text" name="login"><input type="password" name="password">`)
			return
		}
		if dex.mfa {
			form(w, "/oauth2/totp", `<input type="text" name="totp">`)
			return
		}
		http.Redirect(w, r, "/oauth2/approval?req=r1", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /oauth2/approval", func(w http.ResponseWriter, r *http.Request) {
		form(w, "", `<input type="hidden" name="req" value="r1"><input type="hidden" name="approval" value="approve">`)
		fmt.Fprint(w, `<form method="post"><input type="hidden" name="req" value="r1"><input type="hidden" name="approval" value="rejected"></form>`)
	})
	mux.HandleFunc("POST /oauth2/approval", func(w http.ResponseWriter, r *http.Request) {
		dex.posts.Add(1)
		if r.FormValue("approval") != "approve" || r.URL.Query().Get("req") != "r1" {
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		http.Redirect(w, r, "/oauth2/device/callback?code=c&state=s1", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /oauth2/device/callback", func(w http.ResponseWriter, r *http.Request) {
		dex.approved.Store(true)
		fmt.Fprint(w, `<html><body><h1>Login Successful</h1></body></html>`)
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, dex.approved.Load())
	})
	dex.Server = httptest.NewServer(mux)
	t.Cleanup(dex.Close)
	return dex
}

func (dex *fakeDex) verification() string { return dex.URL + "/oauth2/device?user_code=" + testCode }

func TestDeviceLoginAnswersTheDexForms(t *testing.T) {
	dex := newFakeDex(t)
	if err := deviceLogin(t.Context(), dex.URL, dex.verification(), testEmail, testPassword); err != nil {
		t.Fatal(err)
	}
	// device code, password, approval
	if !dex.approved.Load() || dex.posts.Load() != 3 {
		t.Fatalf("approved %v after %d posts", dex.approved.Load(), dex.posts.Load())
	}
}

func TestDeviceLoginStopsWhenAFormComesBack(t *testing.T) {
	for name, tc := range map[string]struct {
		target, password, want string
	}{
		"wrong password": {"/oauth2/device?user_code=" + testCode, "wrong", "rejected the password"},
		"wrong code":     {"/oauth2/device?user_code=WXYZ-WXYZ", testPassword, "rejected the device code"},
	} {
		t.Run(name, func(t *testing.T) {
			dex := newFakeDex(t)
			err := deviceLogin(t.Context(), dex.URL, dex.URL+tc.target, testEmail, tc.password)
			if err == nil || !strings.Contains(err.Error(), tc.want) || dex.approved.Load() || dex.posts.Load() > 2 {
				t.Fatalf("error %v after %d posts", err, dex.posts.Load())
			}
		})
	}
}

func TestDeviceLoginRefusesMFAAndOtherOrigins(t *testing.T) {
	dex := newFakeDex(t)
	dex.mfa = true
	if err := deviceLogin(t.Context(), dex.URL, dex.verification(), testEmail, testPassword); err == nil || !strings.Contains(err.Error(), "MFA") {
		t.Fatalf("MFA: %v", err)
	}

	other := newFakeDex(t)
	if err := deviceLogin(t.Context(), dex.URL, other.verification(), testEmail, testPassword); err == nil || other.posts.Load() != 0 {
		t.Fatalf("foreign verification URL: %v", err)
	}
	redirecting := newFakeDex(t)
	redirecting.elsewhere = other.URL + "/oauth2/auth/local/login"
	if err := deviceLogin(t.Context(), redirecting.URL, redirecting.verification(), testEmail, testPassword); err == nil ||
		!strings.Contains(err.Error(), "outside") || other.posts.Load() != 0 {
		t.Fatalf("foreign redirect: %v", err)
	}
}

// TestHelperNetBird stands in for "netbird ssh": it prints the login
// instructions on standard error unless its token is cached, waits for the
// fake Dex to approve the device, then runs the session.
func TestHelperNetBird(t *testing.T) {
	dex := os.Getenv("SSHLOGIN_HELPER_DEX")
	if dex == "" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	if os.Getenv("SSHLOGIN_HELPER_CACHED") == "" {
		fmt.Fprintf(os.Stderr, "SSH authentication required.\n%s/oauth2/device?user_code=%s\nOr visit: %s/oauth2/device and enter code: %s\nWaiting for authentication...\n", dex, testCode, dex, testCode)
		for !approved(dex) {
			time.Sleep(20 * time.Millisecond)
		}
		fmt.Print(authenticated)
	}
	input, _ := io.ReadAll(os.Stdin)
	fmt.Printf("session %s %s", strings.Join(args, " "), input)
	os.Exit(len(input) % 2)
}

func approved(dex string) bool {
	response, err := http.Get(dex + "/status")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return string(body) == "true"
}

func TestRunSignsInOnlyWhenNetBirdAsks(t *testing.T) {
	for name, cached := range map[string]bool{"fresh login": false, "cached token": true} {
		t.Run(name, func(t *testing.T) {
			dex := newFakeDex(t)
			t.Setenv("SSHLOGIN_HELPER_DEX", dex.URL)
			if cached {
				t.Setenv("SSHLOGIN_HELPER_CACHED", "1")
			}
			var reads atomic.Int32
			login := func(context.Context) (string, string, error) {
				reads.Add(1)
				return testEmail, testPassword, nil
			}
			var stdout, stderr bytes.Buffer
			argv := []string{os.Args[0], "-test.run=^TestHelperNetBird$", "--", "root@gru-1-db-1", "hostname"}
			if err := run(t.Context(), argv, strings.NewReader("ok"), &stdout, &stderr, dex.URL, login); err != nil {
				t.Fatalf("%v\n%s", err, stderr.String())
			}
			if stdout.String() != "session root@gru-1-db-1 hostname ok" {
				t.Fatalf("stdout %q", stdout.String())
			}
			if want := int32(1); cached {
				want = 0
				if reads.Load() != want || stderr.Len() != 0 {
					t.Fatalf("cached token read the Vault %d times, stderr %q", reads.Load(), stderr.String())
				}
			} else if reads.Load() != want || !dex.approved.Load() || !strings.Contains(stderr.String(), "user_code="+testCode) {
				t.Fatalf("fresh login: %d Vault reads, approved %v, stderr %q", reads.Load(), dex.approved.Load(), stderr.String())
			}
		})
	}
}

func TestRunStopsTheClientWhenLoginFailsAndKeepsItsExitStatus(t *testing.T) {
	dex := newFakeDex(t)
	t.Setenv("SSHLOGIN_HELPER_DEX", dex.URL)
	argv := []string{os.Args[0], "-test.run=^TestHelperNetBird$", "--", "root@gru-1-db-1"}
	wrong := func(context.Context) (string, string, error) { return testEmail, "wrong", nil }
	start := time.Now()
	err := run(t.Context(), argv, strings.NewReader(""), io.Discard, io.Discard, dex.URL, wrong)
	if err == nil || !strings.Contains(err.Error(), "NetBird SSH login: the identity provider rejected the password") ||
		strings.Contains(err.Error(), "wrong") || time.Since(start) > 4*time.Second {
		t.Fatalf("login failure: %v after %s", err, time.Since(start))
	}

	t.Setenv("SSHLOGIN_HELPER_CACHED", "1")
	err = run(t.Context(), argv, strings.NewReader("odd"), io.Discard, io.Discard, dex.URL, wrong)
	if err == nil || !strings.Contains(err.Error(), "netbird ssh: exit status 1") {
		t.Fatalf("session failure: %v", err)
	}
}

func TestCopyOutputDropsOnlyTheLeadingLoginLine(t *testing.T) {
	for input, want := range map[string]string{
		authenticated + "secret\n":         "secret\n",
		"secret\n" + authenticated:         "secret\n" + authenticated,
		"short":                            "short",
		"":                                 "",
		authenticated:                      "",
		"Authentication successful!" + "x": "Authentication successful!x",
	} {
		var output bytes.Buffer
		if err := copyOutput(&output, strings.NewReader(input)); err != nil || output.String() != want {
			t.Errorf("copyOutput(%q) = %q, %v; want %q", input, output.String(), err, want)
		}
	}
}

func TestVerificationURL(t *testing.T) {
	for line, want := range map[string]string{
		"https://netbird.terrascale.tech/oauth2/device?user_code=ABCD-EFGH\n":                 "https://netbird.terrascale.tech/oauth2/device?user_code=ABCD-EFGH",
		"Or visit: https://netbird.terrascale.tech/oauth2/device and enter code: ABCD-EFGH\n": "",
		"https://netbird.terrascale.tech/oauth2/device\n":                                     "",
		"Waiting for authentication...\n":                                                     "",
	} {
		if got := verificationURL(line); got != want {
			t.Errorf("verificationURL(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestRunRejectsBadArgumentsBeforeVaultOrNetBird(t *testing.T) {
	vault := "ocid1.vault.oc1.sa-saopaulo-1.aaaa.bbbb"
	for _, args := range [][]string{
		{"--", "root@gru-1-db-1", "hostname"},
		{"--vault-id", "ocid1.key.oc1.sa-saopaulo-1.aaaa.bbbb", "--", "root@gru-1-db-1"},
		{"--vault-id", vault},
		{"--vault-id", vault, "--netbird", " ", "--", "root@gru-1-db-1"},
		{"--vault-id", vault, "-L", "1:127.0.0.1:2", "root@gru-1-db-1"},
	} {
		if err := Run(t.Context(), args, io.Discard); err == nil {
			t.Errorf("Run(%q) accepted", args)
		}
	}
	var help bytes.Buffer
	if err := Run(t.Context(), []string{"--help"}, &help); err != nil || !strings.Contains(help.String(), passwordSecret) {
		t.Fatalf("help: %v %q", err, help.String())
	}
}
