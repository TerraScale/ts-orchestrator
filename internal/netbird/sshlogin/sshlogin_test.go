package sshlogin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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

func approved(dex string) bool {
	response, err := http.Get(dex + "/status")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return string(body) == "true"
}
