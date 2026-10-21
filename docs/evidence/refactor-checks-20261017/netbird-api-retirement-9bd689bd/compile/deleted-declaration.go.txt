func TestAPIRefusesRedirectsAndHidesBodies(t *testing.T) {
	redirect := httptest.NewServer(http.RedirectHandler("https://attacker.invalid/api/groups", http.StatusFound))
	defer redirect.Close()
	api, err := NewAPI(redirect.URL, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	var out []apiGroup
	var status *StatusError
	if err := api.do(t.Context(), "GET", "/groups", nil, &out); !errors.As(err, &status) || status.Status != http.StatusFound {
		t.Fatalf("redirect: %v", err)
	}
	f := newFakeManager(t)
	f.failStatus = http.StatusInternalServerError
	err = f.api(t).do(t.Context(), "GET", "/groups", nil, &out)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), testPAT) {
		t.Fatalf("error leaked: %v", err)
	}
	for _, url := range []string{"http://netbird.terrascale.tech", "ftp://127.0.0.1", "https://x/api", "https://u:p@x", "https://x?q"} {
		if _, err := NewAPI(url, testPAT); err == nil {
			t.Errorf("accepted %s", url)
		}
	}
	for _, url := range []string{"http://127.0.0.1:8080", "http://[::1]:1", "https://netbird.terrascale.tech"} {
		if _, err := NewAPI(url, testPAT); err != nil {
			t.Errorf("refused %s: %v", url, err)
		}
	}
}