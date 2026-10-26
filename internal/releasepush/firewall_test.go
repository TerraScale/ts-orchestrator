package releasepush

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCloseTCPRemovesDuplicatesAndPropagatesCommandFailures(t *testing.T) {
	dir := t.TempDir()
	binary, rules := filepath.Join(dir, "iptables"), filepath.Join(dir, "rules")
	script := `#!/bin/sh
if [ "$FIREWALL_TEST_ERROR" = "yes" ]; then echo "xtables lock unavailable" >&2; exit 4; fi
read -r count < "$FIREWALL_TEST_RULES"
case "$*" in
 "-w 2 -C INPUT -p tcp --dport 7464 -j ACCEPT")
  if [ "$count" -eq 0 ]; then echo "Bad rule (does a matching rule exist in that chain?)" >&2; exit 1; fi;;
 "-w 2 -D INPUT -p tcp --dport 7464 -j ACCEPT") printf '%s\n' "$((count-1))" > "$FIREWALL_TEST_RULES";;
 *) echo "unexpected firewall command" >&2; exit 2;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte("2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("FIREWALL_TEST_RULES", rules)
	if err := CloseTCP(t.Context(), 7464); err != nil {
		t.Fatal(err)
	}
	count, _ := os.ReadFile(rules)
	if string(count) != "0\n" {
		t.Fatalf("duplicate rules remain: %q", count)
	}
	t.Setenv("FIREWALL_TEST_ERROR", "yes")
	if err := CloseTCP(t.Context(), 7464); err == nil {
		t.Fatal("command failure reported as rule absent")
	}
	t.Setenv("FIREWALL_TEST_ERROR", "")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := CloseTCP(ctx, 7464); err == nil {
		t.Fatal("cancellation reported as rule absent")
	}
	if err := os.Remove(binary); err != nil {
		t.Fatal(err)
	}
	if err := CloseTCP(t.Context(), 7464); err == nil {
		t.Fatal("missing command reported as rule absent")
	}
}
