#!/usr/bin/env python3
"""Zero-configuration policy guard.

Fails the change when it introduces an operator-facing on/off switch: a
feature flag, enable/disable variable, opt-in setting, boolean enabled
configuration key, deploy toggle or kill switch in code, config or CI
(AGENTS.md, "Zero configuration", user decision 2026-10-09, do not revert).

Boundary (AGENTS.md, "Migration scope and safety"): the policy governs
operator and deployment configuration - environment variables, compose
inputs, workflow toggles and application config structs. Per-tenant state
stored in the database (for example a workspace's integration connection
rows) is customer data, not operator configuration, and stays out of scope.
Test code is out of scope (fakes and skip paths belong there by policy).

A line the policy must nevertheless keep (an unavoidable third-party name)
carries a trailing `# zero-config: <reason>` comment; the reason must be
non-empty.

Vendored from the existing TerraScale policy guard (ts-builder guard ref
8dacab4), with GitHub workflow paths. Kept locally so PR checks need no
private repository credentials.

Usage: zero-config-check.py <base-sha> <head-sha>
"""
import re
import subprocess
import sys

# Operator configuration surfaces this repository exposes. Files outside
# these surfaces are customer data, product code or tests (see docstring).
CONFIG_SUFFIXES = (".env", ".toml", ".ini", ".mk")


def is_config_surface(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name.startswith(".env") or name.startswith("docker-compose.") or name.startswith("compose."):
        return True
    if name == "Makefile" or name.startswith("Dockerfile") or name.startswith("Containerfile"):
        return True
    if path.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
        return True
    if name.endswith(CONFIG_SUFFIXES):
        return True
    # Go application configuration: the config packages, plus any file
    # binding environment variables (envconfig struct tags, os.Getenv).
    if path.endswith(".go") and (
        "/config/" in f"/{path}" or path.rsplit("/", 1)[-1] == "config.go"
    ):
        return True
    return False


# Switch-shaped names: identifiers or keys that enable, disable, toggle or
# gate a feature. Case-insensitive. Deliberately narrow so ordinary prose
# and unrelated words (sslmode=disable, "disable the cache" in a comment
# about removing one) do not trip it: the token must look like a name being
# declared or set, not a sentence.
SWITCH_PATTERNS = [
    re.compile(r"\b[A-Z0-9_]*(?:ENABLE|DISABLE)[A-Z0-9_]*\b"),  # env keys
    re.compile(r"\b(?:feature[_-]?flags?|kill[_-]?switch|opt[_-]?in|opt[_-]?out|toggles?)\b", re.I),
    re.compile(r"\b(?:is[_-])?enabled\b\s*[:=]", re.I),  # yaml/json/go keys
    re.compile(r"\b(?:is[_-])?disabled\b\s*[:=]", re.I),
    re.compile(r"\benabled\s+bool\b", re.I),  # go config struct fields
    re.compile(r"\bdisabled\s+bool\b", re.I),
    re.compile(r"\bhost[_-]?telemetry(?:\s+bool\b|\s*[:=])", re.I),
    re.compile(r'type:\s*boolean\b', re.I),  # workflow_dispatch inputs
]

EXEMPT = re.compile(r"#\s*zero-config:\s*\S")


def split_app_config_lines(path: str, head: str) -> set[int]:
    """Find operator config declarations without scanning unrelated app state."""
    if not path.startswith("internal/app/") or not path.endswith(".go"):
        return set()
    source = subprocess.run(
        ["git", "show", f"{head}:{path}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    lines = set()
    in_config = False
    for lineno, line in enumerate(source.splitlines(), 1):
        declaration = re.match(r"^type (?:Config|[A-Z]\w*Config) struct\s*\{", line)
        if declaration:
            in_config = True
        if in_config:
            lines.add(lineno)
        if line.startswith("}") or declaration and "}" in line:
            in_config = False
    return lines


def added_lines(base: str, head: str):
    """Yield (path, lineno, text) for every line added between base and head."""
    diff = subprocess.run(
        ["git", "diff", "--unified=0", "--diff-filter=ACMR", base, head],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    path = None
    lineno = 0
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            path = line[6:]
            continue
        if line.startswith("@@"):
            # @@ -old,count +new,count @@ context
            m = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if m:
                lineno = int(m.group(1))
            continue
        if path and line.startswith("+"):
            yield path, lineno, line[1:]
            lineno += 1


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <base-sha> <head-sha>", file=sys.stderr)
        return 2
    base, head = sys.argv[1], sys.argv[2]
    violations = []
    scanned = 0
    split_configs = {}
    for path, lineno, text in added_lines(base, head):
        # Go env binding outside the config packages is still operator
        # configuration; catch it by content instead of path. Other Go
        # lines are scanned only inside the config surfaces.
        go_env_binding = path.endswith(".go") and (
            'envconfig:"' in text or "os.Getenv(" in text
        )
        if path.endswith("_test.go"):
            continue
        if path.endswith(".go"):
            if not go_env_binding and not is_config_surface(path):
                if path not in split_configs:
                    split_configs[path] = split_app_config_lines(path, head)
                if lineno not in split_configs[path]:
                    continue
        elif not is_config_surface(path):
            continue
        if EXEMPT.search(text):
            continue
        scanned += 1
        for pattern in SWITCH_PATTERNS:
            if pattern.search(text):
                violations.append((path, lineno, text.strip()))
                break
    for path, lineno, text in violations:
        print(f"::error file={path},line={lineno}::zero-config violation: switch-style configuration added: {text}")
        print("   The policy (AGENTS.md) forbids on/off switches, feature flags and opt-in settings.")
        print('   If this is an unavoidable third-party name, append "# zero-config: <one-line reason>".')
    if violations:
        print(f"zero-config guard: {len(violations)} violation(s) in {scanned} added configuration line(s).")
        return 1
    print(f"zero-config guard: clean ({scanned} added configuration line(s) scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
