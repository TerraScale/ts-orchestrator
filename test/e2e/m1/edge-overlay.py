import json
import pathlib
import subprocess
import sys

repo = pathlib.Path(sys.argv[1]).resolve()
work = pathlib.Path(sys.argv[2])
areas = ["internal/edge", "internal/observability"]
current = subprocess.check_output(["git", "-C", str(repo), "ls-files", *areas], text=True)
base = subprocess.check_output(
    ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "origin/main", *areas],
    text=True,
)
base_paths = set(base.splitlines())
replacements = {}
for name in sorted(set(current.splitlines()) | base_paths):
    if not name.endswith(".go") or pathlib.PurePosixPath(name).parent.as_posix() not in areas:
        continue
    original = repo / name
    content = (
        subprocess.check_output(
            ["git", "-C", str(repo), "show", f"origin/main:{name}"]
        )
        if name in base_paths
        else f"package {original.parent.name}\n".encode()
    )
    if name in {"internal/edge/durations.go", "internal/edge/upstream.go"}:
        content = original.read_bytes()
    if name == "internal/edge/edge.go":
        source = content.decode()
        source = source.replace(
            "lastHealthProbe    atomic.Int64",
            "lastHealthProbe    atomic.Int64\n\trequestDurations sync.Map\n\tupstreamSockets upstreamBudget",
        )
        source = source.replace(
            "e.peers = newPeerTransport(e)",
            "e.peers = durationTransport{newPeerTransport(e)}",
        )
        source = source.replace(
            "\n\te.proxy = &httputil.ReverseProxy{",
            "\n\te.local = durationTransport{e.local}\n\te.proxy = &httputil.ReverseProxy{",
        )
        source = source.replace(
            'countResponses("http", http.HandlerFunc(',
            'countResponses("http", e.measureRequests(http.HandlerFunc(',
        ).replace(
            "\n\t\t})),\n\t\tReadHeaderTimeout",
            "\n\t\t}))),\n\t\tReadHeaderTimeout",
        ).replace(
            'countResponses("https", http.HandlerFunc(e.serveHTTPS))',
            'countResponses("https", e.measureRequests(http.HandlerFunc(e.serveHTTPS)))',
        )
        content = source.encode()
    target = work / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
    replacements[str(original)] = str(target)
(work / "overlay.json").write_text(json.dumps({"Replace": replacements}))
