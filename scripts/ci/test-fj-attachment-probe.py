#!/usr/bin/env python3
"""Exercise the pinned fj attachment probe against bounded local HTTP fixtures."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


FIXTURE_TOKEN = "fixture-token-do-not-log"
TAG = "image-inputs-fixture"
ASSET_UUID = "fixture-asset-uuid"
EXPECTED_MANIFEST_SHA256 = (
    "773dd889b55136d4b8569560c47b823232eace81a5ccb262cb5aa9970594dd97"
)
EXPECTED_MANIFEST_BYTES = 3294
ERROR_BODY = b"Not Found\n"
SUCCESS_BODY = b'{"schema":"fixture.image-inputs.v1"}\n'
SUCCESS_SHA256 = hashlib.sha256(SUCCESS_BODY).hexdigest()
SECRET_QUERY = "fixture-secret-query-do-not-log"


class State:
    def __init__(self, *, mode: str, private: bool = False) -> None:
        self.mode = mode
        self.private = private
        self.draft = False
        self.asset_size = len(SUCCESS_BODY)
        self.browser_url = ""
        self.redirect_url = ""
        self.requests: list[tuple[str, bool]] = []
        self.lock = threading.Lock()

    def record(self, path: str, has_authorization: bool) -> None:
        with self.lock:
            self.requests.append((path, has_authorization))

    def snapshot(self) -> list[tuple[str, bool]]:
        with self.lock:
            return list(self.requests)

    def reset_requests(self) -> None:
        with self.lock:
            self.requests.clear()


def handler_for(state: State, root_origin: str | None = None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def send_body(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            path = urlsplit(self.path).path
            authorization = self.headers.get("Authorization")
            has_authorization = authorization is not None
            valid_token = authorization == f"token {FIXTURE_TOKEN}"
            state.record(path, has_authorization)
            attachment = {
                "id": 33,
                "uuid": ASSET_UUID,
                "name": "image-inputs.json",
                "size": state.asset_size,
                "browser_download_url": state.browser_url,
            }
            release = {
                "id": 22,
                "tag_name": TAG,
                "name": TAG,
                "draft": state.draft,
                "prerelease": True,
                "assets": [attachment],
            }

            if root_origin is None and path == f"/objects/{ASSET_UUID}":
                self.send_body(200, SUCCESS_BODY)
                return
            if path == "/api/v1/version":
                self.send_body(200, b'{"version":"v16.0.0-fixture"}', "application/json")
                return
            if path == "/api/v1/repos/search":
                self.send_body(200, b'{"data":[]}', "application/json")
                return
            if path == "/api/v1/repos/TerraScale/ts-orchestrator":
                body = json.dumps({"private": state.private}).encode()
                self.send_body(200, body, "application/json")
                return
            if path == f"/api/v1/repos/TerraScale/ts-orchestrator/releases/tags/{TAG}":
                self.send_body(200, json.dumps(release).encode(), "application/json")
                return
            if path == "/api/v1/repos/TerraScale/ts-orchestrator/releases":
                body = json.dumps([release]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Total-Count", "1")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/v1/repos/TerraScale/ts-orchestrator/releases/22/assets/33":
                self.send_body(200, json.dumps(attachment).encode(), "application/json")
                return
            if path == f"/attachments/{ASSET_UUID}":
                if state.mode == "error-body":
                    self.send_body(404, ERROR_BODY)
                    return
                if state.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", state.redirect_url)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if state.mode == "auth-vs-anonymous" and not valid_token:
                    self.send_body(404, ERROR_BODY)
                    return
                if state.mode == "private" and not valid_token:
                    self.send_body(404, ERROR_BODY)
                    return
                self.send_body(200, SUCCESS_BODY)
                return
            self.send_body(404, ERROR_BODY)

    return Handler


def start_server(state: State, root_origin: str | None = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(state, root_origin))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    origin = f"http://{host}:{port}"
    return server, thread, origin


def stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def run_probe(
    binary: Path,
    server_origin: str,
    data_home: Path,
    *,
    expected_sha256: str = SUCCESS_SHA256,
    expected_bytes: int = len(SUCCESS_BODY),
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    data_home.mkdir(mode=0o700)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "XDG_DATA_HOME": str(data_home),
        "NO_COLOR": "1",
        "TERM": "dumb",
        "LANG": "C.UTF-8",
    }
    loader_path = os.environ.get("LD_LIBRARY_PATH")
    if loader_path:
        env["LD_LIBRARY_PATH"] = loader_path
    auth = subprocess.run(
        [str(binary), "--host", server_origin, "auth", "add-token"],
        input=f"{FIXTURE_TOKEN}\n",
        text=True,
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )
    if auth.returncode != 0:
        raise AssertionError("fixture token setup failed")

    result = subprocess.run(
        [
            str(binary),
            "--host",
            server_origin,
            "release",
            "--repo",
            "TerraScale/ts-orchestrator",
            "asset",
            "probe",
            TAG,
            "image-inputs.json",
            "--expect-sha256",
            expected_sha256,
            "--expect-bytes",
            str(expected_bytes),
            "--compare-anonymous",
        ],
        text=True,
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )
    if FIXTURE_TOKEN in result.stdout or FIXTURE_TOKEN in result.stderr:
        raise AssertionError("fixture token appeared in fj output")
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError("fj did not return one JSON diagnostic object") from error
    if not isinstance(report, dict):
        raise AssertionError("fj diagnostic was not a JSON object")
    return result, report


def run_download(
    binary: Path, server_origin: str, data_home: Path
) -> tuple[subprocess.CompletedProcess[str], Path]:
    data_home.mkdir(mode=0o700)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "XDG_DATA_HOME": str(data_home),
        "NO_COLOR": "1",
        "TERM": "dumb",
        "LANG": "C.UTF-8",
    }
    loader_path = os.environ.get("LD_LIBRARY_PATH")
    if loader_path:
        env["LD_LIBRARY_PATH"] = loader_path
    auth = subprocess.run(
        [str(binary), "--host", server_origin, "auth", "add-token"],
        input=f"{FIXTURE_TOKEN}\n",
        text=True,
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )
    if auth.returncode != 0:
        raise AssertionError("fixture token setup failed")
    output = data_home / "downloaded-asset"
    result = subprocess.run(
        [
            str(binary), "--host", server_origin, "release", "--repo",
            "TerraScale/ts-orchestrator", "asset", "download", TAG,
            "image-inputs.json", "--output", str(output),
        ],
        text=True,
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )
    if FIXTURE_TOKEN in result.stdout or FIXTURE_TOKEN in result.stderr:
        raise AssertionError("fixture token appeared in fj output")
    return result, output


def auth_requests(state: State) -> list[bool]:
    return [authorized for path, authorized in state.snapshot() if path.startswith("/attachments/")]


def assert_no_sensitive_output(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stdout + result.stderr
    lines = combined.splitlines()
    sanitized_lines = []
    index = 0
    while index < len(lines):
        if (
            lines[index] == "Location:"
            and index + 1 < len(lines)
            and lines[index + 1].lstrip().startswith("src/release/probe.rs:")
        ):
            index += 2
            continue
        sanitized_lines.append(lines[index])
        index += 1
    combined = "\n".join(sanitized_lines)
    for forbidden in (
        FIXTURE_TOKEN,
        ASSET_UUID,
        SECRET_QUERY,
        "/attachments/",
        "/objects/",
        "Authorization",
        "Location",
    ):
        if forbidden in combined:
            raise AssertionError("fj output contained a credential, header name, raw path, or query")


def case_error_body(binary: Path, root_state: State, root_origin: str, temp: Path) -> None:
    root_state.mode = "error-body"
    root_state.private = False
    root_state.asset_size = EXPECTED_MANIFEST_BYTES
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.reset_requests()
    result, report = run_probe(
        binary,
        root_origin,
        temp / "error-body-data",
        expected_sha256=EXPECTED_MANIFEST_SHA256,
        expected_bytes=EXPECTED_MANIFEST_BYTES,
    )
    authenticated = report["authenticated"]
    if result.returncode == 0 or authenticated["status"] != 404:
        raise AssertionError("HTTP error-body case did not fail with its response status")
    if authenticated["body_bytes"] != len(ERROR_BODY):
        raise AssertionError("HTTP error-body byte count was not reported")
    if authenticated["body_sha256"] != hashlib.sha256(ERROR_BODY).hexdigest():
        raise AssertionError("HTTP error-body SHA-256 was not reported")
    if authenticated["sent_authorization"] is not True:
        raise AssertionError("same-origin attachment request did not use the fixture token")
    assert_no_sensitive_output(result)


def case_download_http_status(binary: Path, root_state: State, root_origin: str, temp: Path) -> None:
    root_state.mode = "error-body"
    root_state.private = False
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.reset_requests()
    result, output = run_download(binary, root_origin, temp / "download-404-data")
    if result.returncode == 0 or output.exists():
        raise AssertionError("attachment HTTP 404 was accepted or written to disk")
    if "release attachment HTTP status 404" not in result.stderr:
        raise AssertionError("attachment HTTP status was not reported safely")
    if auth_requests(root_state) != [True]:
        raise AssertionError("download did not use the authenticated attachment route")
    assert_no_sensitive_output(result)


def case_download_success(binary: Path, root_state: State, root_origin: str, temp: Path) -> None:
    root_state.mode = "auth-vs-anonymous"
    root_state.private = False
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.reset_requests()
    result, output = run_download(binary, root_origin, temp / "download-200-data")
    if result.returncode != 0 or not output.exists() or output.read_bytes() != SUCCESS_BODY:
        raise AssertionError("authenticated attachment download did not return exact bytes")
    if auth_requests(root_state) != [True]:
        raise AssertionError("download did not use only the authenticated attachment route")
    assert_no_sensitive_output(result)


def case_download_cross_origin(
    binary: Path,
    root_state: State,
    root_origin: str,
    sink_state: State,
    sink_origin: str,
    temp: Path,
) -> None:
    root_state.mode = "private"
    root_state.private = False
    root_state.browser_url = f"{sink_origin}/objects/{ASSET_UUID}?{SECRET_QUERY}=value"
    root_state.reset_requests()
    sink_state.reset_requests()
    result, output = run_download(binary, root_origin, temp / "download-cross-origin-data")
    if result.returncode == 0 or output.exists():
        raise AssertionError("cross-origin initial attachment URL was accepted")
    if auth_requests(root_state) or sink_state.snapshot():
        raise AssertionError("download sent a request to an untrusted attachment origin")
    assert_no_sensitive_output(result)


def case_download_redirect(
    binary: Path,
    root_state: State,
    root_origin: str,
    sink_state: State,
    sink_origin: str,
    temp: Path,
) -> None:
    root_state.mode = "redirect"
    root_state.private = False
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.redirect_url = f"{sink_origin}/objects/{ASSET_UUID}?{SECRET_QUERY}=value"
    sink_state.mode = "object"
    root_state.reset_requests()
    sink_state.reset_requests()
    result, output = run_download(binary, root_origin, temp / "download-redirect-data")
    if result.returncode != 0 or not output.exists() or output.read_bytes() != SUCCESS_BODY:
        raise AssertionError("attachment redirect did not return exact bytes")
    if auth_requests(root_state) != [True]:
        raise AssertionError("initial attachment request lacked authentication")
    if any(authorized for _path, authorized in sink_state.snapshot()):
        raise AssertionError("Authorization reached the cross-origin redirect destination")
    assert_no_sensitive_output(result)


def case_auth_vs_anonymous(
    binary: Path, root_state: State, root_origin: str, temp: Path
) -> None:
    root_state.mode = "auth-vs-anonymous"
    root_state.private = False
    root_state.asset_size = len(SUCCESS_BODY)
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.reset_requests()
    result, report = run_probe(binary, root_origin, temp / "auth-vs-anon-data")
    if result.returncode != 0:
        raise AssertionError("anonymous comparison affected a valid authenticated result")
    if report["authenticated"]["status"] != 200 or not report["authenticated"]["matches_expected"]:
        raise AssertionError("authenticated route did not match its expected content")
    if report["authenticated"]["sent_authorization"] is not True:
        raise AssertionError("authenticated route did not report its credential boundary")
    if report["anonymous"]["skipped"] is not False or report["anonymous"]["status"] != 404:
        raise AssertionError("public release anonymous comparison was not recorded")
    attachment_auth = auth_requests(root_state)
    if attachment_auth != [True, False]:
        raise AssertionError("authenticated and anonymous requests did not remain separate")
    assert_no_sensitive_output(result)


def case_cross_origin_redirect(
    binary: Path,
    root_state: State,
    root_origin: str,
    sink_state: State,
    sink_origin: str,
    temp: Path,
) -> None:
    root_state.mode = "redirect"
    root_state.private = False
    root_state.asset_size = len(SUCCESS_BODY)
    sink_state.mode = "object"
    root_state.redirect_url = f"{sink_origin}/objects/{ASSET_UUID}?{SECRET_QUERY}=value"
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.reset_requests()
    sink_state.reset_requests()
    result, report = run_probe(binary, root_origin, temp / "redirect-data")
    if result.returncode != 0 or report["authenticated"]["status"] != 200:
        raise AssertionError("cross-origin redirect did not return authenticated content")
    if report["authenticated"]["redirect_count"] != 1:
        raise AssertionError("cross-origin redirect count was not reported")
    if report["authenticated"]["initial_origin"] != root_origin:
        raise AssertionError("redirect report did not preserve its initial origin")
    if report["authenticated"]["final_origin"] != sink_origin:
        raise AssertionError("redirect report did not preserve its final origin")
    if report["authenticated"]["redirect_origins"] != [sink_origin]:
        raise AssertionError("redirect origins were not sanitized to origin-only values")
    if any(authorized for _path, authorized in sink_state.snapshot()):
        raise AssertionError("Authorization reached the cross-origin redirect destination")
    assert_no_sensitive_output(result)


def case_private_skip(binary: Path, root_state: State, root_origin: str, temp: Path) -> None:
    root_state.mode = "private"
    root_state.private = True
    root_state.asset_size = len(SUCCESS_BODY)
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.reset_requests()
    result, report = run_probe(binary, root_origin, temp / "private-data")
    if result.returncode != 0 or report["authenticated"]["matches_expected"] is not True:
        raise AssertionError("private repository authenticated route did not pass")
    if report["anonymous"]["skipped"] is not True:
        raise AssertionError("private repository anonymous comparison was not skipped")
    if auth_requests(root_state) != [True]:
        raise AssertionError("private repository attempted an anonymous attachment request")
    assert_no_sensitive_output(result)


def case_draft_skip(binary: Path, root_state: State, root_origin: str, temp: Path) -> None:
    root_state.mode = "private"
    root_state.private = False
    root_state.asset_size = len(SUCCESS_BODY)
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    root_state.reset_requests()
    root_state.draft = True
    result, report = run_probe(binary, root_origin, temp / "draft-data")
    root_state.draft = False
    if result.returncode != 0 or report["authenticated"]["matches_expected"] is not True:
        raise AssertionError("draft release authenticated route did not pass")
    if report["anonymous"]["skipped"] is not True:
        raise AssertionError("draft release anonymous comparison was not skipped")
    if auth_requests(root_state) != [True]:
        raise AssertionError("draft release attempted an anonymous attachment request")
    assert_no_sensitive_output(result)


def case_strict_pins(binary: Path, root_state: State, root_origin: str, temp: Path) -> None:
    root_state.mode = "private"
    root_state.private = False
    root_state.asset_size = len(SUCCESS_BODY)
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    wrong_hash, wrong_hash_report = run_probe(
        binary,
        root_origin,
        temp / "wrong-hash-data",
        expected_sha256="0" * 64,
    )
    if wrong_hash.returncode == 0 or wrong_hash_report["authenticated"]["matches_expected"] is not False:
        raise AssertionError("probe accepted a mismatched expected SHA-256")
    wrong_size, wrong_size_report = run_probe(
        binary,
        root_origin,
        temp / "wrong-size-data",
        expected_bytes=len(SUCCESS_BODY) + 1,
    )
    if wrong_size.returncode == 0 or wrong_size_report["authenticated"]["matches_expected"] is not False:
        raise AssertionError("probe accepted a mismatched expected byte count")
    assert_no_sensitive_output(wrong_hash)
    assert_no_sensitive_output(wrong_size)


def case_cross_origin_browser_url(
    binary: Path,
    root_state: State,
    root_origin: str,
    sink_state: State,
    sink_origin: str,
    temp: Path,
) -> None:
    root_state.mode = "private"
    root_state.private = False
    root_state.asset_size = len(SUCCESS_BODY)
    root_state.browser_url = (
        f"{sink_origin}/objects/{ASSET_UUID}?{SECRET_QUERY}=value"
    )
    root_state.reset_requests()
    sink_state.reset_requests()
    result, report = run_probe(binary, root_origin, temp / "browser-cross-origin-data")
    authenticated = report["authenticated"]
    if result.returncode == 0 or authenticated["status"] is not None:
        raise AssertionError("cross-origin browser URL was treated as an authenticated success")
    if authenticated["sent_authorization"] is not False:
        raise AssertionError("cross-origin browser URL did not report withheld credentials")
    if authenticated["error"] != "origin_mismatch":
        raise AssertionError("cross-origin browser URL lacked its fixed safe error class")
    if report["url_comparison"]["origin_equal"] is not False:
        raise AssertionError("cross-origin browser URL equality was not reported")
    if auth_requests(root_state):
        raise AssertionError("unexpected authenticated request reached the configured origin")
    if any(authorized for _path, authorized in sink_state.snapshot()):
        raise AssertionError("Forgejo Authorization reached the browser URL origin")
    assert_no_sensitive_output(result)


def preflight_report(
    private: bool | None,
    *,
    authenticated_status: int = 200,
    authenticated_matches: bool = True,
    anonymous_skipped: bool = True,
    anonymous_status: int | None = None,
) -> dict[str, object]:
    authenticated_body_bytes = (
        EXPECTED_MANIFEST_BYTES if authenticated_status == 200 else len(ERROR_BODY)
    )
    authenticated_body_sha256 = (
        EXPECTED_MANIFEST_SHA256
        if authenticated_status == 200
        else hashlib.sha256(ERROR_BODY).hexdigest()
    )
    authenticated = {
        "status": authenticated_status,
        "sent_authorization": True,
        "initial_origin": "https://forgejo.example",
        "final_origin": "https://forgejo.example",
        "redirect_count": 0,
        "redirect_origins": [],
        "body_bytes": authenticated_body_bytes,
        "body_sha256": authenticated_body_sha256,
        "matches_expected": authenticated_matches,
        "error": None if authenticated_status == 200 else "http_status",
    }
    if anonymous_skipped:
        anonymous = {
            "skipped": True,
            "status": None,
            "initial_origin": None,
            "final_origin": None,
            "redirect_count": 0,
            "redirect_origins": [],
            "body_bytes": None,
            "body_sha256": None,
            "error": None,
        }
    else:
        anonymous_body_bytes = (
            EXPECTED_MANIFEST_BYTES if anonymous_status == 200 else len(ERROR_BODY)
        )
        anonymous_body_sha256 = (
            EXPECTED_MANIFEST_SHA256
            if anonymous_status == 200
            else hashlib.sha256(ERROR_BODY).hexdigest()
        )
        anonymous = {
            "skipped": False,
            "status": anonymous_status,
            "initial_origin": "https://forgejo.example",
            "final_origin": "https://forgejo.example",
            "redirect_count": 0,
            "redirect_origins": [],
            "body_bytes": anonymous_body_bytes,
            "body_sha256": anonymous_body_sha256,
            "error": None if anonymous_status == 200 else "http_status",
        }
    return {
        "schema": "terrascale.fj-attachment-probe.v1",
        "repository": {"private": private},
        "server_version": "v16.0.5+gitea1.22",
        "release": {
            "tag": TAG,
            "draft": False,
            "prerelease": True,
            "id": 22,
        },
        "asset": {"name": "image-inputs.json", "size": EXPECTED_MANIFEST_BYTES, "id": 33},
        "url_comparison": {
            "origin_equal": True,
            "path_equal": True,
            "query_equal": True,
        },
        "authenticated": authenticated,
        "anonymous": anonymous,
    }


def case_preflight_gates(temp: Path) -> None:
    preflight = Path(__file__).resolve().with_name("preflight-image-input-attachment.sh")
    stub_source = """#!/usr/bin/env bash
set -euo pipefail
printf 'call\\n' >> "$PREFLIGHT_FJ_CALL_LOG"
case ${1:-} in
  auth) cat >/dev/null ;;
  --host)
    cat "$PREFLIGHT_REPORT_PATH"
    exit "$PREFLIGHT_PROBE_STATUS"
    ;;
  *) exit 2 ;;
esac
"""

    cases = (
        ("private-success-skipped", preflight_report(True), True),
        (
            "public-success-anonymous-failure",
            preflight_report(
                False,
                anonymous_skipped=False,
                anonymous_status=404,
            ),
            True,
        ),
        (
            "authenticated-failure-anonymous-success",
            preflight_report(
                False,
                authenticated_status=404,
                authenticated_matches=False,
                anonymous_skipped=False,
                anonymous_status=200,
            ),
            False,
        ),
    )
    for name, report, should_pass in cases:
        case_root = temp / f"preflight-{name}"
        mock_bin = case_root / "bin"
        runner_temp = case_root / "runner-temp"
        mock_bin.mkdir(parents=True, mode=0o700)
        runner_temp.mkdir(mode=0o700)
        report_path = case_root / "report.json"
        report_path.write_text(json.dumps(report))
        fj = mock_bin / "fj"
        fj.write_text(stub_source)
        fj.chmod(0o700)
        env = {
            "PATH": f"{mock_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "RUNNER_TEMP": str(runner_temp),
            "FORGEJO_READ_TOKEN": "fixture-preflight-token-do-not-log",
            "FORGEJO_SERVER_URL": "https://forgejo.example",
            "IMAGE_INPUT_TAG": TAG,
            "IMAGE_INPUT_MANIFEST_SHA256": EXPECTED_MANIFEST_SHA256,
            "IMAGE_INPUT_MANIFEST_BYTES": str(EXPECTED_MANIFEST_BYTES),
            "PREFLIGHT_REPORT_PATH": str(report_path),
            "PREFLIGHT_FJ_CALL_LOG": str(case_root / "fj-calls.log"),
            "PREFLIGHT_PROBE_STATUS": "0" if report["authenticated"]["matches_expected"] else "1",
        }
        loader_path = os.environ.get("LD_LIBRARY_PATH")
        if loader_path:
            env["LD_LIBRARY_PATH"] = loader_path
        result = subprocess.run(
            ["bash", str(preflight)],
            text=True,
            capture_output=True,
            env=env,
            check=False,
            timeout=20,
        )
        leaked_token = "fixture-preflight-token-do-not-log" in result.stdout + result.stderr
        if leaked_token or (result.returncode == 0) != should_pass:
            raise AssertionError(f"preflight case {name} had an unexpected result")

    case_root = temp / "preflight-relative-runner-temp"
    mock_bin = case_root / "bin"
    mock_bin.mkdir(parents=True, mode=0o700)
    report_path = case_root / "report.json"
    report_path.write_text(json.dumps(preflight_report(True)))
    fj = mock_bin / "fj"
    fj.write_text(stub_source)
    fj.chmod(0o700)
    call_log = case_root / "fj-calls.log"
    env = {
        "PATH": f"{mock_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "RUNNER_TEMP": "relative-runner-temp",
        "FORGEJO_READ_TOKEN": "fixture-preflight-token-do-not-log",
        "FORGEJO_SERVER_URL": "https://forgejo.example",
        "IMAGE_INPUT_TAG": TAG,
        "IMAGE_INPUT_MANIFEST_SHA256": EXPECTED_MANIFEST_SHA256,
        "IMAGE_INPUT_MANIFEST_BYTES": str(EXPECTED_MANIFEST_BYTES),
        "PREFLIGHT_REPORT_PATH": str(report_path),
        "PREFLIGHT_FJ_CALL_LOG": str(call_log),
        "PREFLIGHT_PROBE_STATUS": "0",
    }
    loader_path = os.environ.get("LD_LIBRARY_PATH")
    if loader_path:
        env["LD_LIBRARY_PATH"] = loader_path
    result = subprocess.run(
        ["bash", str(preflight)],
        cwd=case_root,
        text=True,
        capture_output=True,
        env=env,
        check=False,
        timeout=20,
    )
    if (
        result.returncode != 2
        or "RUNNER_TEMP must be an absolute path" not in result.stderr
        or call_log.exists()
        or "fixture-preflight-token-do-not-log" in result.stdout + result.stderr
    ):
        raise AssertionError("relative RUNNER_TEMP did not fail before fj calls")
    print("image-input preflight gate fixture passed cases=4")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: test-fj-attachment-probe.py PATH_TO_PINNED_FJ", file=sys.stderr)
        return 2
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        print("pinned fj binary is not executable", file=sys.stderr)
        return 2

    root_state = State(mode="auth-vs-anonymous")
    sink_state = State(mode="object")
    sink, sink_thread, sink_origin = start_server(sink_state)
    root, root_thread, root_origin = start_server(root_state, root_origin="configured")
    root_state.browser_url = f"{root_origin}/attachments/{ASSET_UUID}"
    try:
        with tempfile.TemporaryDirectory(prefix="fj-attachment-fixture-") as temporary:
            temp = Path(temporary)
            case_error_body(binary, root_state, root_origin, temp)
            case_download_http_status(binary, root_state, root_origin, temp)
            case_download_success(binary, root_state, root_origin, temp)
            case_auth_vs_anonymous(binary, root_state, root_origin, temp)
            case_cross_origin_redirect(
                binary, root_state, root_origin, sink_state, sink_origin, temp
            )
            case_private_skip(binary, root_state, root_origin, temp)
            case_draft_skip(binary, root_state, root_origin, temp)
            case_strict_pins(binary, root_state, root_origin, temp)
            case_cross_origin_browser_url(
                binary, root_state, root_origin, sink_state, sink_origin, temp
            )
            case_download_cross_origin(
                binary, root_state, root_origin, sink_state, sink_origin, temp
            )
            case_download_redirect(
                binary, root_state, root_origin, sink_state, sink_origin, temp
            )
            case_preflight_gates(temp)
    finally:
        stop_server(root, root_thread)
        stop_server(sink, sink_thread)
    print("pinned fj attachment probe fixture passed cases=11")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
