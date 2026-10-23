#!/usr/bin/env python3
"""USER RUN ONLY: install a native project key response without displaying it."""

import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys

REPO = "TerraScale/ts-orchestrator"
ENVIRONMENT = "production"
SECRET = "E2E_PROJECT_CREDENTIAL"
ID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")
KEY = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}_[0123456789abcdefghjkmnpqrstvwxyz]{52}")
DATABASE = re.compile(r"[a-z][a-z0-9_-]{0,62}")
VARIABLES = ("E2E_ORGANIZATION_ID", "E2E_PROJECT_ID", "E2E_DATABASE", "E2E_UNRELATED_DATABASE")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field; installation refused.")
        result[key] = value
    return result


def parse_json(raw):
    def invalid_constant(_):
        raise ValueError("Non-JSON numeric constant.")

    try:
        return json.loads(raw, object_pairs_hook=no_duplicates,
                          parse_constant=invalid_constant)
    except (ValueError, UnicodeError):
        raise ValueError("Invalid JSON; installation refused.") from None


def validate(raw, expected, now):
    if not raw or len(raw.encode("utf-8")) > 65536:
        raise ValueError("Native create-response JSON must fit within 64 KiB.")
    body = parse_json(raw)
    if not isinstance(body, dict) or not isinstance(body.get("api_key"), dict):
        raise ValueError("Paste the native key creation response with api_key and key.")
    metadata = body["api_key"]
    for field in ("id", "organization_id", "project_id"):
        if not isinstance(metadata.get(field), str) or not ID.fullmatch(metadata[field]):
            raise ValueError("Native key, organization and project ids are required.")
    key = body.get("key")
    if not isinstance(key, str) or not KEY.fullmatch(key) or not key.startswith(metadata["id"] + "_"):
        raise ValueError("Native key string must match its metadata id.")
    if not isinstance(metadata.get("database"), str) or not DATABASE.fullmatch(metadata["database"]):
        raise ValueError("One explicit database restriction is required.")
    if metadata.get("scopes") != ["documents:read"]:
        raise ValueError("Only the exact documents:read scope is allowed.")
    try:
        expiry = dt.datetime.fromisoformat(metadata["expires_at"].replace("Z", "+00:00"))
        valid_expiry = now < expiry <= now + dt.timedelta(hours=24)
    except (KeyError, TypeError, ValueError, AttributeError):
        valid_expiry = False
    if not valid_expiry:
        raise ValueError("An explicit future expiry within 24 hours is required.")
    for field, variable in (("organization_id", VARIABLES[0]), ("project_id", VARIABLES[1]), ("database", VARIABLES[2])):
        if metadata[field] != expected.get(variable):
            raise ValueError("Credential metadata must match the approved production environment variables.")
    unrelated = expected.get(VARIABLES[3])
    if not isinstance(unrelated, str) or not DATABASE.fullmatch(unrelated) or unrelated == metadata["database"]:
        raise ValueError("An owner-confirmed existing different database in the same approved project is required.")
    return metadata


def read_hidden_json():
    if not sys.stdin.isatty():
        raise ValueError("Run interactively in a private terminal; piped secret entry is refused.")
    try:
        import termios
    except ImportError:
        raise ValueError("Safe terminal echo control is unavailable; secret entry refused.") from None
    try:
        fd = sys.stdin.fileno()
        original = termios.tcgetattr(fd)
    except (termios.error, OSError, ValueError):
        raise ValueError("Safe terminal echo control is unavailable; secret entry refused.") from None

    def interrupted(signum, frame):
        raise SystemExit("Hidden credential entry stopped; no value displayed.")

    handlers = {}
    try:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            handlers[sig] = signal.signal(sig, interrupted)
        hidden = original.copy()
        hidden[3] &= ~(termios.ECHO | termios.ECHONL)
        # TCSANOW preserves all queued paste lines; getpass flushes them per prompt.
        termios.tcsetattr(fd, termios.TCSANOW, hidden)
        print("Paste native create-response JSON (hidden; empty line finishes): ", end="", file=sys.stderr, flush=True)
        raw = ""
        while True:
            line = sys.stdin.readline(65537 - len(raw))
            raw += line
            if not line.strip() or len(raw.encode("utf-8")) > 65536:
                return raw
            try:
                parse_json(raw)
                return raw
            except ValueError:
                continue
    except (termios.error, OSError):
        raise ValueError("Safe terminal input failed; secret entry refused.") from None
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSANOW, original)
        except (termios.error, OSError):
            raise ValueError("Terminal restoration failed; stop using this terminal until echo is restored.") from None
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
            print(file=sys.stderr)


def gh(args, data=None):
    env = os.environ.copy()
    env.pop("GH_DEBUG", None)
    env["GH_HOST"] = "github.com"
    env["GH_PROMPT_DISABLED"] = "1"
    try:
        result = subprocess.run(["gh", *args], input=data, env=env, check=True,
                                stdout=subprocess.PIPE if data is None else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=60)
    except (OSError, subprocess.SubprocessError):
        raise ValueError("GitHub operation failed; diagnostic output suppressed to protect credentials.") from None
    return parse_json(result.stdout) if data is None else None


def preflight():
    account = gh(["api", "user"])
    repository = gh(["api", "repos/" + REPO])
    environment = gh(["api", "repos/" + REPO + "/environments/" + ENVIRONMENT])
    if account.get("login") != "MarioGK" or repository.get("full_name") != REPO or environment.get("name") != ENVIRONMENT:
        raise ValueError("Expected GitHub account MarioGK, repository TerraScale/ts-orchestrator and environment production.")
    if environment.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        raise ValueError("Approved main-only production environment branch protection is required before secret entry.")
    policies = gh(["api", "repos/" + REPO + "/environments/" + ENVIRONMENT + "/deployment-branch-policies"])
    branches = policies.get("branch_policies", [])
    if policies.get("total_count") != 1 or len(branches) != 1 or branches[0].get("name") != "main" or branches[0].get("type") != "branch":
        raise ValueError("Production must allow exactly the main branch: no tags, wildcards or additional policies.")
    variables = gh(["api", "repos/" + REPO + "/environments/" + ENVIRONMENT + "/variables"])
    expected = {v["name"]: v["value"] for v in variables.get("variables", []) if v.get("name") in VARIABLES}
    if any(not expected.get(name) for name in VARIABLES):
        raise ValueError("The parent must prepare all four approved production environment variables first.")
    if (any(not isinstance(expected[name], str) or not ID.fullmatch(expected[name])
            for name in (VARIABLES[0], VARIABLES[1])) or
            any(not isinstance(expected[name], str) or not DATABASE.fullmatch(expected[name])
                for name in (VARIABLES[2], VARIABLES[3])) or
            expected[VARIABLES[2]] == expected[VARIABLES[3]]):
        raise ValueError("Approved organization/project must have native identifiers and both databases must have distinct canonical names.")
    return expected


def install():
    expected = preflight()
    if not sys.stdin.isatty():
        raise ValueError("Run interactively in a private terminal; piped secret entry is refused.")
    print("Verified MarioGK / TerraScale/ts-orchestrator / production.")
    target = expected[VARIABLES[1]] + "/" + expected[VARIABLES[3]]
    print("Owner must confirm existing target: organization " + expected[VARIABLES[0]] + ", same approved project/negative database " + target +
          ". Confirm it contains one document and has no key; the native key must restrict only the positive database " + expected[VARIABLES[2]] + ". A missing database cannot prove isolation.")
    if input("After owner confirmation of this exact existing target, type " + target + ": ") != target:
        raise ValueError("Exact existing negative project/database confirmation required; installation refused.")
    raw = read_hidden_json()
    metadata = validate(raw, expected, dt.datetime.now(dt.timezone.utc))
    gh(["secret", "set", "--repo", REPO, "--env", ENVIRONMENT, SECRET], data=raw.encode("utf-8"))
    print("Installed E2E_PROJECT_CREDENTIAL (value hidden); project " + metadata["project_id"] + ", database " + metadata["database"] + ".")
    print("Installation is prepared; the approved manual production run must still prove access and denials.")


def self_test():
    import copy
    import unittest
    from unittest import mock

    now = dt.datetime(2026, 10, 23, tzinfo=dt.timezone.utc)
    ids = ["0000000000000000000000000" + str(i) for i in range(1, 5)]
    expected = dict(zip(VARIABLES, [ids[1], ids[2], "e2e_read", "e2e_negative"]))
    body = {"api_key": {"id": ids[0], "organization_id": ids[1], "project_id": ids[2],
                        "database": "e2e_read", "scopes": ["documents:read"], "expires_at": "2026-10-23T01:00:00Z"},
            "key": ids[0] + "_" + "a" * 52}

    class HandoffTests(unittest.TestCase):
        def test_valid_native_response(self):
            self.assertEqual(validate(json.dumps(body), expected, now), body["api_key"])

        def test_refuses_broad_or_mismatched_credentials(self):
            for field, value in [("project_id", None), ("database", None), ("scopes", ["documents:read", "documents:write"]),
                                 ("scopes", ["documents:read", "documents:read"]), ("expires_at", None),
                                 ("expires_at", "2026-10-23T00:00:00Z"), ("expires_at", "2026-10-24T00:00:01Z"),
                                 ("organization_id", ids[3]), ("project_id", ids[3]), ("database", "other")]:
                changed = copy.deepcopy(body)
                changed["api_key"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate(json.dumps(changed), expected, now)
            for raw in ["not-json", '"' + body["key"] + '"', json.dumps(body)[:-1] + ',"key":"duplicate"}',
                        json.dumps(body).replace(body["key"], ids[3] + "_" + "a" * 52)]:
                with self.assertRaises(ValueError) as caught:
                    validate(raw, expected, now)
                self.assertNotIn(body["key"], str(caught.exception))
            for database in (None, "", "E2E_negative", "e2e/negative", "e2e_negative\n", "a" * 64, "e2e_read"):
                with self.subTest(database=database), self.assertRaises(ValueError):
                    validate(json.dumps(body), {**expected, VARIABLES[3]: database}, now)

        def test_credential_only_goes_to_stdin(self):
            with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
                gh(["secret", "set", "--repo", REPO, "--env", ENVIRONMENT, SECRET], data=json.dumps(body).encode())
                args, kwargs = run.call_args
                self.assertNotIn(body["key"], str(args))
                self.assertEqual(kwargs["input"], json.dumps(body).encode())
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
                self.assertEqual(kwargs["env"]["GH_HOST"], "github.com")
            with mock.patch.object(subprocess, "run", side_effect=subprocess.CalledProcessError(1, [body["key"]], stderr=body["key"])):
                with self.assertRaises(ValueError) as caught:
                    gh(["secret", "set"], data=json.dumps(body).encode())
                self.assertNotIn(body["key"], str(caught.exception))

        def test_wrong_destination_stops_before_secret_entry(self):
            module = sys.modules[__name__]
            for account, repo, environment in [("other", REPO, ENVIRONMENT), ("MarioGK", "TerraScale/other", ENVIRONMENT),
                                               ("MarioGK", REPO, "other")]:
                with mock.patch.object(module, "gh", side_effect=[{"login": account}, {"full_name": repo}, {"name": environment}]), \
                     mock.patch.object(module, "read_hidden_json") as prompt:
                    with self.assertRaises(ValueError):
                        install()
                    prompt.assert_not_called()

        def test_main_only_policy_required_before_secret_entry(self):
            module = sys.modules[__name__]
            main_only = {"protected_branches": False, "custom_branch_policies": True}
            for policy, branches in [(None, []), ({"protected_branches": True, "custom_branch_policies": False}, []),
                                     (main_only, []), (main_only, [{"name": "*", "type": "branch"}]),
                                     (main_only, [{"name": "main", "type": "tag"}]),
                                     (main_only, [{"name": "main", "type": "branch"}, {"name": "other", "type": "branch"}])]:
                replies = [{"login": "MarioGK"}, {"full_name": REPO}, {"name": ENVIRONMENT, "deployment_branch_policy": policy},
                           {"total_count": len(branches), "branch_policies": branches}]
                with mock.patch.object(module, "gh", side_effect=replies) as github, mock.patch.object(module, "read_hidden_json") as prompt:
                    with self.assertRaises(ValueError):
                        install()
                    prompt.assert_not_called()
                    self.assertTrue(all(call.args[0][0] == "api" for call in github.call_args_list))

        def test_approved_metadata_precedes_hidden_prompt_and_install(self):
            module = sys.modules[__name__]
            fresh = copy.deepcopy(body)
            fresh["api_key"]["expires_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
            replies = [{"login": "MarioGK"}, {"full_name": REPO},
                       {"name": ENVIRONMENT, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
                       {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]},
                       {"variables": [{"name": name, "value": value} for name, value in expected.items()]}, None]
            with mock.patch.object(module, "gh", side_effect=replies) as github, mock.patch.object(sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(module, "read_hidden_json", return_value=json.dumps(fresh, indent=2)) as prompt, \
                 mock.patch("builtins.input", return_value=ids[2] + "/e2e_negative"), mock.patch("builtins.print"):
                install()
                prompt.assert_called_once()
                self.assertTrue(all(call.args[0][0] == "api" for call in github.call_args_list[:5]))
                self.assertEqual(github.call_args_list[-1].args[0], ["secret", "set", "--repo", REPO, "--env", ENVIRONMENT, SECRET])
                self.assertEqual(parse_json(github.call_args_list[-1].kwargs["data"]), fresh)

        def test_exact_existing_negative_database_confirmation_required(self):
            module = sys.modules[__name__]
            replies = [{"login": "MarioGK"}, {"full_name": REPO},
                       {"name": ENVIRONMENT, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
                       {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]},
                       {"variables": [{"name": name, "value": value} for name, value in expected.items()]}]
            for confirmation in ("", ids[2], ids[3] + "/e2e_negative", ids[2] + "/e2e_read"):
                with mock.patch.object(module, "gh", side_effect=replies) as github, \
                     mock.patch.object(sys.stdin, "isatty", return_value=True), mock.patch("builtins.input", return_value=confirmation), \
                     mock.patch.object(module, "read_hidden_json") as prompt, mock.patch("builtins.print"):
                    with self.assertRaises(ValueError):
                        install()
                    prompt.assert_not_called()
                    self.assertTrue(all(call.args[0][0] == "api" for call in github.call_args_list))

        def test_invalid_negative_database_stops_before_secret_entry(self):
            module = sys.modules[__name__]
            for database in (None, "", "E2E_negative", "e2e/negative", "e2e_negative\n", "a" * 64, "e2e_read"):
                variables = {**expected, VARIABLES[3]: database}
                replies = [{"login": "MarioGK"}, {"full_name": REPO},
                           {"name": ENVIRONMENT, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
                           {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]},
                           {"variables": [{"name": name, "value": value} for name, value in variables.items()]}]
                with self.subTest(database=database), mock.patch.object(module, "gh", side_effect=replies) as github, \
                     mock.patch.object(module, "read_hidden_json") as prompt, mock.patch("builtins.input") as confirmation:
                    with self.assertRaises(ValueError):
                        install()
                    prompt.assert_not_called()
                    confirmation.assert_not_called()
                    self.assertTrue(all(call.args[0][0] == "api" for call in github.call_args_list))

        def test_hidden_json_requires_safe_terminal(self):
            with mock.patch.object(sys.stdin, "isatty", return_value=False), self.assertRaises(ValueError):
                read_hidden_json()

        def test_real_pty_paste_is_complete_hidden_and_restores_terminal(self):
            import hashlib
            import select
            import termios
            import time

            for mode in ("single-line", "multiline", "interrupt", "terminate"):
                with self.subTest(mode=mode):
                    master, slave = os.openpty()
                    original = termios.tcgetattr(slave)
                    digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
                    child = "import hashlib, json, runpy; m = runpy.run_path(" + repr(os.path.abspath(__file__)) + "); "
                    child += "raw = m['read_hidden_json'](); assert hashlib.sha256(json.dumps(json.loads(raw), sort_keys=True).encode()).hexdigest() == " + repr(digest) + "; print('ACCEPTED')"
                    process = subprocess.Popen([sys.executable, "-c", child], stdin=slave, stdout=slave, stderr=slave)
                    output = b""
                    try:
                        deadline = time.monotonic() + 5
                        while b"empty line finishes): " not in output:
                            remaining = deadline - time.monotonic()
                            self.assertGreater(remaining, 0, "hidden prompt timed out")
                            self.assertTrue(select.select([master], [], [], remaining)[0], "hidden prompt timed out")
                            output += os.read(master, 4096)
                        self.assertFalse(termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL))
                        if mode in ("interrupt", "terminate"):
                            process.send_signal(signal.SIGINT if mode == "interrupt" else signal.SIGTERM)
                        else:
                            paste = (json.dumps(body, indent=2) if mode == "multiline" else json.dumps(body)).encode() + b"\n"
                            self.assertEqual(os.write(master, paste), len(paste))
                        process.wait(timeout=5)
                        while select.select([master], [], [], 0)[0]:
                            output += os.read(master, 4096)
                        if mode in ("single-line", "multiline"):
                            self.assertEqual(process.returncode, 0, "complete JSON paste was not accepted")
                            self.assertIn(b"ACCEPTED", output)
                        else:
                            self.assertNotEqual(process.returncode, 0)
                        self.assertNotIn(body["key"].encode(), output)
                        self.assertNotIn(b'"api_key"', output)
                        self.assertEqual(termios.tcgetattr(slave), original)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=5)
                        os.close(master)
                        os.close(slave)

    return 0 if unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(HandoffTests)).wasSuccessful() else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if sys.argv[1:]:
        sys.exit("Run python3 scripts/e2e/install-production-credential.py without credential arguments.")
    try:
        install()
    except UnicodeError:
        print("Invalid credential text; no value displayed.", file=sys.stderr)
        sys.exit(1)
    except (ValueError, EOFError, KeyboardInterrupt) as error:
        print(str(error) if isinstance(error, ValueError) else "Hidden credential entry stopped; no value displayed.", file=sys.stderr)
        sys.exit(1)
