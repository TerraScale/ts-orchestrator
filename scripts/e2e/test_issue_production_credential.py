"""Synthetic only: no credentials, network, GitHub calls or production execution."""
import contextlib
import datetime as dt
import email.utils
import http.cookiejar
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import termios
import time
import unittest
from unittest import mock
import urllib.error

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("issuance", Path(__file__).with_name("issue-production-credential.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
I = m.installer
IDS = ["0000000000000000000000000" + str(i) for i in range(1, 5)]
EXPECTED = dict(zip(I.VARIABLES, [IDS[0], IDS[1], "e2e", IDS[2]]))
KEY_URL = m.AUTH + "/v1/terrascale/organizations/" + IDS[0] + "/projects/" + IDS[1] + "/api-keys"


def native():
    return {"api_key": {"id": IDS[3], "name": m.KEY_NAME, "organization_id": IDS[0], "project_id": IDS[1],
                        "database": "e2e", "scopes": ["documents:read"],
                        "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=23)).isoformat()},
            "key": IDS[3] + "_" + "a" * 52}


def github_replies():
    return [{"login": "MarioGK"}, {"full_name": I.REPO},
            {"name": I.ENVIRONMENT, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
            {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]},
            {"variables": [{"name": k, "value": v} for k, v in EXPECTED.items()]}]


class TrustTests(unittest.TestCase):
    def test_preflight_returns_exact_validated_four_variables(self):
        replies = github_replies()
        replies[-1]["variables"].append({"name": "UNRELATED", "value": "ignored"})
        with mock.patch.object(I, "gh", side_effect=replies):
            self.assertEqual(I.preflight(), EXPECTED)
        for key, value in [(I.VARIABLES[0], "bad"), (I.VARIABLES[1], IDS[2]),
                           (I.VARIABLES[2], "../other"), (I.VARIABLES[2], 123), (I.VARIABLES[3], IDS[1])]:
            replies = github_replies()
            replies[-1]["variables"] = [{"name": k, "value": value if k == key else v} for k, v in EXPECTED.items()]
            with self.subTest(key=key), mock.patch.object(I, "gh", side_effect=replies), self.assertRaises(ValueError):
                I.preflight()

    def test_fresh_exact_recipient_and_native_subject_only(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        def header(subject="123456 is your TerraScale sign-in code", to=m.ADDRESS, sent=now):
            return ("Subject: " + subject + "\r\nTo: " + to + "\r\nDate: " + email.utils.format_datetime(sent) + "\r\n").encode()
        self.assertEqual(m.fresh_code(header(), now, now), "123456")
        for subject, to, sent in [("123456 reset code", m.ADDRESS, now),
                                   ("[Test] 123456 is your TerraScale sign-in code", m.ADDRESS, now),
                                   ("123456 is your TerraScale sign-in code", "x" + m.ADDRESS, now),
                                   ("123456 is your TerraScale sign-in code", m.ADDRESS + ", other@example.com", now),
                                   ("123456 is your TerraScale sign-in code", m.ADDRESS, now - dt.timedelta(seconds=6)),
                                   ("123456 is your TerraScale sign-in code", m.ADDRESS, now + dt.timedelta(seconds=6))]:
            self.assertIsNone(m.fresh_code(header(subject, to, sent), now, now))
        self.assertIsNone(m.fresh_code(header() + b"Subject: duplicate\r\n", now, now))

    def test_readonly_mailbox_bounded_wait_without_new_issue(self):
        box = mock.Mock()
        box.login.return_value = ("OK", [])
        box.select.return_value = ("OK", [])
        box.search.return_value = ("OK", [b""])
        clock = [0]
        with mock.patch.object(m.imaplib, "IMAP4_SSL", return_value=box) as connect, \
             mock.patch.object(m.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(m.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaises(ValueError):
                m.mailbox_code("synthetic-password", dt.datetime.now(dt.timezone.utc))
        self.assertEqual(clock[0], 60)
        box.select.assert_called_once_with("INBOX", readonly=True)
        box.shutdown.assert_called_once()
        self.assertEqual(connect.call_args.args, ("mailserver.purelymail.com", 993))
        self.assertLessEqual(box.search.call_count, 12)

    def test_device_approval_one_poll_and_identity_binding(self):
        for wrong_email, refresh in [(False, False), (True, False), (False, True)]:
            session = m.Session()
            cookie = mock.Mock(name="cookie")
            cookie.name, cookie.secure = "tsauth_session", True
            session.jar = [cookie]
            tokens = {"token_type": "Bearer", "access_token": "synthetic-access"}
            if refresh:
                tokens["refresh_token"] = "synthetic-refresh"
            replies = [b"Code sent", b"Signed in", {"interval": 5, "expires_in": 600,
                       "verification_uri": m.AUTH + "/ui/terrascale/device", "user_code": "synthetic-user-code",
                       "device_code": "synthetic-device-code"}, b"Device connected", tokens,
                       {"email": "other@example.com" if wrong_email else m.ADDRESS, "email_verified": True}]
            with mock.patch.object(session, "call", side_effect=replies) as call, \
                 mock.patch.object(m, "mailbox_code", return_value="123456"), mock.patch.object(m.time, "sleep") as sleep:
                if wrong_email or refresh:
                    with self.assertRaises(ValueError):
                        session.login("synthetic-password")
                else:
                    session.login("synthetic-password")
                    self.assertEqual(session.token, "synthetic-access")
                sleep.assert_called_once_with(5)
                self.assertEqual(sum(c.args[0] == m.ISSUER + "/oauth/token" for c in call.call_args_list), 1)
                device = call.call_args_list[2]
                self.assertEqual(device.args[2], {"client_id": m.CLIENT, "scope": "openid email"})
                self.assertEqual(call.call_args_list[3].args[0], m.AUTH + "/ui/terrascale/device")
                self.assertEqual(call.call_args_list[4].args[2]["grant_type"], "urn:ietf:params:oauth:grant-type:device_code")
            session.token = None

    def test_both_exact_databases_verified_before_empty_key_list(self):
        def replies():
            return [{"id": IDS[0], "role": "owner"},
                    {"id": IDS[1], "organization_id": IDS[0]}, {"token_type": "Bearer", "access_token": "target-token"},
                    {"projectId": IDS[1], "name": "e2e"},
                    {"id": IDS[2], "organization_id": IDS[0]}, {"token_type": "Bearer", "access_token": "negative-token"},
                    {"projectId": IDS[2], "name": "e2e"}, {"items": [], "next": None}]
        session = m.Session()
        session.token = "synthetic-signin"
        try:
            with mock.patch.object(session, "call", side_effect=replies()) as call:
                self.assertEqual(session.verify_targets(EXPECTED), KEY_URL)
                exchanges = [c for c in call.call_args_list if c.args[0] == m.ISSUER + "/oauth/token"]
                self.assertEqual(len(exchanges), 2)
                self.assertEqual([c.args[2]["project"] for c in exchanges], [IDS[1], IDS[2]])
                self.assertTrue(all(c.args[2]["scope"] == "databases:read" and c.args[2]["client_id"] == m.CLIENT for c in exchanges))
                self.assertTrue(all(c.args[1] == "POST" for c in exchanges))
                self.assertEqual(call.call_args_list[3].args[0], m.API + "/v1/projects/" + IDS[1] + "/databases/e2e")
                self.assertEqual(call.call_args_list[6].args[0], m.API + "/v1/projects/" + IDS[2] + "/databases/e2e")
            for index, bad in [(0, {"id": IDS[0], "role": "member"}),
                               (4, {"id": IDS[2], "organization_id": IDS[3]}),
                               (6, {"error": "unknown_database"}), (6, {"projectId": IDS[2], "name": "other"}),
                               (7, {"items": [{}], "next": None}), (7, {"items": [], "next": "more"}), (7, {})]:
                data = replies()
                data[index] = bad
                with self.subTest(index=index, bad=bad), mock.patch.object(session, "call", side_effect=data), self.assertRaises(ValueError):
                    session.verify_targets(EXPECTED)
        finally:
            session.close()

    def test_one_exact_issuance_even_after_ambiguous_http_failure(self):
        session = m.Session()
        try:
            start = dt.datetime.now(dt.timezone.utc)
            with mock.patch.object(session, "call", side_effect=RuntimeError("synthetic-private-response")) as call:
                with self.assertRaises(RuntimeError):
                    session.issue(KEY_URL, EXPECTED)
                with self.assertRaises(ValueError):
                    session.issue(KEY_URL, EXPECTED)
                call.assert_called_once()
                args, kwargs = call.call_args
                self.assertEqual(args[:2], (KEY_URL, "POST"))
                request = args[2]
                self.assertEqual(set(request), {"name", "database", "scopes", "expires_at"})
                self.assertEqual(request["scopes"], ["documents:read"])
                self.assertEqual(request["name"], "deployment-e2e-read")
                self.assertEqual(request["database"], "e2e")
                expiry = dt.datetime.fromisoformat(request["expires_at"].replace("Z", "+00:00"))
                self.assertTrue(start + dt.timedelta(hours=22, minutes=59) < expiry < start + dt.timedelta(hours=24))
                self.assertEqual(kwargs["status"], 201)
        finally:
            session.close()

    def test_pinned_tls_no_redirects_or_api_cookies(self):
        session = m.Session()
        try:
            for url in ["http://auth.terrascale.tech/", "https://auth.terrascale.tech.evil/", "https://user@auth.terrascale.tech/", "https://auth.terrascale.tech:443/", m.AUTH + "/#fragment"]:
                with mock.patch.object(session.http, "open") as http, self.assertRaises(ValueError):
                    session.call(url)
                http.assert_not_called()
            self.assertIsNone(m.NoRedirect().redirect_request(None, None, None, None, None, None))
            handler = next(h for h in session.http.handlers if isinstance(h, m.urllib.request.HTTPSHandler))
            self.assertEqual(handler._context.verify_mode, m.ssl.CERT_REQUIRED)
            self.assertTrue(handler._context.check_hostname)
            with mock.patch.object(m.http.cookiejar.CookieJar, "add_cookie_header") as cookies:
                processor = m.AuthCookies(session.jar)
                processor.https_request(m.urllib.request.Request(m.API + "/v1/projects/" + IDS[1]))
                cookies.assert_not_called()
                processor.https_request(m.urllib.request.Request(m.AUTH + "/ui/terrascale/device"))
                cookies.assert_called_once()
        finally:
            session.close()
        self.assertIsNone(session.token)
        self.assertEqual(list(session.jar), [])


class RunTests(unittest.TestCase):
    def test_failures_never_leak_or_retry_and_always_clear(self):
        for failure in ("preflight", "confirm", "login", "targets", "changed", "issue", "validation", "install", "success"):
            body = native()
            secret = body["key"]
            if failure == "validation":
                body["api_key"]["scopes"] = ["documents:write"]
            session = mock.Mock()
            session.verify_targets.return_value = KEY_URL
            session.issue.return_value = body
            for stage, member in [("login", "login"), ("targets", "verify_targets"), ("issue", "issue")]:
                if failure == stage:
                    getattr(session, member).side_effect = RuntimeError(secret)
            output = io.StringIO()
            preflight = [EXPECTED, {**EXPECTED, "E2E_DATABASE": "changed"} if failure == "changed" else EXPECTED]
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(m.resource, "setrlimit"))
                check = stack.enter_context(mock.patch.object(I, "preflight", side_effect=RuntimeError(secret) if failure == "preflight" else preflight))
                confirmation = stack.enter_context(mock.patch.object(m, "confirm", side_effect=RuntimeError(secret) if failure == "confirm" else None))
                factory = stack.enter_context(mock.patch.object(m, "Session", return_value=session))
                stdin = stack.enter_context(mock.patch.object(m.sys, "stdin", io.StringIO("synthetic-password\n")))
                gh = stack.enter_context(mock.patch.object(I, "gh", side_effect=RuntimeError(secret) if failure == "install" else None))
                stack.enter_context(contextlib.redirect_stdout(output))
                stack.enter_context(contextlib.redirect_stderr(output))
                self.assertEqual(m.run(), 0 if failure == "success" else 1)
                self.assertNotIn(secret, output.getvalue())
                self.assertNotIn("synthetic-password", output.getvalue())
                self.assertNotIn('"api_key"', output.getvalue())
                self.assertLessEqual(session.issue.call_count, 1)
                self.assertLessEqual(gh.call_count, 1)
                if factory.called:
                    session.close.assert_called_once()
                if failure in ("preflight", "confirm"):
                    factory.assert_not_called()
                    self.assertEqual(stdin.tell(), 0)
                if failure in ("targets", "changed"):
                    session.issue.assert_not_called()
                if failure in ("install", "success"):
                    self.assertIn("Key id: " + IDS[3], output.getvalue())
                    self.assertEqual(gh.call_args.args[0], ["secret", "set", "--repo", I.REPO, "--env", I.ENVIRONMENT, I.SECRET])
                    self.assertNotIn(secret, str(gh.call_args.args))
                    self.assertEqual(json.loads(gh.call_args.kwargs["data"])["key"], secret)
                if failure in ("validation", "install", "success"):
                    self.assertEqual(body, {})

    def test_real_hidden_controlling_terminal_and_refusal(self):
        phrase = "issue " + IDS[1] + "/e2e negative " + IDS[2] + "/e2e"
        child = ("import importlib.util,sys; s=importlib.util.spec_from_file_location('h'," +
                 repr(str(Path(m.__file__).resolve())) + "); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); " +
                 "m.signal.signal(m.signal.SIGTERM,m.interrupted); m.confirm(" + repr(EXPECTED) + "); print('CONFIRMED')")
        # A detached process with no controlling terminal must refuse.
        result = subprocess.run([sys.executable, "-c", child], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"CONFIRMED", result.stdout)
        import fcntl
        for mode in ("accept", "reject", "interrupt", "terminate"):
            master, slave = os.openpty()
            original = termios.tcgetattr(slave)
            def controlling_terminal():
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            process = subprocess.Popen([sys.executable, "-c", child], stdin=subprocess.DEVNULL, stdout=slave, stderr=slave,
                                       preexec_fn=controlling_terminal)
            output = b""
            try:
                deadline = time.monotonic() + 5
                while not output.endswith(b"> "):
                    remaining = deadline - time.monotonic()
                    self.assertGreater(remaining, 0)
                    self.assertTrue(select.select([master], [], [], remaining)[0], repr(output))
                    output += os.read(master, 4096)
                self.assertFalse(termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL))
                before = len(output)
                if mode in ("interrupt", "terminate"):
                    process.send_signal(signal.SIGINT if mode == "interrupt" else signal.SIGTERM)
                else:
                    os.write(master, (phrase if mode == "accept" else "wrong").encode() + b"\n")
                process.wait(timeout=5)
                while select.select([master], [], [], 0)[0]:
                    output += os.read(master, 4096)
                self.assertEqual(process.returncode == 0, mode == "accept")
                self.assertNotIn(phrase.encode(), output[before:])
                self.assertNotIn(b"wrong", output[before:])
                self.assertEqual(termios.tcgetattr(slave), original)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                os.close(master)
                os.close(slave)


if __name__ == "__main__":
    unittest.main()
