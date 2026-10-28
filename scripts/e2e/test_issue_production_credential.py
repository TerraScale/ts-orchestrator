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
import tempfile
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
IDS = ["0000000000000000000000000" + str(i) for i in range(1, 7)]
DB, NEGATIVE_DB = IDS[4], IDS[5]
EXPECTED = dict(zip(I.VARIABLES, [IDS[0], IDS[1], "e2e_read", "e2e_negative"]))
KEY_URL = m.AUTH + "/v1/terrascale/organizations/" + IDS[0] + "/projects/" + IDS[1] + "/api-keys"


def native():
    return {"api_key": {"id": IDS[3], "name": m.KEY_NAME, "organization_id": IDS[0], "project_id": IDS[1],
                        "database": DB, "scopes": ["documents:read"],
                        "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=23)).isoformat()},
            "key": IDS[3] + "_" + "a" * 52}


def github_replies():
    return [{"login": "MarioGK"}, {"full_name": I.REPO},
            {"name": I.ENVIRONMENT, "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
            {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]},
            {"variables": [{"name": k, "value": v} for k, v in EXPECTED.items()]}]


def cookie(jar):
    jar.set_cookie(http.cookiejar.Cookie(0, "tsauth_session", "synthetic-session", None, False,
        "auth.terrascale.tech", False, False, "/", True, True, None, True, None, None, {}))


class SyntheticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        patch = mock.patch.object(m, "SESSION_DIR", Path(temporary.name) / "ts-session")
        patch.start()
        self.addCleanup(patch.stop)
        for target, member in ((m.urllib.request.OpenerDirector, "open"), (m.imaplib, "IMAP4_SSL"), (I, "gh")):
            patch = mock.patch.object(target, member, side_effect=AssertionError("Live calls forbidden in synthetic tests"))
            patch.start()
            self.addCleanup(patch.stop)

    def session(self, cached=False):
        session = m.Session()
        self.addCleanup(session.close)
        if cached:
            cache = session.session_cache()
            cookie(session.jar)
            with cache.lock():
                cache.save("mariogk.cookies", lambda fd: session.jar.save("/proc/self/fd/" + str(fd), ignore_discard=True))
        return session


class TrustTests(SyntheticTests):
    def test_preflight_returns_exact_validated_four_variables(self):
        replies = github_replies()
        replies[-1]["variables"].append({"name": "UNRELATED", "value": "ignored"})
        with mock.patch.object(I, "gh", side_effect=replies):
            self.assertEqual(I.preflight(), EXPECTED)
        for key, value in [(I.VARIABLES[0], "bad"), (I.VARIABLES[1], "bad"),
                           (I.VARIABLES[2], "../other"), (I.VARIABLES[2], 123), (I.VARIABLES[3], "e2e_read")]:
            replies = github_replies()
            replies[-1]["variables"] = [{"name": k, "value": value if k == key else v} for k, v in EXPECTED.items()]
            with self.subTest(key=key), mock.patch.object(I, "gh", side_effect=replies), self.assertRaises(ValueError):
                I.preflight()

    def test_fresh_exact_recipient_and_native_subject_only(self):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        def header(subject="123456 is your TerraScale sign-in code", to=m.ADDRESS, sent=now):
            return ("Subject: " + subject + "\r\nTo: " + to + "\r\nDate: " + email.utils.format_datetime(sent) + "\r\n").encode()
        self.assertEqual(m.fresh_code(header(), now, now), "123456")
        for offset in (-120, -119, 5):
            with self.subTest(offset=offset):
                self.assertEqual(m.fresh_code(header(sent=now + dt.timedelta(seconds=offset)), now, now), "123456")
        for subject, to, sent in [("123456 reset code", m.ADDRESS, now),
                                   ("[Test] 123456 is your TerraScale sign-in code", m.ADDRESS, now),
                                   ("123456 is your TerraScale sign-in code", "x" + m.ADDRESS, now),
                                   ("123456 is your TerraScale sign-in code", m.ADDRESS + ", other@example.com", now),
                                   ("123456 is your TerraScale sign-in code", m.ADDRESS, now - dt.timedelta(seconds=121)),
                                   ("123456 is your TerraScale sign-in code", m.ADDRESS, now + dt.timedelta(seconds=6))]:
            self.assertIsNone(m.fresh_code(header(subject, to, sent), now, now))
        self.assertIsNone(m.fresh_code(header() + b"Subject: duplicate\r\n", now, now))

    def test_readonly_mailbox_bounded_wait_without_new_issue(self):
        box = mock.Mock()
        box.login.return_value = ("OK", [])
        box.select.return_value = ("OK", [])
        box.search.return_value = ("OK", [b""])
        clock = [0]
        polls = []
        box.search.side_effect = lambda *args: (polls.append(clock[0]) or ("OK", [b""]))
        with mock.patch.object(m.imaplib, "IMAP4_SSL", return_value=box) as connect, \
             mock.patch.object(m.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(m.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaises(ValueError):
                m.mailbox_code("synthetic-password", dt.datetime.now(dt.timezone.utc))
        self.assertEqual(clock[0], 180)
        box.select.assert_called_once_with("INBOX", readonly=True)
        box.shutdown.assert_called_once()
        self.assertEqual(connect.call_args.args, ("mailserver.purelymail.com", 993))
        self.assertEqual(box.search.call_count, 18)
        self.assertEqual(polls, list(range(0, 180, 10)))

    def test_delayed_skewed_mail_and_ambiguous_codes(self):
        started = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        def header(code):
            return ("Subject: " + code + " is your TerraScale sign-in code\r\nTo: " + m.ADDRESS +
                    "\r\nDate: " + email.utils.format_datetime(started - dt.timedelta(minutes=2)) + "\r\n").encode()
        for codes in (("123456",), ("123456", "654321")):
            with self.subTest(codes=codes):
                clock = [0]
                box = mock.Mock()
                box.login.return_value = box.select.return_value = ("OK", [])
                box.search.side_effect = lambda *args: ("OK", [b"1" if clock[0] >= 170 else b""])
                box.fetch.return_value = ("OK", [(b"header", header(code)) for code in codes])
                with mock.patch.object(m.imaplib, "IMAP4_SSL", return_value=box), \
                     mock.patch.object(m.time, "monotonic", side_effect=lambda: clock[0]), \
                     mock.patch.object(m.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
                    if len(codes) > 1:
                        with self.assertRaisesRegex(ValueError, "Ambiguous"):
                            m.mailbox_code("synthetic-password", started)
                    else:
                        self.assertEqual(m.mailbox_code("synthetic-password", started), "123456")
                self.assertEqual(clock[0], 170)
                box.shutdown.assert_called_once()

    def test_mailbox_timeout_does_not_resend_or_redeem(self):
        session = self.session()
        jar = session.jar
        def request(*args, **kwargs):
            self.assertTrue(session.cache.locked)
        with mock.patch.object(session, "call", side_effect=request) as call, \
             mock.patch.object(m, "mailbox_code", side_effect=ValueError("synthetic timeout")):
            with self.assertRaises(ValueError):
                session.login("synthetic-password")
            call.assert_called_once_with(m.AUTH + "/ui/terrascale/sign-in", "POST", {"email": m.ADDRESS}, form=True)
            self.assertIs(session.jar, jar)
        with mock.patch.object(session, "call") as call, self.assertRaisesRegex(ValueError, "five-minute"):
            session.login("synthetic-password")
        call.assert_not_called()

    def test_device_approval_one_poll_and_identity_binding(self):
        for wrong_email, refresh, verified in [(False, False, True), (True, False, True),
                                                (False, True, True), (False, False, False)]:
            session = self.session(cached=True)
            tokens = {"token_type": "Bearer", "access_token": "synthetic-access"}
            if refresh:
                tokens["refresh_token"] = "synthetic-refresh"
            replies = [b"signed-in form", {"interval": 5, "expires_in": 600,
                       "verification_uri": m.AUTH + "/ui/terrascale/device", "user_code": "synthetic-user-code",
                       "device_code": "synthetic-device-code"}, b"Device connected", tokens,
                       {"email": "other@example.com" if wrong_email else m.ADDRESS, "email_verified": verified}]
            with mock.patch.object(session, "call", side_effect=replies) as call, \
                 mock.patch.object(m, "mailbox_code", return_value="123456"), mock.patch.object(m.time, "sleep") as sleep:
                if wrong_email or refresh or not verified:
                    with self.assertRaises(ValueError):
                        session.login("synthetic-password")
                else:
                    session.login("synthetic-password")
                    self.assertEqual(session.token, "synthetic-access")
                sleep.assert_called_once_with(5)
                self.assertEqual(sum(c.args[0] == m.ISSUER + "/oauth/token" for c in call.call_args_list), 1)
                self.assertFalse(any(c.args[0].startswith(m.AUTH + "/ui/terrascale/sign-in") for c in call.call_args_list))
                device = call.call_args_list[1]
                self.assertEqual(device.args[2], {"client_id": m.CLIENT, "scope": "openid email"})
                self.assertEqual(call.call_args_list[2].args[0], m.AUTH + "/ui/terrascale/device")
                self.assertEqual(call.call_args_list[3].args[2]["grant_type"], "urn:ietf:params:oauth:grant-type:device_code")
            session.token = None

    def test_both_exact_databases_verified_before_empty_key_list(self):
        def replies():
            return [{"id": IDS[0], "role": "owner"},
                    {"id": IDS[1], "organization_id": IDS[0]}, {"token_type": "Bearer", "access_token": "target-token"},
                    {"id": DB, "projectId": IDS[1], "name": "e2e_read"},
                    {"id": NEGATIVE_DB, "projectId": IDS[1], "name": "e2e_negative"}, {"items": [], "next": None}]
        session = m.Session()
        session.token = "synthetic-signin"
        try:
            with mock.patch.object(session, "call", side_effect=replies()) as call:
                self.assertEqual(session.verify_targets(EXPECTED), (KEY_URL, DB))
                exchanges = [c for c in call.call_args_list if c.args[0] == m.ISSUER + "/oauth/token"]
                self.assertEqual(len(exchanges), 1)
                self.assertEqual([c.args[2]["project"] for c in exchanges], [IDS[1]])
                self.assertTrue(all(c.args[2]["scope"] == "databases:read" and c.args[2]["client_id"] == m.CLIENT for c in exchanges))
                self.assertTrue(all(c.args[1] == "POST" for c in exchanges))
                self.assertEqual(call.call_args_list[3].args[0], m.API + "/v1/projects/" + IDS[1] + "/databases/e2e_read")
                self.assertEqual(call.call_args_list[4].args[0], m.API + "/v1/projects/" + IDS[1] + "/databases/e2e_negative")
                self.assertEqual(sum("/projects/" in c.args[0] and "/databases/" not in c.args[0] and not c.args[0].endswith("/api-keys")
                                     for c in call.call_args_list), 1)
            for index, bad in [(0, {"id": IDS[0], "role": "member"}),
                               (1, {"id": IDS[1], "organization_id": IDS[3]}),
                               (4, {"error": "unknown_database"}), (4, {"id": NEGATIVE_DB, "projectId": IDS[1], "name": "other"}),
                               (3, {"projectId": IDS[1], "name": "e2e_read"}), (3, {"id": "e2e_read", "projectId": IDS[1], "name": "e2e_read"}),
                               (4, {"id": DB, "projectId": IDS[1], "name": "e2e_negative"}),
                               (5, {"items": [{}], "next": None}), (5, {"items": [], "next": "more"}), (5, {})]:
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
                    session.issue(KEY_URL, DB)
                with self.assertRaises(ValueError):
                    session.issue(KEY_URL, DB)
                call.assert_called_once()
                args, kwargs = call.call_args
                self.assertEqual(args[:2], (KEY_URL, "POST"))
                request = args[2]
                self.assertEqual(set(request), {"name", "database", "scopes", "expires_at"})
                self.assertEqual(request["scopes"], ["documents:read"])
                self.assertEqual(request["name"], "deployment-e2e-read")
                self.assertEqual(request["database"], DB)
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


class CacheTests(SyntheticTests):
    def assert_locked(self, session):
        with open(m.SESSION_DIR / "signin.lock") as lock:
            with self.assertRaises(BlockingIOError):
                m.fcntl.flock(lock, m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)
        self.assertTrue(session.cache.locked)

    def test_cached_session_avoids_email_and_rechecks_identity(self):
        session = self.session(cached=True)
        with mock.patch.object(session, "call", return_value=b"signed-in form") as call, \
             mock.patch.object(session, "email_login") as login, \
             mock.patch.object(session, "identify") as identify, mock.patch.object(m, "mailbox_code") as mailbox:
            session.login("synthetic-password")
        call.assert_called_once_with(m.AUTH + "/ui/terrascale/device")
        login.assert_not_called()
        mailbox.assert_not_called()
        identify.assert_called_once_with()
        self.assertFalse((m.SESSION_DIR / "last-signin-at").exists())

    def test_cache_appearing_while_waiting_for_lock_is_reused(self):
        session = self.session()
        cache = session.session_cache()
        lock = cache.lock
        @contextlib.contextmanager
        def arriving_session():
            with lock():
                cookie(session.jar)
                cache.save("mariogk.cookies", lambda fd: session.jar.save("/proc/self/fd/" + str(fd), ignore_discard=True))
                yield
        def probe(*args):
            self.assert_locked(session)
            return b"signed-in form"
        with mock.patch.object(cache, "lock", arriving_session), \
             mock.patch.object(session, "call", side_effect=probe) as call, \
             mock.patch.object(session, "email_login") as login, mock.patch.object(session, "identify"):
            session.login("synthetic-password")
        call.assert_called_once_with(m.AUTH + "/ui/terrascale/device")
        login.assert_not_called()

    def test_one_email_request_and_redemption_share_locked_jar_and_private_save(self):
        session = self.session()
        session.token = "synthetic-bearer"
        jar = session.jar
        def request(url, method, data, **kwargs):
            self.assert_locked(session)
            self.assertIs(session.jar, jar)
            self.assertGreater(session.cache.number("last-signin-at"), 0)
            self.assertEqual(method, "POST")
            if url.endswith("/sign-in"):
                cookie(jar)
                return b"Code sent"
            self.assertEqual(url, m.AUTH + "/ui/terrascale/sign-in/verify")
            self.assertEqual(data, {"email": m.ADDRESS, "code": "123456"})
            self.assertTrue(list(jar))
            return b"Signed in"
        def code(*args):
            self.assert_locked(session)
            return "123456"
        with mock.patch.object(session, "call", side_effect=request) as call, \
             mock.patch.object(m, "mailbox_code", side_effect=code) as mailbox, \
             mock.patch.object(session, "identify"):
            session.login("synthetic-password")
        self.assertEqual(call.call_count, 2)
        mailbox.assert_called_once()
        self.assertEqual(m.SESSION_DIR.stat().st_mode & 0o777, 0o700)
        for name in ("mariogk.cookies", "signin.lock", "last-signin-at"):
            self.assertEqual((m.SESSION_DIR / name).stat().st_mode & 0o777, 0o600)
        self.assertFalse(list(m.SESSION_DIR.glob(".tmp-*")))
        saved = (m.SESSION_DIR / "mariogk.cookies").read_text()
        self.assertIn("# Netscape HTTP Cookie File", saved)
        self.assertNotIn("synthetic-password", saved)
        self.assertNotIn("synthetic-bearer", saved)
        session.cache.load(jar)
        self.assertEqual([(c.name, c.value) for c in jar], [("tsauth_session", "synthetic-session")])

    def test_only_absent_401_and_exact_signin_redirect_allow_email(self):
        redirect = "/ui/terrascale/sign-in?next=%2Fui%2Fterrascale%2Fdevice"
        for status, location, allowed in [(401, None, True), (302, "/ui/terrascale/sign-in", True),
                (302, redirect, True), (302, m.AUTH + redirect, True),
                (302, "https://evil.example" + redirect, False),
                (302, "http://auth.terrascale.tech" + redirect, False),
                (302, "//auth.terrascale.tech" + redirect, False),
                (302, redirect + "&next=%2Fui%2Fterrascale%2Fdevice", False),
                (302, redirect + "&other=1", False), (302, redirect + "#fragment", False),
                (302, redirect.replace("%2Fdevice", "%2Fother"), False),
                (302, redirect.replace("sign-in?", "other?"), False),
                (302, m.AUTH + "/ui/terrascale/sign-in", True), (302, "/ui/terrascale/sign-in?other", False),
                (302, "https://evil.example/ui/terrascale/sign-in", False), (303, "/ui/terrascale/sign-in", False),
                (403, None, False), (500, None, False)]:
            with self.subTest(status=status, location=location):
                session = self.session(cached=True)
                (m.SESSION_DIR / "last-signin-at").unlink(missing_ok=True)
                error = urllib.error.HTTPError(m.AUTH + "/ui/terrascale/device", status, "synthetic", {"Location": location}, io.BytesIO())
                self.addCleanup(error.close)
                probes = []
                def probe(*args):
                    probes.append(session.cache.locked)
                    raise error
                def email_login(password):
                    self.assert_locked(session)
                    self.assertEqual(probes, [False, True])
                with mock.patch.object(session, "call", side_effect=probe), \
                     mock.patch.object(session, "email_login", side_effect=email_login) as login, \
                     mock.patch.object(session, "identify") as identify, mock.patch.object(m, "mailbox_code") as mailbox:
                    if allowed:
                        session.login("synthetic-password")
                        self.assertTrue(session.cache.load(session.jar))
                        self.assertEqual(login.call_count, 1)
                        self.assertTrue(identify.called)
                    else:
                        with self.assertRaises(urllib.error.HTTPError):
                            session.login("synthetic-password")
                        login.assert_not_called()
                        identify.assert_not_called()
                        self.assertEqual(probes, [False])
                    mailbox.assert_not_called()
        for error in (urllib.error.URLError("synthetic outage"), ValueError("synthetic response")):
            session = self.session(cached=True)
            with mock.patch.object(session, "call", side_effect=error), mock.patch.object(session, "email_login") as login:
                with self.assertRaises(type(error)):
                    session.login("synthetic-password")
                login.assert_not_called()

    def test_rate_limits_shared_across_sessions_and_expire_at_exact_boundary(self):
        first, second = self.session(), self.session()
        cache = first.session_cache()
        with cache.lock():
            cache.timestamp("last-signin-at", 1000)
        with mock.patch.object(m.time, "time", return_value=1299.99), \
             mock.patch.object(second, "email_login") as login, self.assertRaisesRegex(ValueError, "five-minute"):
            second.login("synthetic-password")
        login.assert_not_called()
        def fail(*args):
            self.assert_locked(second)
            raise ValueError("synthetic timeout")
        with mock.patch.object(m.time, "time", return_value=1300), mock.patch.object(second, "email_login", side_effect=fail) as login:
            with self.assertRaisesRegex(ValueError, "synthetic timeout"):
                second.login("synthetic-password")
        login.assert_called_once()
        self.assertEqual(cache.number("last-signin-at"), 1300)

    def test_any_http429_records_shared_cooldown_without_sleep_or_retry(self):
        first, second = self.session(cached=True), self.session()
        error = urllib.error.HTTPError(m.AUTH + "/ui/terrascale/device", 429, "synthetic private body", {}, io.BytesIO())
        self.addCleanup(error.close)
        for locked in (False, True):
            with self.subTest(locked=locked), mock.patch.object(m.time, "time", return_value=2000), \
                 mock.patch.object(first.http, "open", side_effect=error) as http, \
                 mock.patch.object(m.time, "sleep") as sleep:
                with first.cache.lock() if locked else contextlib.nullcontext():
                    with self.assertRaises(urllib.error.HTTPError):
                        first.call(m.AUTH + "/ui/terrascale/device")
                http.assert_called_once()
                sleep.assert_not_called()
                self.assertEqual(first.cache.number("cooldown-until"), 2900)
        with mock.patch.object(m.time, "time", return_value=2899.99), \
             mock.patch.object(second, "call") as call, mock.patch.object(m.time, "sleep") as sleep:
            with self.assertRaisesRegex(ValueError, "cooldown"):
                second.login("synthetic-password")
            call.assert_not_called()
            sleep.assert_not_called()
        with mock.patch.object(m.time, "time", return_value=2900), \
             mock.patch.object(second, "call", return_value=b"signed-in form"), mock.patch.object(second, "identify") as identify:
            second.login("synthetic-password")
        identify.assert_called_once()

    def test_concurrent_processes_send_only_once_even_after_failed_login(self):
        child = """
import importlib.util, sys
from pathlib import Path
from unittest import mock
spec = importlib.util.spec_from_file_location('issuance', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.SESSION_DIR = Path(sys.argv[2])
session = m.Session()
def send(password):
    assert session.cache.locked
    print('SENT', flush=True)
    raise ValueError('synthetic mailbox timeout')
try:
    with mock.patch.object(session, 'email_login', side_effect=send), \\
         mock.patch.object(session.http, 'open', side_effect=AssertionError('Network forbidden')):
        try:
            session.login('synthetic-password')
        except ValueError:
            pass
finally:
    session.close()
"""
        processes = [subprocess.Popen([sys.executable, "-B", "-c", child, m.__file__, str(m.SESSION_DIR)],
                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        try:
            results = [process.communicate(timeout=10) for process in processes]
            self.assertTrue(all(process.returncode == 0 for process in processes), repr(results))
            self.assertEqual(b"".join(result[0] for result in results), b"SENT\n")
            self.assertTrue(all(result[1] == b"" for result in results), repr(results))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)

    def test_no_signin_post_outside_lock(self):
        session = self.session()
        for path in ("/ui/terrascale/sign-in", "/ui/terrascale/sign-in/verify"):
            with mock.patch.object(session.http, "open") as http, self.assertRaisesRegex(ValueError, "lock"):
                session.call(m.AUTH + path, "POST", {}, form=True)
            http.assert_not_called()
        with self.assertRaisesRegex(ValueError, "lock"):
            session.email_login("synthetic-password")

    def test_atomic_save_keeps_old_cache_on_failure_and_rejects_unsafe_files(self):
        session = self.session(cached=True)
        cache = session.cache
        original = (m.SESSION_DIR / "mariogk.cookies").read_bytes()
        def fail(fd):
            os.write(fd, b"incomplete synthetic content")
            self.assertEqual((m.SESSION_DIR / "mariogk.cookies").read_bytes(), original)
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
            raise ValueError("synthetic write failure")
        with cache.lock(), self.assertRaises(ValueError):
            cache.save("mariogk.cookies", fail)
        self.assertEqual((m.SESSION_DIR / "mariogk.cookies").read_bytes(), original)
        self.assertFalse(list(m.SESSION_DIR.glob(".tmp-*")))
        target = m.SESSION_DIR / "untouched"
        target.write_bytes(b"synthetic original")
        for name in ("mariogk.cookies", "last-signin-at", "cooldown-until", "signin.lock"):
            path = m.SESSION_DIR / name
            path.unlink(missing_ok=True)
            path.symlink_to(target)
            with self.subTest(name=name), self.assertRaises(OSError):
                if name == "signin.lock":
                    with cache.lock():
                        self.fail("Symlink lock accepted")
                elif name == "mariogk.cookies":
                    cache.load(session.jar)
                else:
                    cache.number(name)
            if name != "signin.lock":
                with cache.lock(), self.assertRaises(OSError):
                    cache.save(name, lambda fd: os.write(fd, b"must not overwrite"))
            self.assertTrue(path.is_symlink())
            self.assertEqual(target.read_bytes(), b"synthetic original")
            path.unlink()

    def test_unsafe_permissions_malformed_cache_and_state_fail_closed(self):
        session = self.session(cached=True)
        path = m.SESSION_DIR / "mariogk.cookies"
        for mode, content in ((0o644, "synthetic"), (0o600, "not a cookie jar")):
            path.chmod(0o600)
            path.write_text(content)
            path.chmod(mode)
            output = io.StringIO()
            with mock.patch.object(session, "call") as call, mock.patch.object(session, "email_login") as login, \
                 contextlib.redirect_stderr(output), self.assertRaises(Exception):
                session.login("synthetic-password")
            self.assertEqual(output.getvalue(), "")
            call.assert_not_called()
            login.assert_not_called()
        for content in ("nan", "inf", "-1", "unknown", "1" * 129):
            with session.cache.lock():
                session.cache.save("cooldown-until", lambda fd: os.write(fd, content.encode()))
            with self.subTest(content=content), self.assertRaises(ValueError):
                session.cache.check_cooldown()
        session.close()
        m.SESSION_DIR.chmod(0o755)
        with self.assertRaises(ValueError):
            m.SessionCache()
        m.SESSION_DIR.chmod(0o700)
        target = m.SESSION_DIR.with_name("real-session")
        m.SESSION_DIR.rename(target)
        m.SESSION_DIR.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError):
            m.SessionCache()


class RunTests(SyntheticTests):
    def test_failures_never_leak_or_retry_and_always_clear(self):
        for failure in ("preflight", "confirm", "login", "targets", "changed", "issue", "validation", "install", "success"):
            body = native()
            expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=23)).replace(microsecond=0)
            body["api_key"]["expires_at"] = expiry.isoformat()
            secret = body["key"]
            if failure == "validation":
                body["api_key"]["scopes"] = ["documents:write"]
            session = mock.Mock()
            session.verify_targets.return_value = (KEY_URL, DB)
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
                    self.assertIn("; expires: " + expiry.strftime("%Y-%m-%dT%H:%M:%SZ") + "; target: ", output.getvalue())
                    self.assertEqual(gh.call_args.args[0], ["secret", "set", "--repo", I.REPO, "--env", I.ENVIRONMENT, I.SECRET])
                    self.assertNotIn(secret, str(gh.call_args.args))
                    self.assertEqual(json.loads(gh.call_args.kwargs["data"])["key"], secret)
                if failure in ("validation", "install", "success"):
                    self.assertEqual(body, {})

    def test_real_hidden_controlling_terminal_and_refusal(self):
        phrase = "issue " + IDS[1] + "/e2e_read negative " + IDS[1] + "/e2e_negative"
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
