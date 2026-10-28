#!/usr/bin/env python3
"""USER RUN ONLY. One issuance and GitHub installation; password via redirected stdin."""

import contextlib
import datetime as dt
import email
import email.header
import email.utils
import fcntl
import http.cookiejar
import imaplib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import signal
import ssl
import stat
import sys
import termios
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

# Load the existing installer without executing its interactive entry point.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("credential_installer", Path(__file__).with_name("install-production-credential.py"))
installer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = installer
spec.loader.exec_module(installer)

AUTH = "https://auth.terrascale.tech"
ISSUER = AUTH + "/terrascale"
API = "https://api.terrascale.tech"
ADDRESS = "mariogk@terrascale.tech"
CLIENT = "00000000000000000000000007"
KEY_NAME = "deployment-e2e-read"
SESSION_DIR = Path.home() / ".cache/ts-session"
SUBJECT = re.compile(r"([0-9]{6})(?: is your (?:TerraScale|ts-auth) sign-in code| é o seu código de acesso para (?:TerraScale|ts-auth))")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class AuthCookies(urllib.request.HTTPCookieProcessor):
    # A broad-domain auth cookie must never accompany a TerraBase request.
    def http_request(self, request):
        return super().http_request(request) if urllib.parse.urlsplit(request.full_url).netloc == "auth.terrascale.tech" else request

    https_request = http_request


class SessionCache:
    def __init__(self):
        SESSION_DIR.parent.mkdir(parents=True, exist_ok=True)
        SESSION_DIR.mkdir(mode=0o700, exist_ok=True)
        self.fd = os.open(SESSION_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.locked = False
        try:
            self.validate(os.fstat(self.fd), directory=True)
        except BaseException:
            os.close(self.fd)
            raise

    @staticmethod
    def validate(info, directory=False):
        if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600) or
                not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)):
            raise ValueError("Private session cache permissions required.")

    def open(self, name, flags):
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
        try:
            self.validate(os.fstat(fd))
            return fd
        except BaseException:
            os.close(fd)
            raise

    @contextlib.contextmanager
    def lock(self):
        if self.locked:
            yield
            return
        with os.fdopen(self.open("signin.lock", os.O_CREAT | os.O_RDWR), "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.locked = True
            try:
                yield
            finally:
                self.locked = False
                fcntl.flock(lock, fcntl.LOCK_UN)

    def number(self, name):
        try:
            with os.fdopen(self.open(name, os.O_RDONLY)) as source:
                value = float(source.read(128))
                if not math.isfinite(value) or value < 0 or source.read(1):
                    raise ValueError("Invalid shared sign-in timestamp.")
                return value
        except FileNotFoundError:
            return 0

    def check_cooldown(self):
        if time.time() < self.number("cooldown-until"):
            raise ValueError("Shared HTTP 429 cooldown active; wait 15 minutes after the last rate limit.")

    def save(self, name, writer):
        if not self.locked:
            raise ValueError("Session cache writes require the sign-in lock.")
        # Reject unsafe existing entries; rename publishes only a complete private file.
        try:
            os.close(self.open(name, os.O_RDONLY))
        except FileNotFoundError:
            pass
        temporary = ".tmp-" + os.urandom(16).hex()
        fd = self.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            writer(fd)
            os.fsync(fd)
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            os.close(fd)
            try:
                os.unlink(temporary, dir_fd=self.fd)
            except FileNotFoundError:
                pass

    def timestamp(self, name, value):
        def write(fd):
            with os.fdopen(os.dup(fd), "w") as target:
                target.write(str(value))
        self.save(name, write)

    def load(self, jar):
        jar.clear()
        try:
            fd = self.open("mariogk.cookies", os.O_RDONLY)
        except FileNotFoundError:
            return False
        try:
            # Descriptor paths keep CookieJar's filename API on the validated inode.
            with warnings.catch_warnings():
                warnings.simplefilter("error", UserWarning)
                jar.load("/proc/self/fd/" + str(fd), ignore_discard=True)
        finally:
            os.close(fd)
        return True


def confirm(expected):
    target = expected["E2E_PROJECT_ID"] + "/" + expected["E2E_DATABASE"]
    negative = expected["E2E_PROJECT_ID"] + "/" + expected["E2E_UNRELATED_DATABASE"]
    phrase = "issue " + target + " negative " + negative
    try:
        with open("/dev/tty", "r") as control, open("/dev/tty", "w") as terminal:
            fd = control.fileno()
            if not os.isatty(fd):
                raise ValueError("A private controlling terminal is required.")
            original = termios.tcgetattr(fd)
            hidden = original.copy()
            hidden[3] &= ~(termios.ECHO | termios.ECHONL)
            try:
                # Discard queued input: an unattended pipe cannot supply consent.
                termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
                terminal.write("USER ONLY: issue one 23-hour documents:read key and install into MarioGK / "
                               "TerraScale/ts-orchestrator / production / E2E_PROJECT_CREDENTIAL.\n"
                               "Organization: " + expected["E2E_ORGANIZATION_ID"] + "\n"
                               "Confirm both exact databases in this one approved project; no negative-database key.\n"
                               "Type (hidden): " + phrase + "\n> ")
                terminal.flush()
                answer = control.readline(512).rstrip("\r\n")
            finally:
                termios.tcsetattr(fd, termios.TCSAFLUSH, original)
                terminal.write("\n")
                terminal.flush()
            if answer != phrase:
                raise ValueError("Exact hidden confirmation required.")
    except (OSError, termios.error):
        raise ValueError("Safe hidden /dev/tty confirmation unavailable; refused.") from None


def fresh_code(header, started, now):
    try:
        message = email.message_from_bytes(header)
        if len(message.get_all("Subject", [])) != 1 or len(message.get_all("Date", [])) != 1:
            return None
        recipients = [address for _, address in email.utils.getaddresses(message.get_all("To", []))]
        if recipients != [ADDRESS]:
            return None
        subject = str(email.header.make_header(email.header.decode_header(message["Subject"])))
        match = SUBJECT.fullmatch(subject)
        sent = email.utils.parsedate_to_datetime(message["Date"])
        if match and sent.tzinfo is not None and started - dt.timedelta(minutes=2) <= sent <= now + dt.timedelta(seconds=5):
            return match[1]
    except (ValueError, TypeError, UnicodeError, LookupError):
        pass
    return None


def mailbox_code(password, started):
    deadline = time.monotonic() + 180
    box = None
    try:
        box = imaplib.IMAP4_SSL("mailserver.purelymail.com", 993, ssl_context=ssl.create_default_context(), timeout=10)

        def command(operation, *args, **kwargs):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Mailbox delivery deadline reached.")
            box.sock.settimeout(min(10, remaining))
            status, data = operation(*args, **kwargs)
            if status != "OK":
                raise ValueError("Mailbox read failed.")
            return data

        command(box.login, ADDRESS, password)
        password = None
        command(box.select, "INBOX", readonly=True)
        while time.monotonic() < deadline:
            messages = command(box.search, None, "OR", "SUBJECT", '"TerraScale"', "SUBJECT", '"ts-auth"')
            codes = set()
            for item in reversed(messages[0].split()[-10:]):
                fetched = command(box.fetch, item, "(BODY.PEEK[HEADER.FIELDS (SUBJECT DATE TO)])")
                for entry in fetched:
                    if isinstance(entry, tuple):
                        code = fresh_code(entry[1], started, dt.datetime.now(dt.timezone.utc))
                        if code:
                            codes.add(code)
            if len(codes) > 1:
                raise ValueError("Ambiguous fresh sign-in mail; refused.")
            if codes:
                return codes.pop()
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(10, remaining))
        raise ValueError("Fresh sign-in mail not delivered within 180 seconds.")
    finally:
        password = None
        if box is not None:
            box.shutdown()


class Session:
    def __init__(self):
        self.jar = http.cookiejar.MozillaCookieJar()
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()), AuthCookies(self.jar), NoRedirect())
        self.token = None
        self.issuance_attempted = False
        self.cache = None

    def session_cache(self):
        if self.cache is None:
            self.cache = SessionCache()
        return self.cache

    def close(self):
        self.token = None
        self.jar.clear()
        self.http.close()
        if self.cache is not None:
            os.close(self.cache.fd)
            self.cache = None

    def call(self, url, method="GET", data=None, token=None, form=False, status=200):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc not in ("auth.terrascale.tech", "api.terrascale.tech") or parsed.fragment:
            raise ValueError("Only pinned TLS endpoints are allowed.")
        if (method == "POST" and url in (AUTH + "/ui/terrascale/sign-in", AUTH + "/ui/terrascale/sign-in/verify") and
                (self.cache is None or not self.cache.locked)):
            raise ValueError("Email sign-in requires the shared lock.")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if parsed.netloc == "api.terrascale.tech":
            headers["X-TerraScale-Region-Pin"] = "gru"
        if parsed.path.startswith("/ui/"):
            headers["Origin"] = AUTH
            headers["Accept-Language"] = "en"
        body = None
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            body = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
        # HTTPError and private response bodies are never rendered by the entry point.
        try:
            response = self.http.open(urllib.request.Request(url, body, headers, method=method), timeout=20)
        except urllib.error.HTTPError as error:
            try:
                if error.code == 429:
                    cache = self.session_cache()
                    with cache.lock():
                        cache.timestamp("cooldown-until", max(cache.number("cooldown-until"), time.time() + 900))
            finally:
                error.close()
            raise
        with response:
            content = response.read(65537)
            if response.status != status or response.geturl() != url or len(content) > 65536:
                raise ValueError("Pinned endpoint response rejected.")
            if response.headers.get_content_type() == "application/json":
                result = installer.parse_json(content)
                if not isinstance(result, dict) or "error" in result:
                    raise ValueError("Native response rejected.")
                return result
            if parsed.path.startswith("/ui/"):
                return content
            raise ValueError("Native JSON response required.")

    def cached_session(self, cache):
        if not cache.load(self.jar):
            return False
        try:
            self.call(AUTH + "/ui/terrascale/device")
            return True
        except urllib.error.HTTPError as error:
            if error.code == 401 or (error.code == 302 and error.headers.get("Location") in
                    ("/ui/terrascale/sign-in", AUTH + "/ui/terrascale/sign-in",
                     "/ui/terrascale/sign-in?next=%2Fui%2Fterrascale%2Fdevice",
                     AUTH + "/ui/terrascale/sign-in?next=%2Fui%2Fterrascale%2Fdevice")):
                return False
            raise

    def login(self, password):
        cache = self.session_cache()
        cache.check_cooldown()
        if not self.cached_session(cache):
            with cache.lock():
                cache.check_cooldown()
                if not self.cached_session(cache):
                    now = time.time()
                    if now < cache.number("last-signin-at") + 300:
                        raise ValueError("Shared five-minute sign-in request limit active.")
                    cache.timestamp("last-signin-at", now)
                    self.email_login(password)
                    cache.save("mariogk.cookies", lambda fd: self.jar.save("/proc/self/fd/" + str(fd), ignore_discard=True))
        password = None
        self.identify()

    def email_login(self, password):
        if self.cache is None or not self.cache.locked:
            raise ValueError("Email sign-in requires the shared lock.")
        started = dt.datetime.now(dt.timezone.utc)
        self.call(AUTH + "/ui/terrascale/sign-in", "POST", {"email": ADDRESS}, form=True)
        code = mailbox_code(password, started)
        password = None
        page = self.call(AUTH + "/ui/terrascale/sign-in/verify", "POST", {"email": ADDRESS, "code": code}, form=True)
        code = None
        if b"Signed in" not in page or not any(c.name == "tsauth_session" and c.secure for c in self.jar):
            raise ValueError("Hosted signed session required.")

    def identify(self):
        issued = self.call(ISSUER + "/oauth/device", "POST", {"client_id": CLIENT, "scope": "openid email"}, form=True)
        interval = issued.get("interval")
        if (issued.get("verification_uri") != AUTH + "/ui/terrascale/device" or
                type(interval) is not int or not 1 <= interval <= 60 or
                type(issued.get("expires_in")) is not int or issued["expires_in"] <= interval or
                any(not isinstance(issued.get(field), str) or not issued[field] for field in ("user_code", "device_code"))):
            raise ValueError("Native device response rejected.")
        page = self.call(AUTH + "/ui/terrascale/device", "POST",
                         {"user_code": issued["user_code"], "decision": "approve"}, form=True)
        if b"Device connected" not in page:
            raise ValueError("Hosted device approval failed.")
        time.sleep(interval)
        tokens = self.call(ISSUER + "/oauth/token", "POST", {"client_id": CLIENT,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": issued["device_code"]}, form=True)
        issued.clear()
        if tokens.get("token_type") != "Bearer" or "refresh_token" in tokens or not isinstance(tokens.get("access_token"), str) or not tokens["access_token"]:
            raise ValueError("Native sign-in token rejected.")
        self.token = tokens.pop("access_token")
        tokens.clear()
        me = self.call(ISSUER + "/oauth/userinfo", token=self.token)
        if me.get("email") != ADDRESS or me.get("email_verified") is not True:
            raise ValueError("Verified operator identity required.")

    def verify_targets(self, expected):
        organization, project, database, negative = (expected[name] for name in installer.VARIABLES)
        root = AUTH + "/v1/terrascale/organizations/" + organization
        org = self.call(root, token=self.token)
        if org.get("id") != organization or org.get("role") not in ("owner", "admin"):
            raise ValueError("Organization owner/admin required.")
        if database == negative:
            raise ValueError("Two distinct databases in one approved project required.")
        metadata = self.call(root + "/projects/" + project, token=self.token)
        if metadata.get("id") != project or metadata.get("organization_id") != organization:
            raise ValueError("Exact project must belong to the approved organization.")
        tokens = self.call(ISSUER + "/oauth/token", "POST", {"client_id": CLIENT,
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": self.token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "organization": organization,
            "project": project, "scope": "databases:read"}, form=True)
        if tokens.get("token_type") != "Bearer" or "refresh_token" in tokens or not isinstance(tokens.get("access_token"), str) or not tokens["access_token"]:
            raise ValueError("Read-only metadata exchange rejected.")
        ids = []
        for selected in (database, negative):
            metadata = self.call(API + "/v1/projects/" + project + "/databases/" + selected, token=tokens["access_token"])
            if (metadata.get("projectId") != project or metadata.get("name") != selected or
                    not isinstance(metadata.get("id"), str) or not installer.ID.fullmatch(metadata["id"])):
                raise ValueError("Both exact databases must already exist.")
            ids.append(metadata["id"])
        if ids[0] == ids[1]:
            raise ValueError("Two distinct databases in one approved project required.")
        tokens.clear()
        keys_url = root + "/projects/" + project + "/api-keys"
        prior = self.call(keys_url, token=self.token)
        if prior.get("items") != [] or prior.get("next", "missing") is not None:
            raise ValueError("Project must have zero existing keys; operator inspection required.")
        return keys_url, ids[0]

    def issue(self, keys_url, database_id):
        if self.issuance_attempted:
            raise ValueError("A second issuance is forbidden.")
        self.issuance_attempted = True
        expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=23)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        return self.call(keys_url, "POST", {"name": KEY_NAME, "database": database_id,
            "scopes": ["documents:read"], "expires_at": expiry}, token=self.token, status=201)


def run():
    session = None
    raw = password = issued = None
    stage = "GitHub preflight"
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        expected = installer.preflight()
        stage = "hidden user confirmation"
        confirm(expected)
        stage = "stdin password"
        if sys.stdin.isatty():
            raise ValueError("Redirect the existing mailbox password file to stdin.")
        password = sys.stdin.readline(4097).rstrip("\r\n")
        if not password or len(password) > 4096:
            raise ValueError("One mailbox password line is required on stdin.")
        session = Session()
        stage = "hosted sign-in"
        session.login(password)
        password = None
        stage = "read-only target verification"
        keys_url, database_id = session.verify_targets(expected)
        # Recheck GitHub immediately before the irreversible one-time issuance.
        if installer.preflight() != expected:
            raise ValueError("GitHub target variables changed; refused.")
        stage = "single key issuance (outcome may be ambiguous; never retry)"
        issued = session.issue(keys_url, database_id)
        raw = json.dumps(issued)
        stage = "native response validation (key may exist; never retry)"
        metadata = installer.validate(raw, expected, dt.datetime.now(dt.timezone.utc), database_id)
        if metadata.get("name") != KEY_NAME:
            raise ValueError("Native key name mismatch.")
        # Print only validated, allowlisted cleanup fields before any installation failure.
        print("Key id: " + metadata["id"] + "; expires: " +
              dt.datetime.fromisoformat(metadata["expires_at"].replace("Z", "+00:00")).astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z") +
              "; target: " + expected["E2E_ORGANIZATION_ID"] + "/" + metadata["project_id"] + "/" + metadata["database"], flush=True)
        stage = "GitHub installation (outcome may be ambiguous; never retry)"
        installer.gh(["secret", "set", "--repo", installer.REPO, "--env", installer.ENVIRONMENT, installer.SECRET], data=raw.encode())
        print("Installed E2E_PROJECT_CREDENTIAL in production; value hidden. Production acceptance remains unproven.")
        return 0
    except (Exception, KeyboardInterrupt):
        print("Stopped during " + stage + ". Private diagnostics suppressed. "
              "After an issuance attempt, inspect native key metadata before any further action; no replacement, retry or revocation performed.", file=sys.stderr)
        return 1
    finally:
        raw = password = None
        if isinstance(issued, dict):
            issued.clear()
        if session is not None:
            session.close()


def interrupted(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    if sys.argv[1:]:
        sys.exit("No arguments accepted; USER RUN ONLY with password-file stdin redirection.")
    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        signal.signal(sig, interrupted)
    sys.exit(run())
