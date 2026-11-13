import ctypes
import errno
import os
import pathlib
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long


def ptrace(op, pid, address=0, data=0):
    ctypes.set_errno(0)
    result = libc.ptrace(op, pid, ctypes.c_void_p(address), data)
    if result == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), "ptrace")
    return result


class Registers(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in [
            "r15",
            "r14",
            "r13",
            "r12",
            "rbp",
            "rbx",
            "r11",
            "r10",
            "r9",
            "r8",
            "rax",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "orig_rax",
            "rip",
            "cs",
            "eflags",
            "rsp",
            "ss",
            "fs_base",
            "gs_base",
            "ds",
            "es",
            "fs",
            "gs",
        ]
    ]


class Iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


def result_register(pid, value, skip=False):
    if os.uname().machine == "x86_64":
        regs = Registers()
        ptrace(12, pid, 0, ctypes.byref(regs))
        if skip:
            regs.orig_rax = value
        else:
            regs.rax = value
        ptrace(13, pid, 0, ctypes.byref(regs))
    else:
        regs = (ctypes.c_ulonglong * 34)()
        view = Iovec(ctypes.addressof(regs), ctypes.sizeof(regs))
        if skip:
            number = ctypes.c_int(-1)
            view = Iovec(ctypes.addressof(number), ctypes.sizeof(number))
            ptrace(0x4205, pid, 0x404, ctypes.byref(view))
        else:
            ptrace(0x4204, pid, 1, ctypes.byref(view))
            regs[0] = value
            ptrace(0x4205, pid, 1, ctypes.byref(view))


def string(pid, address):
    data = bytearray()
    while len(data) < 4096:
        ctypes.set_errno(0)
        word = ptrace(2, pid, address + len(data))
        part = (word & ((1 << 64) - 1)).to_bytes(8, "little")
        data.extend(part)
        if 0 in part:
            return bytes(data).split(b"\0")[0].decode()
    raise RuntimeError("unterminated syscall path")


def path_arg(pid, address, directory=-100):
    value = string(pid, address)
    if value.startswith("/"):
        return value
    root = os.readlink(
        f"/proc/{pid}/cwd" if directory == -100 else f"/proc/{pid}/fd/{directory}"
    )
    return os.path.normpath(root + "/" + value)


class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class SockProgram(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def filter_syscalls(name):
    numbers = [
        number
        for number, call in (fd_calls | path_calls).items()
        if call == name or name == "persistent"
    ]
    if os.uname().machine == "x86_64":
        numbers += [
            number
            for number, call in {
                82: "rename",
                87: "unlink",
                86: "link",
                83: "mkdir",
            }.items()
            if call == name or name == "persistent"
        ]
    instructions = [SockFilter(0x20, 0, 0, 0)]
    for number in numbers:
        instructions += [
            SockFilter(0x15, 0, 1, number),
            SockFilter(0x06, 0, 0, 0x7FF00000),
        ]
    instructions.append(SockFilter(0x06, 0, 0, 0x7FFF0000))
    compiled = (SockFilter * len(instructions))(*instructions)
    program = SockProgram(len(instructions), compiled)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        raise OSError(ctypes.get_errno(), "install syscall filter")


def run(helper, step, flow, syscall_name, pattern, occurrence, outcome, resume, expect):
    with (
        tempfile.TemporaryDirectory(prefix="release-commit-") as work,
        tempfile.TemporaryFile() as log,
    ):
        root_pid = os.fork()
        if root_pid == 0:
            os.dup2(log.fileno(), 1)
            os.dup2(log.fileno(), 2)
            ptrace(0, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            filter_syscalls(syscall_name)
            os.execv(
                helper,
                [helper, flow, work, outcome],
            )
        _, status = os.waitpid(root_pid, 0)
        if not os.WIFSTOPPED(status):
            log.seek(0)
            raise RuntimeError(
                f"{step}: tracer startup failed: {log.read().decode(errors='replace')[-3000:]}"
            )
        ptrace(0x4200, root_pid, 0, 1 | 2 | 4 | 8 | 16 | 0x80 | 0x100000)
        ptrace(7, root_pid)
        live = {root_pid}
        injected = set()
        hits = 0
        root_status = None
        committed = False
        committing = set()
        kill_after = set()
        busy = None
        stalled = {}
        while live:
            for held, until in list(stalled.items()):
                if time.monotonic() >= until:
                    del stalled[held]
                    try:
                        ptrace(7, held)
                    except ProcessLookupError:
                        pass
            try:
                pid, status = os.waitpid(-1, 0x40000000 | (os.WNOHANG if stalled else 0))
            except ChildProcessError:
                if root_status is None:
                    raise
                break
            if pid == 0:
                time.sleep(0.01)
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                live.discard(pid)
                if pid == root_pid:
                    root_status = status
                continue
            try:
                stop = os.WSTOPSIG(status)
                event = status >> 16
                if event in (1, 2, 3):
                    new = ctypes.c_ulonglong()
                    ptrace(0x4201, pid, 0, ctypes.byref(new))
                    live.add(new.value)
                if (stop == (signal.SIGTRAP | 0x80) or event == 7) and pathlib.Path(
                    f"/proc/{pid}"
                ).exists():
                    info = ctypes.create_string_buffer(88)
                    try:
                        ptrace(0x420E, pid, 88, ctypes.byref(info))
                    except ProcessLookupError:
                        continue
                    op = info.raw[0]
                    if op == 3 and pathlib.Path(work, "armed").exists():
                        number, *args = struct.unpack_from("7Q", info.raw, 24)
                        name, path = "", ""
                        try:
                            if number in fd_calls:
                                name = fd_calls[number]
                                path = os.readlink(f"/proc/{pid}/fd/{args[0]}")
                            elif os.uname().machine == "x86_64" and number in (
                                82,
                                87,
                                86,
                                83,
                            ):
                                name = {
                                    82: "rename",
                                    87: "unlink",
                                    86: "link",
                                    83: "mkdir",
                                }[number]
                                path = path_arg(
                                    pid, args[1] if number in (82, 86) else args[0]
                                )
                            elif number in path_calls and path_calls[number] == "exec":
                                name, path = "exec", path_arg(pid, args[0])
                            elif number in path_calls:
                                name = path_calls[number]
                                destination = name in ("rename", "link")
                                path = path_arg(
                                    pid,
                                    args[3] if destination else args[1],
                                    ctypes.c_int(
                                        args[2] if destination else args[0]
                                    ).value,
                                )
                        except (OSError, ValueError):
                            pass
                        relative = path.removeprefix(work)
                        if (
                            syscall_name == "persistent"
                            and name == "rename"
                            and relative == "/installed"
                        ):
                            committing.add(pid)
                        persistent = (
                            syscall_name == "persistent"
                            and committed
                            and not pathlib.Path(work, "disarmed").exists()
                            and (
                                relative == ""
                                or relative.startswith(("/nats/", "/installed.prev"))
                            )
                            and (
                                name in ("write", "fsync", "rename", "unlink")
                                or name == "open"
                                and (relative == "" or "/.release-" in relative)
                            )
                        )
                        if (
                            persistent
                            or name == syscall_name
                            and re.fullmatch(pattern, relative)
                        ):
                            hits += 1
                            if outcome == "busy":
                                if hits == occurrence:
                                    busy = (
                                        os.open(work + relative, os.O_WRONLY),
                                        time.monotonic(),
                                    )
                                elif busy and time.monotonic() - busy[1] > 0.3:
                                    os.close(busy[0])
                                    busy = None
                            elif hits == occurrence and outcome == "stall":
                                stalled[pid] = time.monotonic() + 123
                            elif hits == occurrence and outcome == "crash-after":
                                kill_after.add(pid)
                            elif hits == occurrence and outcome == "crash":
                                for traced in live:
                                    try:
                                        os.kill(traced, signal.SIGKILL)
                                    except ProcessLookupError:
                                        pass
                            elif persistent or hits == occurrence:
                                result_register(pid, (1 << 64) - 1, skip=True)
                                injected.add(pid)
                    elif op == 2:
                        if pid in kill_after:
                            for traced in live:
                                try:
                                    os.kill(traced, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                        if pid in committing:
                            committed = struct.unpack_from("q", info.raw, 24)[0] == 0
                            committing.remove(pid)
                        if pid in injected:
                            result_register(pid, (1 << 64) - errno.EIO)
                            injected.remove(pid)
                deliver = (
                    0
                    if stop in (signal.SIGSTOP, signal.SIGTRAP, signal.SIGTRAP | 0x80)
                    else stop
                )
                if pid in stalled:
                    continue
                ptrace(
                    24
                    if pid in injected or pid in committing or pid in kill_after
                    else 7,
                    pid,
                    0,
                    deliver,
                )
            except ProcessLookupError:
                continue
        if busy:
            os.close(busy[0])
            raise RuntimeError(f"{step}: candidate exec was never retried")
        returncode = os.waitstatus_to_exitcode(root_status)
        log.seek(0)
        output = log.read().decode(errors="replace")
        killed = outcome in ("crash", "crash-after")
        if stalled:
            raise RuntimeError(f"{step}: a stalled syscall was never released")
        if hits < occurrence or returncode != (-signal.SIGKILL if killed else 0):
            raise RuntimeError(
                f"{step}: exit {returncode}, hits {hits}/{occurrence}\n{output[-5000:]}"
            )
        if not re.search(expect, output):
            raise RuntimeError(f"{step}: missing {expect!r}\n{output[-5000:]}")
        if outcome == "persistent":
            for warning in (
                "binary rename durability",
                "worker relay",
                "reply delivery",
                "reply flush",
            ):
                if warning not in output:
                    raise RuntimeError(
                        f"{step}: missing WARN for {warning}\n{output[-5000:]}"
                    )
        continued = subprocess.run(
            [helper, "resume-case", work, resume],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if continued.returncode:
            raise RuntimeError(
                f"{step}: start after {outcome} failed\n{continued.stdout[-2000:]}{continued.stderr[-3000:]}"
            )
        print(f"ok {outcome} {step}: {continued.stdout.strip()}", flush=True)


if os.uname().machine == "x86_64":
    fd_calls = {1: "write", 3: "close", 74: "fsync", 91: "chmod"}
    path_calls = {
        59: "exec",
        257: "open",
        258: "mkdir",
        263: "unlink",
        264: "rename",
        265: "link",
        316: "rename",
    }
elif os.uname().machine == "aarch64":
    fd_calls = {64: "write", 57: "close", 82: "fsync", 52: "chmod"}
    path_calls = {
        221: "exec",
        56: "open",
        34: "mkdir",
        35: "unlink",
        38: "rename",
        37: "link",
        276: "rename",
    }
else:
    raise RuntimeError("syscall fault lane needs Linux amd64 or arm64")
helper = sys.argv[1]
precommit = []
for call in ("open", "write", "chmod", "fsync", "close"):
    precommit.append(("candidate-" + call, call, r"/installed.next", 1))
precommit.append(("preflight-exec", "exec", r"/installed.next", 1))
busy_exec = ("preflight-busy", "commit-case", "exec", r"/installed.next", 1, "busy", "commit", "traced install: installed")
for index, (record, staged) in enumerate(
    (("trial", "/nats/release-trial.staged"), ("run-id", "/nats/release-run-id")), 1
):
    for call in ("open", "write", "fsync", "close"):
        precommit.append((record + "-" + call, call, r"/nats/.release-.*", index))
    precommit.append((record + "-rename", "rename", staged, 1))
    precommit.append((record + "-directory-sync", "fsync", r"/nats", index))
precommit += [
    ("previous-unlink", "unlink", r"/installed.prev.staged", 1),
    ("previous-link", "link", r"/installed.prev.staged", 1),
    ("previous-directory-sync", "fsync", "", 1),
    ("binary-rename", "rename", r"/installed", 1),
]
cases = [
    (name, "commit-case", call, pattern, n, "rejected", "commit", "traced install: rejected")
    for name, call, pattern, n in precommit
]
cases += [
    busy_exec,
    ("binary-directory-open", "commit-case", "open", "", 2, "installed", "commit", "traced install: installed"),
    ("binary-directory-sync", "commit-case", "fsync", "", 2, "installed", "commit", "binary rename durability"),
    ("all-postcommit", "commit-case", "persistent", ".*", 1, "persistent", "commit", ""),
]
cases += [
    ("crash-" + name, "commit-case", call, pattern, n, "crash", "commit", "")
    for name, call, pattern, n in precommit
    + [("binary-directory-sync", "fsync", "", 2)]
]
cases += [
    ("crash-after-" + name, "commit-case", call, pattern, n, "crash-after", "commit", "")
    for name, call, pattern, n in (
        ("trial-rename", "rename", "/nats/release-trial.staged", 1),
        ("run-id-rename", "rename", "/nats/release-run-id", 1),
        ("previous-link", "link", r"/installed.prev.staged", 1),
        ("binary-rename", "rename", r"/installed", 1),
        ("binary-directory-sync", "fsync", "", 2),
    )
]
for outcome in ("crash", "crash-after"):
    for name, call, pattern, n in (
        ("rollback-record-rename", "rename", "/nats/release-rolled-back", 1),
        ("rollback-rename", "rename", r"/installed", 1),
        ("rollback-directory-sync", "fsync", "", 1),
    ):
        cases.append((outcome + "-" + name, "rollback-case", call, pattern, n, outcome, "rollback", ""))
cases += [
    ("crash-confirm-unlink", "confirm-case", "unlink", "/nats/release-trial", 1, "crash", "confirm", ""),
    ("crash-after-confirm-unlink", "confirm-case", "unlink", "/nats/release-trial", 1, "crash-after", "confirm", ""),
    ("confirm-sync", "confirm-case", "fsync", r"/nats", 2, "eio", "confirm", '"served":false,"after":"unconfirmed"'),
    ("rollback-directory-sync", "rollback-case", "fsync", "", 1, "eio", "rollback-kept", "START rolled-back"),
    ("settle-directory-sync", "settle-case", "fsync", "", 1, "eio", "settle", '"state":"","error":"","rolled_back":"","health_state":"","served":true'),
    ("expiry-race", "expiry-race-case", "rename", r"/installed", 1, "stall", "expiry", "traced expiry race: installed probation"),
]
served = '"state":"probation","error":"","rolled_back":"","health_state":"","served":true,"after":""'
for flow, label in (("confirm-case", "first"), ("confirm-last-case", "last")):
    cases += [
        ("counter-sync-" + label, flow, "fsync", r"/nats", 1, "eio", "confirm", served),
        ("counter-rename-" + label, flow, "rename", "/nats/release-trial", 1, "eio", "confirm", served),
    ]
for flow, resume, steps in (
    (
        "replace-case",
        "replace",
        (
            ("trial-stage", "rename", "/nats/release-trial.staged", 1),
            ("fence-write", "rename", "/nats/release-run-id", 1),
            ("preflight", "exec", r"/installed.next", 1),
            ("previous-stage", "link", r"/installed.prev.staged", 1),
            ("previous-stage-sync", "fsync", "", 1),
            ("binary-rename", "rename", r"/installed", 1),
        ),
    ),
    (
        "damaged-replace-case",
        "damaged-replace",
        (
            ("fence-write", "rename", "/nats/release-run-id", 1),
            ("previous-stage", "link", r"/installed.prev.staged", 1),
        ),
    ),
):
    cases += [
        (flow.removesuffix("-case") + "-" + name, flow, call, pattern, n, "rejected", resume, "traced replace: rejected")
        for name, call, pattern, n in steps
    ]
for flow, resume, outcome, name, call, pattern, n in (
    ("replace-case", "replace", "crash-after", "trial-stage", "rename", "/nats/release-trial.staged", 1),
    ("replace-case", "replace", "crash", "binary-rename", "rename", r"/installed", 1),
    ("replace-case", "replace", "crash-after", "binary-rename", "rename", r"/installed", 1),
    ("replace-case", "replace", "crash-after", "binary-directory-sync", "fsync", "", 2),
    ("replace-case", "replace", "crash-after", "previous-promote", "rename", r"/installed.prev", 1),
    ("replace-case", "replace", "crash-after", "record-remove", "unlink", "/nats/release-rolled-back", 1),
    ("replace-case", "replace", "crash-after", "trial-promote", "rename", "/nats/release-trial", 1),
    ("replace-case", "replace", "crash-after", "trial-directory-sync", "fsync", r"/nats", 3),
    ("damaged-replace-case", "damaged-replace", "crash-after", "damaged-archive", "link", "/nats/release-trial.damaged", 1),
    ("damaged-replace-case", "damaged-replace", "crash-after", "trial-promote", "rename", "/nats/release-trial", 1),
):
    cases.append((outcome + "-" + flow.removesuffix("-case") + "-" + name, flow, call, pattern, n, outcome, resume, ""))


def isolated(case):
    result = subprocess.run(
        [sys.executable, __file__, helper, case[0]],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stdout[-2000:] + result.stderr[-5000:])
    return result.stdout


if __name__ == "__main__":
    start = time.monotonic()
    if len(sys.argv) == 2:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for output in pool.map(isolated, cases):
                print(output.rstrip(), flush=True)
        completed = len(cases)
    else:
        completed = 0
        for case in cases:
            if case[0] in sys.argv[2:]:
                run(helper, *case)
                completed += 1
    print(
        f"fault journey: {completed} cases PASS in {time.monotonic() - start:.2f}s",
        flush=True,
    )
