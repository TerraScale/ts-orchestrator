import ctypes
import errno
import os
import pathlib
import re
import signal
import struct
import sys
import tempfile

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


def run(helper, step, syscall_name, pattern, occurrence, outcome):
    with (
        tempfile.TemporaryDirectory(prefix="release-commit-") as work,
        tempfile.TemporaryFile() as log,
    ):
        root_pid = os.fork()
        if root_pid == 0:
            os.dup2(log.fileno(), 1)
            os.dup2(log.fileno(), 2)
            ptrace(0, 0)
            os.execv(helper, [helper, "commit-case", work, outcome])
        _, status = os.waitpid(root_pid, 0)
        ptrace(0x4200, root_pid, 0, 1 | 2 | 4 | 8 | 16 | 0x100000)
        ptrace(24, root_pid)
        live = {root_pid}
        injected = set()
        hits = 0
        root_status = None
        while live:
            pid, status = os.waitpid(-1, 0x40000000)
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
                if (
                    stop == (signal.SIGTRAP | 0x80)
                    and pathlib.Path(f"/proc/{pid}").exists()
                ):
                    info = ctypes.create_string_buffer(88)
                    try:
                        ptrace(0x420E, pid, 88, ctypes.byref(info))
                    except ProcessLookupError:
                        continue
                    op = info.raw[0]
                    if op == 1 and pathlib.Path(work, "armed").exists():
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
                        if name == syscall_name and re.fullmatch(pattern, relative):
                            hits += 1
                            if hits == occurrence:
                                result_register(pid, (1 << 64) - 1, skip=True)
                                injected.add(pid)
                    elif op == 2 and pid in injected:
                        result_register(pid, (1 << 64) - errno.EIO)
                        injected.remove(pid)
                deliver = (
                    0
                    if stop in (signal.SIGSTOP, signal.SIGTRAP, signal.SIGTRAP | 0x80)
                    else stop
                )
                ptrace(24, pid, 0, deliver)
            except ProcessLookupError:
                continue
        returncode = os.waitstatus_to_exitcode(root_status)
        log.seek(0)
        output = log.read().decode(errors="replace")
        if returncode or hits < occurrence:
            raise RuntimeError(
                f"{step}: exit {returncode}, hits {hits}/{occurrence}\n{output[-5000:]}"
            )
        print(
            f"ok fault {step}: {outcome}; binary, records, relay, restart; first activation wins",
            flush=True,
        )


if os.uname().machine == "x86_64":
    fd_calls = {1: "write", 3: "close", 74: "fsync", 91: "chmod"}
    path_calls = {
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
cases = [
    ("candidate-open", "open", r"/installed.next", 1, "rejected"),
    ("candidate-write", "write", r"/installed.next", 1, "rejected"),
    ("candidate-chmod", "chmod", r"/installed.next", 1, "rejected"),
    ("candidate-sync", "fsync", r"/installed.next", 1, "rejected"),
    ("candidate-close", "close", r"/installed.next", 1, "rejected"),
    ("journal-create", "mkdir", r"/installed.release", 1, "rejected"),
    ("previous-link", "link", r"/installed.release/previous", 1, "rejected"),
    ("candidate-link", "link", r"/installed.release/candidate", 1, "rejected"),
]
for index, record in enumerate(("run", "trial", "manifest"), 1):
    for call in ("open", "write", "fsync", "close"):
        cases.append(
            (
                record + "-" + call,
                call,
                r"/installed.release/.release-.*",
                index,
                "rejected",
            )
        )
    cases.append(
        (record + "-rename", "rename", "/installed.release/" + record, 1, "rejected")
    )
    cases.append(
        (record + "-directory-sync", "fsync", r"/installed.release", index, "rejected")
    )
cases.extend(
    [
        ("prepare-parent-sync", "fsync", "", 1, "rejected"),
        ("binary-rename", "rename", r"/installed", 1, "rejected"),
        ("binary-directory-open", "open", "", 2, "installed"),
        ("binary-directory-sync", "fsync", "", 2, "installed"),
        ("previous-publish-link", "link", r"/installed.prev.publish", 1, "installed"),
        ("previous-publish-rename", "rename", r"/installed.prev", 1, "installed"),
        ("previous-publish-sync", "fsync", "", 3, "installed"),
        ("run-publish-link", "link", r"/nats/release-run-id.publish", 1, "installed"),
        ("run-publish-rename", "rename", r"/nats/release-run-id", 1, "installed"),
        ("trial-publish-link", "link", r"/nats/release-trial.publish", 1, "installed"),
        ("trial-publish-rename", "rename", r"/nats/release-trial", 1, "installed"),
        ("rollback-removal", "unlink", r"/nats/release-rolled-back", 1, "installed"),
        ("state-detach", "rename", r"/installed.release.done", 1, "installed"),
        (
            "state-cleanup",
            "unlink",
            r"/installed.release.done/previous",
            1,
            "installed",
        ),
        ("run-directory-sync", "fsync", r"/nats", 2, "installed"),
        ("trial-directory-sync", "fsync", r"/nats", 3, "installed"),
        ("rollback-directory-sync", "fsync", r"/nats", 4, "installed"),
        ("activation-write", "write", r"/nats/.release-.*", 3, "installed"),
        ("activation-sync", "fsync", r"/nats/.release-.*", 3, "installed"),
        ("activation-rename", "rename", r"/nats/release-trial", 2, "installed"),
    ]
)
if __name__ == "__main__":
    for case in cases:
        if len(sys.argv) == 2 or case[0] in sys.argv[2:]:
            run(helper, *case)
