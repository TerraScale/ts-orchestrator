import asyncio
import contextlib
import pathlib
import resource
import sys

binary, state, ca = sys.argv[1:]



async def proof(log):
    changed = asyncio.Condition()
    warm_release = asyncio.Event()
    busy_release = asyncio.Event()
    current = {"warm": 0, "busy-0": 0, "busy-1": 0}
    entered = {"warm": 0, "busy": 0}
    refused = 0
    failed = []
    clients = []
    tasks = []
    loaders = []
    servers = []
    process = None
    slots = asyncio.Semaphore(512)

    async def notify():
        async with changed:
            changed.notify_all()

    async def backend(reader, writer, name):
        current[name] += 1
        await notify()
        try:
            while True:
                await reader.readuntil(b"\r\n\r\n")
                kind = "warm" if name == "warm" else "busy"
                entered[kind] += 1
                await notify()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                await writer.drain()
                await (warm_release if kind == "warm" else busy_release).wait()
                writer.write(b"0")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            current[name] -= 1
            await notify()
            writer.close()
            await writer.wait_closed()

    async def connect(index, source):
        return await asyncio.open_connection(
            "127.0.0.1", 80, local_addr=(f"127.0.0.{source + index % 2}", 0)
        )

    async def request(index, name):
        nonlocal refused
        writer = None
        try:
            reader, writer = await connect(index, 2)
            writer.write(
                f"GET /healthz HTTP/1.1\r\nHost: {name}.e2e.test\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
            status = int(header.split(b" ", 2)[1])
            if status == 503:
                refused += 1
                await notify()
            elif status == 200:
                assert await reader.readexactly(1) == b"0"
            else:
                raise AssertionError(f"unexpected HTTP {status}")
        except Exception as error:
            failed.append(error)
            await notify()
            raise
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()

    async def reached(predicate):
        async with changed:
            await changed.wait_for(lambda: predicate() or failed)
        if failed:
            raise failed[0]

    async def park(index):
        async with slots:
            reader, writer = await connect(index, 4)
            writer.write(b"GET / HTTP/1.1\r\nHost: idle.e2e.test\r\n\r\n")
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
            lines = header.split(b"\r\n")
            assert int(lines[0].split(b" ", 2)[1]) == 404
            headers = dict(line.lower().split(b":", 1) for line in lines[1:] if b":" in line)
            await reader.readexactly(int(headers[b"content-length"]))
            clients.append((reader, writer))

    async def start_load(name, count):
        loader = await asyncio.create_subprocess_exec(
            binary, state, ca, "pg.e2e.test", "budget-load", name, str(count),
            stdout=asyncio.subprocess.PIPE,
            stderr=log,
        )
        loaders.append(loader)
        while True:
            line = (await loader.stdout.readline()).decode()
            assert line, f"load process exited: {await loader.wait()}"
            if line.strip() == "load-ready":
                return

    async def snapshot(command):
        process.stdin.write(command.encode() + b"\n")
        await process.stdin.drain()
        lines = []
        while True:
            line = (await process.stdout.readline()).decode()
            assert line, "edge exited during descriptor snapshot"
            if line.strip() == "budget-end":
                return lines
            lines.append(line)

    def samples(lines):
        values = {}
        for line in lines:
            fields = line.split()
            if len(fields) == 2:
                with contextlib.suppress(ValueError):
                    values[fields[0]] = float(fields[1])
        return values

    try:
        ports = []
        for name in current:
            server = await asyncio.start_server(
                lambda reader, writer, name=name: backend(reader, writer, name),
                "127.0.0.1",
                0,
            )
            servers.append(server)
            ports.append(str(server.sockets[0].getsockname()[1]))
        process = await asyncio.create_subprocess_exec(
            binary, state, ca, "pg.e2e.test", "budget", *ports,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=log,
        )
        while True:
            line = (await process.stdout.readline()).decode()
            assert line, f"edge exited: {process.returncode}"
            if line.strip() == "budget-ready":
                break
        tasks = [asyncio.create_task(request(i, "warm")) for i in range(512)]
        await reached(lambda: entered["warm"] == 512)
        warm_release.set()
        await asyncio.gather(*tasks)
        await reached(lambda: current["warm"] == 128)
        print("warm task: 512 concurrent requests, 128 retained upstreams")
        await start_load("busy-0", 8192)
        await reached(lambda: entered["busy"] == 8192)
        task_metrics = await snapshot("task")
        assert any("ok shared task budget" in line for line in task_metrics)
        assert any('reason="upstream_task"' in line for line in task_metrics)
        print("task share: 8192 HTTP/1.1 sockets, concurrent h2c request refused with 503")
        await start_load("busy-1", 8064)
        await reached(lambda: entered["busy"] == 16256)
        overload = [asyncio.create_task(request(i, "busy-1")) for i in range(128)]
        await asyncio.gather(*overload)
        assert refused == 128, refused
        before_park = samples(await snapshot("metrics"))
        park_count = 32640 - int(before_park["ts_orch_edge_client_connections"])
        await asyncio.gather(*(park(i) for i in range(park_count)))
        metrics = await snapshot("metrics")
        values = samples(metrics)
        assert values["limit"] == 65536, values
        assert values["ts_orch_edge_upstream_connections"] == 16384, values
        assert values["ts_orch_edge_upstream_connection_limit"] == 16384, values
        assert 48000 <= values["fds"] < 50000, values["fds"]
        assert 32638 <= values["ts_orch_edge_client_connections"] <= 32640, values["ts_orch_edge_client_connections"]
        assert current["busy-0"] == 8192 and current["busy-1"] == 8064
        assert any('reason="upstream_node"' in line for line in metrics)
        print(
            f"mixed tasks: upstreams=16384, active={entered['busy']}, "
            f"idle=128, refused={refused}, parked={park_count}, "
            f"edge_fds={int(values['fds'])}/65536, "
            f"descriptor_headroom={65536 - int(values['fds'])}"
        )
        busy_release.set()
        for loader in loaders:
            assert (await loader.stdout.readline()).strip() == b"load-done"
            assert await loader.wait() == 0
    finally:
        warm_release.set()
        busy_release.set()
        for _, writer in clients:
            writer.close()
        for _, writer in clients:
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for loader in loaders:
            await loader.wait()
        if process is not None:
            process.stdin.close()
            await process.wait()
        for server in servers:
            server.close()
            await server.wait_closed()


async def main(log):
    async with asyncio.timeout(60):
        await proof(log)


resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
with pathlib.Path(state, "upstream-edge.log").open("w+") as log:
    try:
        asyncio.run(main(log))
    except BaseException:
        log.seek(0)
        print("".join(log.readlines()[-20:]), file=sys.stderr)
        raise
