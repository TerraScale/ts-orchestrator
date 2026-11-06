#!/usr/bin/env python3
"""Two bounded integration checks; run only via ts-heavy-any on a dev host."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import cold
import notice


class MemoryKv:
    def __init__(self):
        self.data = {k: {'seq': i + 10, 'data': base64.b64encode(b'{"node":"sjc2","epoch":3}').decode()} for i, k in enumerate(cold.KEYS)}
        self.writes = 0
        self.race = False

    def read(self, key):
        return self.data[key]

    def request(self, subject, data, headers):
        self.writes += 1
        key = subject.removeprefix('$KV.terrabase-homes.')
        if self.race:
            self.data[key] = {**self.data[key], 'seq': 999}
        if self.data[key]['seq'] != headers['Nats-Expected-Last-Subject-Sequence']:
            return {'error': {'code': 400, 'err_code': 10071}}
        assert headers['KV-Operation'] == 'DEL' and data == b''
        m = {'seq': self.data[key]['seq'] + 20, 'data': '', 'hdrs': base64.b64encode(b'NATS/1.0\r\nKV-Operation: DEL\r\n\r\n').decode()}
        self.data[key] = m
        return {'seq': m['seq']}

    def approved(self):
        return {k: {'revision': m['seq'], 'sha256': hashlib.sha256(base64.b64decode(m['data'])).hexdigest()} for k, m in self.data.items()}


class Qualification(unittest.TestCase):
    def test_happy_maintenance_receipts_and_readback(self):
        os.umask(0o077)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            data = root / 'source'; data.mkdir()
            (data / 'db-wal').write_bytes(bytes(range(256)) * 8192)
            (data / 'holds').mkdir(); (data / 'holds' / 'ack').write_bytes(b'acknowledged\x00\xff')
            roots = root / 'roots.json'; roots.write_text(json.dumps([str(data)]))
            password = root / 'existing-password'; password.write_text('dev-only-ephemeral-qualification-key')
            with contextlib.redirect_stdout(io.StringIO()):
                cold.backup(SimpleNamespace(roots=str(roots), destination=str(root / 'backup'), password=str(password)))
            manifest = json.loads((root / 'backup/manifest.json').read_text())
            self.assertGreater(manifest['bytes'], 2_000_000)
            self.assertLess(manifest['elapsedSeconds'], 150)
            print('BACKUP', json.dumps({k: v for k, v in manifest.items() if k != 'files'}))
            helper = root / 'nats.go'
            helper.write_text(r'''package main
import("fmt";"os";"github.com/nats-io/nats-server/v2/server";"github.com/nats-io/nats.go")
func main(){s,e:=server.NewServer(&server.Options{Host:"127.0.0.1",Port:-1,Authorization:"qualification-only",JetStream:true,StoreDir:os.Args[1]});if e!=nil{panic(e)};s.Start();defer s.Shutdown();if !s.ReadyForConnections(5000000000){panic("not ready")};c,e:=nats.Connect(s.ClientURL(),nats.Token("qualification-only"));if e!=nil{panic(e)};defer c.Close();j,e:=c.JetStream();if e!=nil{panic(e)};k,e:=j.CreateKeyValue(&nats.KeyValueConfig{Bucket:"terrabase-homes",History:5});if e!=nil{panic(e)};for _,key:=range []string{"home.00000000000000000000000003","home.00000000000000000000000004"}{if _,e=k.Put(key,[]byte("fixture"));e!=nil{panic(e)}};fmt.Println(s.Addr().(*net.TCPAddr).Port);var b [1]byte;os.Stdin.Read(b[:])}
'''.replace('"os";', '"os";"net";'))
            server = subprocess.Popen(['mise', 'exec', '--', 'go', 'run', str(helper), str(root / 'jetstream')],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            try:
                import selectors
                selector = selectors.DefaultSelector(); selector.register(server.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(60), 'dev NATS did not start within 60s')
                port = int(server.stdout.readline())
                wire = cold.Nats('qualification-only', port)
                try:
                    approved = {k: {'revision': (m := wire.read(k))['seq'],
                                   'sha256': hashlib.sha256(base64.b64decode(m['data'])).hexdigest()} for k in cold.KEYS}
                    cold.delete_keys(wire, approved, False)
                    with contextlib.redirect_stdout(io.StringIO()):
                        actual = cold.delete_keys(wire, approved, True)
                    self.assertTrue(all(x['deleted'] for x in actual.values()))
                finally:
                    wire.r.close(); wire.s.close()
            finally:
                server.communicate(b'x', timeout=10)
                self.assertEqual(server.returncode, 0)
            client = MemoryKv(); approved = client.approved()
            cold.delete_keys(client, approved, False); self.assertEqual(client.writes, 0)
            with contextlib.redirect_stdout(io.StringIO()):
                result = cold.delete_keys(client, approved, True)
            self.assertTrue(all(x['deleted'] for x in result.values()))
            schema = {'table': '', 'after': 0, 'last': 0, 'rows': 4, 'bytes': 10, 'hash': 'schema'}
            pages = [{'revision': 'ts1:x:7:8'}, {'revision': 'ts1:x:7:8', 'moved': False,
                     'ranges': [schema, {'table': 'data', 'rows': 256}], 'next': {'table': 'data', 'after': 256}},
                     {'revision': 'ts1:x:7:8', 'moved': False, 'ranges': [schema, {'table': 'data', 'rows': 20}], 'next': None}]
            def get(path):
                if len(pages) == 1:
                    self.assertIn('after=256', path)
                return pages.pop(0)
            hashes = cold.checksum_database(get, '/checksums')
            self.assertEqual(hashes['counts'], {'data': 276})
            self.assertEqual(len(hashes['ranges']), 3)
            form = root / 'notice.json'; form.write_text(json.dumps({'title': 'Cold maintenance', 'message': 'Announced outage; next update in five minutes.',
                'scheduledStart': '2026-11-07T00:00:00Z', 'scheduledEnd': '2026-11-07T00:15:00Z', 'components': ['01' * 13]}))
            self.assertEqual(notice.fields(form)['kind'], 'maintenance')
            parser = notice.Csrf(); parser.feed('<input name="csrf" value="fixture-token">'); self.assertEqual(parser.value, 'fixture-token')
        # Real nft parser and apply/undo inside a disposable network namespace.
        script = Path(cold.__file__).resolve()
        code = '''import importlib.util,sys,json
s=importlib.util.spec_from_file_location('cold',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
from types import SimpleNamespace
m.gate(SimpleNamespace(action='close',operator='192.0.2.7'))
x=json.loads(m.command(['nft','-j','list','table','inet',m.TABLE]));assert x['nftables']
m.gate(SimpleNamespace(action='open',operator='192.0.2.7'))
'''
        subprocess.run(['sudo', '-n', 'unshare', '-n', sys.executable, '-c', code, str(script)], check=True, timeout=15)
        # Actual TERM-ignoring process exercises KILL escalation and pidfd identity.
        code = '''import importlib.util,sys,subprocess,time,json,tempfile,pathlib,os
s=importlib.util.spec_from_file_location('cold',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
from types import SimpleNamespace
p=subprocess.Popen([sys.executable,'-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready",flush=True);time.sleep(90)'],stdout=subprocess.PIPE)
assert p.stdout.readline()==b'ready\\n'
with tempfile.TemporaryDirectory() as d:
 f=pathlib.Path(d)/'identity';f.write_text(json.dumps(m.identity(p.pid)));f.chmod(0o600)
 t=time.monotonic();m.stop(SimpleNamespace(identity=str(f),receipt=d+'/exit.json'));elapsed=time.monotonic()-t
 assert 20<=elapsed<26;assert p.wait(timeout=1)==-9;print('PHYSICAL_EXIT',elapsed)
'''
        subprocess.run(['sudo', '-n', sys.executable, '-c', code, str(script)], check=True, timeout=30)

    def test_critical_changes_refuse_destructive_steps(self):
        client = MemoryKv(); approved = client.approved(); approved[cold.KEYS[1]]['revision'] += 1
        with self.assertRaises(RuntimeError): cold.delete_keys(client, approved, True)
        self.assertEqual(client.writes, 0)
        client = MemoryKv(); approved = client.approved(); client.race = True
        with self.assertRaises(RuntimeError): cold.delete_keys(client, approved, True)
        self.assertEqual(client.writes, 1); self.assertTrue(all('hdrs' not in x for x in client.data.values()))
        with self.assertRaises(ValueError): cold.gate_rules('0.0.0.0/0')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'escape').symlink_to('/etc')
            with self.assertRaises(RuntimeError): cold.inventory([d], __import__('time').monotonic() + 1)
        with patch.object(cold, 'command', return_value=json.dumps({'nftables': [{'table': {'comment': 'someone-else'}}]}).encode()), patch.object(cold.os, 'geteuid', return_value=0):
            with self.assertRaises(RuntimeError): cold.gate(SimpleNamespace(action='open', operator='192.0.2.1'))
        responses = [{'revision': 'r1'}, {'revision': 'r2', 'moved': True, 'ranges': [], 'next': None}]
        with self.assertRaises(RuntimeError): cold.checksum_database(lambda path: responses.pop(0), '/checksums')
        # An unsafe restart label in any namespace, even an unrelated container,
        # fails the all-runtime barrier before containerd can be stopped.
        replies = [b'namespace\n', b'container\n', b'{"Labels":{"containerd.io/restart.policy":"always"}}']
        with patch.object(cold, 'command', side_effect=replies):
            with self.assertRaises(RuntimeError): cold.runtime_labels(SimpleNamespace(receipt='/unused'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
