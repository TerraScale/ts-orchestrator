#!/usr/bin/env python3
"""Fixed-rate regional rollout probe. Credentials enter only through a private file."""
import argparse
import base64
import concurrent.futures
import http.client
import json
import math
import secrets
import threading
import time
import urllib.parse
from pathlib import Path


REGIONS = ('gru', 'sjc', 'fra')
ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'


def new_id():
    value = (int(time.time() * 1000) << 80) | secrets.randbits(80)
    return ''.join(ALPHABET[(value >> shift) & 31] for shift in range(125, -1, -5))


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=300)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    token = {'value': '', 'until': 0}
    token_lock = threading.Lock()
    output_lock = threading.Lock()
    local = threading.local()
    samples = []
    output = args.output.open('w')

    def emit(value):
        with output_lock:
            output.write(json.dumps(value) + '\n')
            output.flush()

    def renew():
        key = config['key']
        conn = http.client.HTTPSConnection('auth.terrascale.tech', timeout=15)
        try:
            conn.request('POST', '/terrascale/oauth/token',
                         urllib.parse.urlencode({'grant_type': 'client_credentials'}),
                         {'Authorization': 'Basic ' + base64.b64encode((key[:26] + ':' + key).encode()).decode(),
                          'Content-Type': 'application/x-www-form-urlencoded'})
            response = conn.getresponse()
            data = json.loads(response.read())
            if response.status != 200:
                raise RuntimeError('token exchange HTTP ' + str(response.status))
            with token_lock:
                token.update(value=data['access_token'], until=time.monotonic() + int(data['expires_in']))
        finally:
            conn.close()

    def request(region, method, path, body=None):
        if not hasattr(local, 'connections'):
            local.connections = {}
        conn = local.connections.setdefault(region, http.client.HTTPSConnection(region + '.api.terrascale.tech', timeout=40))
        with token_lock:
            bearer = token['value']
        try:
            conn.request(method, path, None if body is None else json.dumps(body),
                         {'Authorization': 'Bearer ' + bearer, 'Content-Type': 'application/json',
                          'X-TerraScale-Region-Pin': region})
            response = conn.getresponse()
            data = response.read()
            headers = {key.lower(): value for key, value in response.getheaders()
                       if key.lower().startswith(('x-terrabase', 'terrascale-', 'server-timing', 'x-request-id'))}
            return response.status, headers, json.loads(data) if data else None
        except Exception:
            conn.close()
            local.connections.pop(region, None)
            raise

    base = '/v1/projects/' + config['project'] + '/databases'
    database = None
    stopping = threading.Event()

    def renew_background():
        while not stopping.wait(40):
            try:
                renew()
            except Exception as error:
                emit({'kind': 'token_error', 'type': type(error).__name__, 'at': time.time()})

    def sql(region, statement):
        return request(region, 'POST', base + '/' + database + '/sql/execute', {'statements': [{'sql': statement}]})

    def sample(region, kind, number, scheduled):
        started = time.time()
        statement = ("INSERT INTO rollout_rows (id, region, sequence) VALUES ('" + new_id() + "', '" + region + "', " + str(number) + ")"
                     if kind == 'write' else 'SELECT COUNT(*) FROM rollout_rows')
        result = {'kind': kind, 'region': region, 'sequence': number, 'started_at': started,
                  'schedule_lag_ms': round((time.monotonic() - scheduled) * 1000, 3)}
        try:
            status, headers, _ = sql(region, statement)
            result.update(status=status, headers=headers, ok=status == 200)
        except Exception as error:
            result.update(status=0, ok=False, error=type(error).__name__)
        result.update(completed_at=time.time(), ms=round((time.time() - started) * 1000, 3))
        with output_lock:
            samples.append(result)
        emit(result)

    renew()
    renewal = threading.Thread(target=renew_background, daemon=True)
    renewal.start()
    try:
        status, _, body = request('gru', 'POST', base, {'name': 'rollout-' + new_id().lower(),
                                                     'homeRegion': 'gru', 'replicaRegions': ['sjc', 'fra']})
        if status != 201:
            raise RuntimeError('database create HTTP ' + str(status))
        database = body['id']
        emit({'kind': 'database', 'id': database, 'at': time.time()})
        if sql('gru', 'CREATE TABLE rollout_rows (id TEXT PRIMARY KEY, region TEXT, sequence INTEGER)')[0] != 200:
            raise RuntimeError('schema create failed')
        for region in REGIONS:
            for attempt in range(60):
                if sql(region, 'SELECT COUNT(*) FROM rollout_rows')[0] == 200:
                    break
                if attempt == 59:
                    raise RuntimeError('regional warmup failed')
                stopping.wait(1)
        start = time.monotonic()
        emit({'kind': 'load_start', 'at': time.time(), 'seconds': args.seconds, 'writes_per_second_per_region': 5,
              'reads_per_second_per_region': 5, 'retries': 0})
        with concurrent.futures.ThreadPoolExecutor(max_workers=96) as pool:
            for number in range(args.seconds * 5):
                scheduled = start + number / 5
                stopping.wait(max(0, scheduled - time.monotonic()))
                for region in REGIONS:
                    for kind in ('write', 'read'):
                        pool.submit(sample, region, kind, number, scheduled)
        for region in REGIONS:
            status, _, body = sql(region, 'SELECT region, COUNT(*) FROM rollout_rows GROUP BY region')
            emit({'kind': 'inventory', 'region': region, 'status': status, 'body': body})
        for region in REGIONS:
            for kind in ('write', 'read'):
                cell = [sample for sample in samples if sample['region'] == region and sample['kind'] == kind]
                times = sorted(sample['ms'] for sample in cell)
                emit({'kind': 'summary', 'region': region, 'operation': kind, 'requests': len(cell),
                      'failed': sum(not sample['ok'] for sample in cell),
                      'p99_ms': times[math.ceil(len(times) * .99) - 1], 'max_ms': times[-1]})
    finally:
        if database:
            try:
                status, _, _ = request('gru', 'DELETE', base + '/' + database)
                emit({'kind': 'cleanup', 'status': status})
            except Exception as error:
                emit({'kind': 'cleanup', 'error': type(error).__name__})
        stopping.set()
        renewal.join(timeout=16)
        output.close()


if __name__ == '__main__':
    main()
