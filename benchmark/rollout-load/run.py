#!/usr/bin/env python3
"""Fixed-rate regional rollout probe. Credentials enter only through a private file."""
import argparse
import base64
import concurrent.futures
import http.client
import hashlib
import json
import math
import queue
import secrets
import signal
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
    connections = {region: queue.Queue(maxsize=4) for region in REGIONS}
    for region, pool in connections.items():
        for _ in range(4):
            pool.put(http.client.HTTPSConnection(region + '.api.terrascale.tech', timeout=40))
    samples = []
    admission = threading.BoundedSemaphore(96)
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
        conn = connections[region].get()
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
            raise
        finally:
            connections[region].put(conn)

    base = '/v1/projects/' + config['project'] + '/databases'
    database = None
    stopping = threading.Event()
    stop_offers = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop_offers.set())
    signal.signal(signal.SIGINT, lambda *_: stop_offers.set())

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
        lag = (time.monotonic() - scheduled) * 1000
        row_id = new_id() if kind == 'write' else None
        statement = ("INSERT INTO rollout_rows (id, region, sequence) VALUES ('" + row_id + "', '" + region + "', " + str(number) + ")"
                     if kind == 'write' else 'SELECT COUNT(*) FROM rollout_rows')
        result = {'kind': kind, 'region': region, 'sequence': number, 'row_id': row_id, 'started_at': started,
                  'offered_at': started - lag / 1000, 'schedule_lag_ms': round(lag, 3)}
        try:
            status, headers, body = sql(region, statement)
            if status != 200 and isinstance(body, dict):
                result['error_code'] = body.get('code')
                if not result['error_code'] and isinstance(body.get('error'), dict):
                    result['error_code'] = body['error'].get('code')
            result.update(status=status, headers=headers, ok=status == 200)
        except Exception as error:
            result.update(status=0, ok=False, error=type(error).__name__)
        result.update(completed_at=time.time(), request_ms=round((time.time() - started) * 1000, 3),
                      ms=round((time.monotonic() - scheduled) * 1000, 3))
        with output_lock:
            samples.append(result)
        emit(result)
        admission.release()

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
        # Warm every bounded regional connection before measured arrivals. Pool
        # waiting remains inside offered latency; requests never retry on failure.
        for region in REGIONS:
            for _ in range(4):
                if sql(region, 'SELECT COUNT(*) FROM rollout_rows')[0] != 200:
                    raise RuntimeError('connection warmup failed')
        start = time.monotonic()
        emit({'kind': 'load_start', 'at': time.time(), 'seconds': args.seconds, 'writes_per_second_per_region': 5,
              'reads_per_second_per_region': 5, 'retries': 0})
        with concurrent.futures.ThreadPoolExecutor(max_workers=96) as pool:
            for number in range(args.seconds * 5):
                if stop_offers.is_set():
                    break
                scheduled = start + number / 5
                stopping.wait(max(0, scheduled - time.monotonic()))
                for region in REGIONS:
                    for kind in ('write', 'read'):
                        if admission.acquire(blocking=False):
                            pool.submit(sample, region, kind, number, scheduled)
                        else:
                            missed = {'kind': kind, 'region': region, 'sequence': number,
                                      'started_at': time.time(), 'completed_at': time.time(),
                                      'offered_at': time.time() - (time.monotonic() - scheduled),
                                      'status': 0, 'ok': False, 'error': 'offered_arrival_missed',
                                      'ms': 0, 'schedule_lag_ms': round((time.monotonic() - scheduled) * 1000, 3)}
                            with output_lock:
                                samples.append(missed)
                            emit(missed)
        expected = {region: sum(row['ok'] and row['kind'] == 'write' and row['region'] == region for row in samples)
                    for region in REGIONS}
        acknowledged = {row['row_id']: (row['region'], row['sequence'])
                        for row in samples if row['ok'] and row['kind'] == 'write'}
        for region in REGIONS:
            deadline = time.monotonic() + 30
            while True:
                try:
                    actual = {}
                    after = ''
                    while True:
                        status, _, body = sql(region, "SELECT id, region, sequence FROM rollout_rows WHERE id > '" + after
                                              + "' ORDER BY id LIMIT 500")
                        if status != 200:
                            break
                        page = body['results'][0]['rows']
                        actual.update({row[0]: (row[1], row[2]) for row in page})
                        if len(page) < 500:
                            break
                        after = page[-1][0]
                        if len(actual) > len(samples):
                            raise RuntimeError('inventory exceeds offered load')
                    missing = sorted(acknowledged.keys() - actual.keys())
                    unexpected = sorted(actual.keys() - acknowledged.keys())
                    changed = sum(actual.get(key) != value for key, value in acknowledged.items())
                    exact = status == 200 and actual == acknowledged
                    emit({'kind': 'inventory', 'region': region, 'at': time.time(), 'status': status,
                          'rows': len(actual), 'expected_acked': expected, 'missing': missing[:10],
                          'missing_count': len(missing), 'unexpected_count': len(unexpected), 'changed_count': changed,
                          'id_sha256': hashlib.sha256('\n'.join(sorted(actual)).encode()).hexdigest(), 'exact': exact})
                    if exact or time.monotonic() >= deadline:
                        break
                except Exception as error:
                    emit({'kind': 'inventory', 'region': region, 'at': time.time(), 'status': 0,
                          'error': type(error).__name__, 'exact': False})
                    if time.monotonic() >= deadline:
                        break
                stopping.wait(1)
        for region in REGIONS:
            for kind in ('write', 'read'):
                cell = [sample for sample in samples if sample['region'] == region and sample['kind'] == kind]
                times = sorted(sample['ms'] for sample in cell)
                if not times:
                    continue
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
        for pool in connections.values():
            while not pool.empty():
                pool.get().close()
        output.close()


if __name__ == '__main__':
    main()
