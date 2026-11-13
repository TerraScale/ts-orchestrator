#!/usr/bin/env python3
"""Regional canary: write one unique row through each region, read all through each.
Usage: canary.py KEYFILE STATEFILE [setup|probe]. Credentials never printed."""
import base64
import http.client
import json
import secrets
import sys
import time
import urllib.parse

with open(sys.argv[1]) as key_file:
    KEY = key_file.read().strip()
STATE = sys.argv[2]
MODE = sys.argv[3] if len(sys.argv) > 3 else 'probe'
REGIONS = ('gru', 'sjc', 'fra')


def token():
    c = http.client.HTTPSConnection('auth.terrascale.tech', timeout=15)
    c.request('POST', '/terrascale/oauth/token', urllib.parse.urlencode({'grant_type': 'client_credentials'}),
              {'Authorization': 'Basic ' + base64.b64encode((KEY.removeprefix('sk_')[:26] + ':' + KEY).encode()).decode(),
               'Content-Type': 'application/x-www-form-urlencoded'})
    r = c.getresponse(); d = json.loads(r.read())
    if r.status != 200:
        raise SystemExit(f'token HTTP {r.status}')
    return d['access_token'], d


def req(tok, region, method, path, body=None):
    c = http.client.HTTPSConnection(region + '.api.terrascale.tech', timeout=20)
    c.request(method, path, None if body is None else json.dumps(body),
              {'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json', 'X-TerraScale-Region-Pin': region})
    r = c.getresponse(); data = r.read()
    try:
        return r.status, json.loads(data) if data else None
    except ValueError:
        return r.status, {'raw': data[:200].decode(errors='replace')}


tok, meta = token()
out = {'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'token': 'issued', 'tokenFields': sorted(k for k in meta if k != 'access_token')}
if MODE == 'setup':
    payload = tok.split('.')[1]; payload += '=' * (-len(payload) % 4)
    project = json.loads(base64.urlsafe_b64decode(payload))['project_id']
    base = f'/v1/projects/{project}/databases'
    s, db = req(tok, 'gru', 'POST', base, {'name': 'zdt-canary-' + secrets.token_hex(4), 'homeRegion': 'gru', 'replicaRegions': ['sjc', 'fra']})
    if s != 201:
        raise SystemExit(f'database create HTTP {s} {json.dumps(db)[:200]}')
    database = db['id']
    s, b = req(tok, 'gru', 'POST', f'{base}/{database}/sql/execute', {'statements': [{'sql': 'CREATE TABLE canary (id TEXT PRIMARY KEY, region TEXT, at TEXT)'}]})
    if s != 200:
        raise SystemExit(f'schema HTTP {s} {json.dumps(b)[:200]}')
    with open(STATE, 'w') as state_file:
        json.dump({'project': project, 'database': database}, state_file)
    out.update(project=project, database=database)
with open(STATE) as state_file:
    st = json.load(state_file)
base = f"/v1/projects/{st['project']}/databases/{st['database']}/sql/execute"
ids = {}
for region in REGIONS:
    rid = f'{region}-{secrets.token_hex(6)}'
    ok = False
    for attempt in range(20):
        s, b = req(tok, region, 'POST', base, {'statements': [{'sql': f"INSERT INTO canary (id, region, at) VALUES ('{rid}', '{region}', '{out['at']}')"}]})
        if s == 200:
            ok = True; break
        time.sleep(1)
    out['write_' + region] = s
    if not ok:
        raise SystemExit(json.dumps(out) + f' write failed {region}: {json.dumps(b)[:200]}')
    ids[region] = rid
reads = {}
for reader in REGIONS:
    for attempt in range(30):
        s, b = req(tok, reader, 'POST', base, {'statements': [{'sql': "SELECT id FROM canary WHERE id IN (" + ','.join(f"'{v}'" for v in ids.values()) + ")"}]})
        seen = json.dumps(b)
        if s == 200 and all(v in seen for v in ids.values()):
            reads[reader] = 'all3'; break
        time.sleep(1)
    else:
        reads[reader] = f'HTTP {s} missing'
out.update(ids=ids, reads=reads, ok=all(v == 'all3' for v in reads.values()))
print(json.dumps(out))
sys.exit(0 if out['ok'] else 1)
