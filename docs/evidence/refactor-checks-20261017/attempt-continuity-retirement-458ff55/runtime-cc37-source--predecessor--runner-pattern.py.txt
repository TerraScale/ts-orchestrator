import fcntl, hashlib, json, os, pathlib, resource, subprocess, time
OUT = pathlib.Path(__file__).parent
REQUEST = pathlib.Path('/tmp/ts-netbird-api-boundary-44fccacf-source-c5y_75hp/request.json')
EXPECTED_REQUEST_SHA = '40655dbc31cea9a9d90ee11117042194de0b5371ba31d5614121227c766beb28'
def sha(data): return hashlib.sha256(data).hexdigest()
def write(name, value):
    with (OUT / name).open('x') as f: json.dump(value, f, indent=2); f.write('\n')
def git(w, *args): return subprocess.check_output(['/run/current-system/sw/bin/git', '-C', str(w), *args])
raw = REQUEST.read_bytes()
assert sha(raw) == EXPECTED_REQUEST_SHA
request = json.loads(raw)
w = pathlib.Path(request['worktree'])
def snapshot():
    return {'head': git(w,'rev-parse','HEAD').decode().strip(), 'tree': git(w,'rev-parse','HEAD^{tree}').decode().strip(), 'status':git(w,'status','--porcelain').decode(), 'source_sha256':sha((w / request['owned_changed_paths'][0]).read_bytes()), 'original_sha256':sha((w / 'internal/netbird/manager/manager_test.go').read_bytes()), 'go_sha256':sha(pathlib.Path('/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/go').read_bytes()), 'request_sha256':sha(REQUEST.read_bytes())}
pre = snapshot()
assert pre['head'] == request['commit'] and pre['tree'] == request['tree'] and not pre['status']
assert pre['source_sha256'] == request['source_file_sha256'] and pre['original_sha256'] == request['retained_original_file_sha256'] and pre['go_sha256'] == request['go_binary_sha256']
write('preflight.json', {'source':pre, 'argv':request['request']['argv'], 'cwd':str(w), 'effective_child_environment':{'HOME':'/home/mariogk','PATH':'/home/mariogk/.local/share/mise/installs/go/1.27.1/bin:/run/current-system/sw/bin','GOMAXPROCS':'2','GOFLAGS':'-p=2','GOTOOLCHAIN':'local','LANG':'C.UTF-8'}, 'GOROOT_present':False, 'python_sha256':sha(pathlib.Path('/home/mariogk/.local/share/mise/installs/python/3.15.0/bin/python3.15').read_bytes())})
with open('/tmp/ts-orch-refactor-gate-check.lock','a') as gate:
    try: fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','source':pre}); raise SystemExit(75)
    started = time.time(); clock = time.monotonic()
    with (OUT/'stdout.jsonl').open('xb') as stdout, (OUT/'stderr.log').open('xb') as stderr:
        proc = subprocess.Popen(request['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True)
        write('started.json',{'pid':proc.pid,'epoch':started,'argv':request['request']['argv']})
        print(json.dumps({'state':'STARTED','pid':proc.pid,'output':str(OUT)}),flush=True)
        returncode = proc.wait()
    elapsed = time.monotonic()-clock
    post = snapshot()
    actions=[]; parsed=[]
    for line in (OUT/'stdout.jsonl').read_text().splitlines():
        try: event=json.loads(line)
        except json.JSONDecodeError: continue
        if event.get('Test') and event.get('Action') in ['pass','fail','skip']:
            actions.append({key:event[key] for key in ['Test','Action','Elapsed'] if key in event})
        if event.get('Action') in ['pass','fail','skip'] and not event.get('Test'): parsed.append(event)
    passed={e['Test'] for e in actions if e['Action']=='pass'}
    success=returncode==0 and passed==set(request['expected_pass_tests']) and all(e['Action']=='pass' for e in actions) and pre==post
    receipt={'state':'PASS' if success else 'NOT_QUALIFIED','exit_code':returncode,'wall_seconds':elapsed,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'expected_tests':request['expected_pass_tests'],'test_outcomes':actions,'package_outcomes':parsed,'stdout_sha256':sha((OUT/'stdout.jsonl').read_bytes()),'stderr_sha256':sha((OUT/'stderr.log').read_bytes()),'scope':'one standard new-root attempt only; no original retirement/race/global closure'}
    write('receipt.json',receipt)
    with (OUT/'SHA256SUMS').open('x') as f:
        for path in sorted(OUT.iterdir()):
            if path.name!='SHA256SUMS': f.write(sha(path.read_bytes())+'  '+path.name+'\n')
    print(json.dumps(receipt),flush=True)
    fcntl.flock(gate,fcntl.LOCK_UN)
raise SystemExit(0 if success else 1)
