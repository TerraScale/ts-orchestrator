import fcntl, hashlib, json, pathlib, resource, subprocess, sys, time
OUT = pathlib.Path(__file__).resolve().parent
REQUEST = OUT / 'request.json'
EXPECTED_REQUEST_SHA = 'db2786b475cb32e786a8c1aa61c8712668647441cbce2c235cfeb33a1e1cb0f3'
def sha(data): return hashlib.sha256(data).hexdigest()
def write(name, value):
    with (RUN / name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
def git(w, *args):
    return subprocess.check_output(['/run/current-system/sw/bin/git', '-C', str(w), *args])
# Directory creation is an exclusive one-shot guard, including failed preflight/lock attempts.
RUN = OUT / 'qa-output'
RUN.mkdir(mode=0o700)
raw = REQUEST.read_bytes()
assert sha(raw) == EXPECTED_REQUEST_SHA
request = json.loads(raw)
w = pathlib.Path(request['worktree'])
assert request['request']['cwd'] == str(w)
assert request['state'] == 'SOURCE_ONLY_NOT_COMPILED_OR_RUN_NO_LEASE'
assert request['request']['attempts'] == 1
assert request['request']['lease_required'] is True
manifest_raw = (OUT / 'SHA256SUMS').read_bytes()
assets = {}
for line in manifest_raw.decode().splitlines():
    digest, name = line.split('  ', 1)
    assert pathlib.PurePath(name).name == name and name not in assets
    assets[name] = digest
assert assets['run.py'] == sha(pathlib.Path(__file__).read_bytes())
assert assets['request.json'] == EXPECTED_REQUEST_SHA
assert request['sourceproof_sha256'] == assets['SOURCEPROOF.json']
def snapshot():
    return {
        'head': git(w,'rev-parse','HEAD').decode().strip(),
        'tree': git(w,'rev-parse','HEAD^{tree}').decode().strip(),
        'status': git(w,'status','--porcelain=v1','--untracked-files=all').decode(),
        'source_sha256': sha((w / request['owned_changed_paths'][0]).read_bytes()),
        'base_original_sha256': sha(git(w,'show',request['base']+':'+request['owned_changed_paths'][0])),
        'go_sha256': sha(pathlib.Path(request['go_binary']).read_bytes()),
        'python_sha256': sha(pathlib.Path(request['python_binary']).read_bytes()),
        'executing_python_sha256': sha(pathlib.Path(sys.executable).resolve().read_bytes()),
        'runner_sha256': sha(pathlib.Path(__file__).read_bytes()),
        'request_sha256': sha(REQUEST.read_bytes()),
        'sealed_manifest_sha256': sha((OUT / 'SHA256SUMS').read_bytes()),
        'sealed_asset_sha256': {name:sha((OUT/name).read_bytes()) for name in assets}
    }
pre = snapshot()
assert pre['head'] == request['commit'] and pre['tree'] == request['tree'] and not pre['status']
assert pre['source_sha256'] == request['source_file_sha256']
assert pre['base_original_sha256'] == request['retained_original_file_sha256']
assert pre['go_sha256'] == request['go_binary_sha256']
assert pre['python_sha256'] == pre['executing_python_sha256'] == request['python_binary_sha256']
assert pre['request_sha256'] == EXPECTED_REQUEST_SHA
assert pre['sealed_asset_sha256'] == assets
assert pre['sealed_manifest_sha256'] == sha(manifest_raw)
write('preflight.json', {'source':pre,'argv':request['request']['argv'],'cwd':str(w),'effective_child_environment':request['request']['effective_child_environment'],'GOROOT_present':False})
with open(request['request']['shared_lock'],'a') as gate:
    try:
        fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','source':pre})
        raise SystemExit(75)
    started = time.time()
    clock = time.monotonic()
    with (RUN/'stdout.jsonl').open('xb') as stdout, (RUN/'stderr.log').open('xb') as stderr:
        proc = subprocess.Popen(request['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True)
        write('started.json',{'pid':proc.pid,'epoch':started,'argv':request['request']['argv']})
        print(json.dumps({'state':'STARTED','pid':proc.pid,'output':str(RUN)}),flush=True)
        returncode = proc.wait()
    elapsed = time.monotonic()-clock
    post = snapshot()
    actions, packages, malformed = [], [], []
    for index,line in enumerate((RUN/'stdout.jsonl').read_text().splitlines(),1):
        try:
            event = json.loads(line)
            assert isinstance(event,dict)
        except (json.JSONDecodeError,AssertionError):
            malformed.append(index)
            continue
        if event.get('Action') in ['pass','fail','skip']:
            if event.get('Test'):
                actions.append({key:event[key] for key in ['Package','Test','Action','Elapsed'] if key in event})
            else:
                packages.append(event)
    expected = request['expected_pass_tests']
    success = (returncode == 0 and not malformed and len(actions) == len(expected)
        and sorted(e['Test'] for e in actions) == sorted(expected)
        and all(e['Action'] == 'pass' and e.get('Package') == request['expected_pass_package'] for e in actions)
        and len(packages) == 1 and packages[0]['Action'] == 'pass'
        and packages[0].get('Package') == request['expected_pass_package'] and pre == post)
    receipt = {'state':'PASS' if success else 'NOT_QUALIFIED','exit_code':returncode,'wall_seconds':elapsed,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'expected_tests':expected,'test_outcomes':actions,'package_outcomes':packages,'malformed_json_line_numbers':malformed,'stdout_sha256':sha((RUN/'stdout.jsonl').read_bytes()),'stderr_sha256':sha((RUN/'stderr.log').read_bytes()),'scope':'One standard new-root attempt only; zero child leaves; no original retirement, race or global closure.'}
    write('receipt.json',receipt)
    with (RUN/'SHA256SUMS').open('x') as f:
        for path in sorted(RUN.iterdir()):
            if path.name != 'SHA256SUMS':
                f.write(sha(path.read_bytes())+'  '+path.name+'\n')
    print(json.dumps(receipt),flush=True)
    fcntl.flock(gate,fcntl.LOCK_UN)
raise SystemExit(0 if success else 1)
