import fcntl, hashlib, json, os, pathlib, resource, stat, subprocess, sys, time
OUT = pathlib.Path(__file__).resolve().parent
REQUEST = OUT / 'request.json'
EXPECTED_REQUEST_SHA = 'ef400a47dde536883488d442cf03b6c09ab06293d51d241e8caf36340593659a'
def sha(data): return hashlib.sha256(data).hexdigest()
if not (sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1 and sys.flags.optimize == 0):
    raise SystemExit('Use the pinned Python with -I -B and no optimization.')
os.umask(0o077)
RUN = OUT / 'qa-output'
RUN.mkdir(mode=0o700)
def write(name, value):
    with (RUN / name).open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')
raw = REQUEST.read_bytes()
assert sha(raw) == EXPECTED_REQUEST_SHA
m = json.loads(raw)
w = pathlib.Path(m['worktree'])
binary = pathlib.Path(m['request']['output_binary'])
assert binary == RUN / 'ociclient.test'
assert not os.path.lexists(binary)
assert stat.S_IMODE(RUN.stat().st_mode) == 0o700
assert m['request']['compile_only'] is True and m['request']['binary_execution_authorized'] is False
assert m['request']['attempts'] == 1 and m['request']['lease_required'] is True
assert '-c' in m['request']['argv']
assert not any(arg.startswith(('-run','-vet')) for arg in m['request']['argv'])
assets = {}
for line in (OUT / 'SHA256SUMS').read_text().splitlines():
    digest, name = line.split('  ', 1)
    assert pathlib.PurePath(name).name == name and name not in assets
    assets[name] = digest
assert assets['run.py'] == sha(pathlib.Path(__file__).read_bytes())
assert assets['request.json'] == EXPECTED_REQUEST_SHA
assert assets['SOURCEPROOF.json'] == m['sourceproof_sha256']
assert assets['source-inputs.json'] == m['source_inputs_sha256']
assert assets['evidence-bindings.json'] == m['evidence_bindings_sha256']
source_inputs = json.loads((OUT / 'source-inputs.json').read_bytes())
evidence = json.loads((OUT / 'evidence-bindings.json').read_bytes())
def git(*args):
    return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(w),*args])
def snapshot():
    return {
        'head':git('rev-parse','HEAD').decode().strip(),
        'tree':git('rev-parse','HEAD^{tree}').decode().strip(),
        'parent':git('rev-parse','HEAD^').decode().strip(),
        'status':git('status','--porcelain=v1','--untracked-files=all').decode(),
        'source_sha256':sha((w / m['source_path']).read_bytes()),
        'source_and_module_inputs':{name:sha(pathlib.Path(name).read_bytes()) for name in source_inputs},
        'evidence_bindings':{name:sha(pathlib.Path(name).read_bytes()) for name in evidence},
        'go_sha256':sha(pathlib.Path(m['go_binary']).read_bytes()),
        'python_sha256':sha(pathlib.Path(m['python_binary']).read_bytes()),
        'executing_python_sha256':sha(pathlib.Path(sys.executable).resolve().read_bytes()),
        'runner_sha256':sha(pathlib.Path(__file__).read_bytes()),
        'request_sha256':sha(REQUEST.read_bytes()),
        'manifest_sha256':sha((OUT/'SHA256SUMS').read_bytes()),
        'sealed_asset_sha256':{name:sha((OUT/name).read_bytes()) for name in assets}
    }
pre = snapshot()
assert pre['head'] == m['commit'] and pre['tree'] == m['tree'] and pre['parent'] == m['base'] and not pre['status']
assert pre['source_sha256'] == m['source_sha256']
assert pre['source_and_module_inputs'] == source_inputs and pre['evidence_bindings'] == evidence
assert pre['go_sha256'] == m['go_binary_sha256']
assert pre['python_sha256'] == pre['executing_python_sha256'] == m['python_binary_sha256']
assert pre['sealed_asset_sha256'] == assets and pre['request_sha256'] == EXPECTED_REQUEST_SHA
write('preflight.json',{'source':pre,'argv':m['request']['argv'],'cwd':str(w),'environment':m['request']['effective_child_environment'],'GOROOT_present':False,'python_isolated':True,'python_no_bytecode':True,'compile_only':True,'default_vet':True,'binary_pre':{'path':str(binary),'exists':False},'binary_execution_count':0})
with open(m['request']['shared_lock'],'a') as gate:
    try:
        fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','source':pre,'binary_execution_count':0})
        raise SystemExit(75)
    # Recheck input identities under the lease lock immediately before launching.
    assert snapshot() == pre
    start = time.monotonic()
    with (RUN/'compile.stdout').open('xb') as stdout, (RUN/'compile.stderr').open('xb') as stderr:
        proc = subprocess.Popen(m['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True)
        write('started.json',{'runner_native_pid':os.getpid(),'native_child_pid':proc.pid,'process_group':proc.pid,'pid_scope':'Popen native outer nice/timeout command, not a claim about the nested Go tool PID','argv':m['request']['argv'],'epoch':time.time(),'compile_only':True,'binary_execution_count':0})
        print(json.dumps({'state':'STARTED_COMPILE_ONLY','native_pid':proc.pid,'output':str(RUN)}),flush=True)
        rc = proc.wait()
    elapsed = time.monotonic() - start
    post = snapshot()
    executable = {'path':str(binary),'exists':os.path.lexists(binary),'never_executed_by_runner':True}
    if binary.is_file() and not binary.is_symlink():
        os.chmod(binary,0o600,follow_symlinks=False)
        wire = binary.read_bytes()
        executable.update({'sha256':sha(wire),'bytes':len(wire),'magic_hex':wire[:4].hex(),'mode':oct(stat.S_IMODE(binary.stat().st_mode)),'regular_file':stat.S_ISREG(binary.stat().st_mode)})
        assert sha(binary.read_bytes()) == executable['sha256']
    success = (rc == 0 and pre == post and executable.get('regular_file') is True
        and executable.get('magic_hex') == '7f454c46' and executable.get('bytes',0) > 64
        and executable.get('mode') == '0o600' and stat.S_IMODE(RUN.stat().st_mode) == 0o700)
    receipt = {'state':'COMPILE_PASS' if success else 'NOT_QUALIFIED','exit_code':rc,'wall_seconds':elapsed,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'binary':executable,'binary_execution_count':0,'default_vet':True,'stdout_sha256':sha((RUN/'compile.stdout').read_bytes()),'stderr_sha256':sha((RUN/'compile.stderr').read_bytes()),'scope':'One true go test -c compile/link attempt; test binary never executed by runner; no runtime rerun/race/global/canonical adoption claim.'}
    write('receipt.json',receipt)
    with (RUN/'SHA256SUMS').open('x') as f:
        for path in sorted(RUN.iterdir()):
            if path.name != 'SHA256SUMS':
                f.write(sha(path.read_bytes())+'  '+path.name+'\n')
    print(json.dumps(receipt),flush=True)
    fcntl.flock(gate,fcntl.LOCK_UN)
raise SystemExit(0 if success else 1)
