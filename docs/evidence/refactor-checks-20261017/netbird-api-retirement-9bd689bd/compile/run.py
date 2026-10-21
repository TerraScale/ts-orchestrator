import fcntl, hashlib, json, os, pathlib, resource, subprocess, time
OUT=pathlib.Path(__file__).parent
REQUEST=OUT/'request.json'
def sha(data):return hashlib.sha256(data).hexdigest()
def write(name,value):
    with (OUT/name).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
assert sha(REQUEST.read_bytes())=='a6de5057dc7aec9a1bf999e032c53e91d6eab3c6da54e15a19914ac9283edcbc'
m=json.loads(REQUEST.read_text());w=pathlib.Path(m['worktree']);binary=pathlib.Path(m['request']['output_binary'])
assert not binary.exists()
def git(*a):return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(w),*a])
def snapshot():return {'head':git('rev-parse','HEAD').decode().strip(),'tree':git('rev-parse','HEAD^{tree}').decode().strip(),'status':git('status','--porcelain').decode(),'source_sha256':sha((w/m['source_path']).read_bytes()),'replacement_sha256':sha((w/m['replacement_path']).read_bytes()),'go_sha256':sha(pathlib.Path('/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/go').read_bytes()),'request_sha256':sha(REQUEST.read_bytes())}
pre=snapshot();assert pre['head']==m['commit'] and pre['tree']==m['tree'] and not pre['status'];assert pre['source_sha256']==m['source_sha256'] and pre['replacement_sha256']==m['replacement_sha256'] and pre['go_sha256']==m['go_binary_sha256']
write('preflight.json',{'source':pre,'argv':m['request']['argv'],'cwd':str(w),'environment':{'HOME':'/home/mariogk','PATH':'/home/mariogk/.local/share/mise/installs/go/1.27.1/bin:/run/current-system/sw/bin','GOMAXPROCS':'2','GOFLAGS':'-p=2','GOTOOLCHAIN':'local','LANG':'C.UTF-8'},'GOROOT_present':False,'compile_only':True,'binary_execution_count':0})
with open('/tmp/ts-orch-refactor-gate-check.lock','a') as gate:
    try:fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED'});raise SystemExit(75)
    start=time.monotonic()
    with (OUT/'compile.stdout').open('xb') as stdout,(OUT/'compile.stderr').open('xb') as stderr:
        proc=subprocess.Popen(m['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True)
        write('started.json',{'pid':proc.pid,'argv':m['request']['argv'],'epoch':time.time()})
        print(json.dumps({'state':'STARTED_COMPILE_ONLY','pid':proc.pid,'output':str(OUT)}),flush=True)
        rc=proc.wait()
    elapsed=time.monotonic()-start;post=snapshot()
    executable={}
    if binary.is_file():
        binary.chmod(0o600)
        wire=binary.read_bytes();executable={'path':str(binary),'sha256':sha(wire),'bytes':len(wire),'magic_hex':wire[:4].hex(),'mode':oct(binary.stat().st_mode&0o777),'never_executed':True}
    success=rc==0 and pre==post and executable.get('magic_hex')=='7f454c46'
    receipt={'state':'COMPILE_PASS' if success else 'NOT_QUALIFIED','exit_code':rc,'wall_seconds':elapsed,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'binary':executable,'binary_execution_count':0,'stdout_sha256':sha((OUT/'compile.stdout').read_bytes()),'stderr_sha256':sha((OUT/'compile.stderr').read_bytes()),'scope':'one true go test -c compile/link only; binary never executed; no runtime rerun or canonical adoption claim'}
    write('receipt.json',receipt)
    print(json.dumps(receipt),flush=True)
    fcntl.flock(gate,fcntl.LOCK_UN)
raise SystemExit(0 if success else 1)
