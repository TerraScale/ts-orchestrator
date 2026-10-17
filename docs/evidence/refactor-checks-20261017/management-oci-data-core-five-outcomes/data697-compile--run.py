import fcntl, hashlib, json, os, pathlib, resource, stat, subprocess, sys, time
P = pathlib.Path(__file__).resolve().parent
EXPECTED_ef4446637d248f10560ae4698cf243e529fc8eff6eaba5138ef3276f434ac4fb = "ef4446637d248f10560ae4698cf243e529fc8eff6eaba5138ef3276f434ac4fb"
def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
assert sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1 and sys.flags.optimize == 0
assert sha(P/'request.json') == EXPECTED_ef4446637d248f10560ae4698cf243e529fc8eff6eaba5138ef3276f434ac4fb
m = json.loads((P/'request.json').read_bytes())
assert not m.get('static_blockers'), 'HOLD: required production prerequisites absent; new coherent source/packet and explicit lease required'
os.umask(0o077)
OUT = P/'qa-output'
OUT.mkdir(mode=0o700)
assert stat.S_IMODE(OUT.stat().st_mode) == 0o700
binary = OUT/'app.test'
assert str(binary) == m['request']['output_binary'] and not os.path.lexists(binary)
assert m['request']['compile_only'] and not m['request']['binary_execution_authorized']
assert m['request']['attempts'] == 1 and m['request']['lease_required']
assert '-c' in m['request']['argv'] and '-mod=readonly' in m['request']['argv']
assert not any(x.startswith(('-run','-vet')) for x in m['request']['argv'])
assets = {}
for line in (P/'SHA256SUMS').read_text().splitlines():
 digest,name = line.split('  ',1)
 assert pathlib.PurePath(name).name == name and name not in assets
 assets[name] = digest
assert assets['request.json'] == EXPECTED_ef4446637d248f10560ae4698cf243e529fc8eff6eaba5138ef3276f434ac4fb and assets['run.py'] == sha(__file__)
full = json.loads((P/'fullsource-manifest.json').read_bytes())
inputs = json.loads((P/'source-inputs.json').read_bytes())
tools = json.loads((P/'tool-pins.json').read_bytes())
w = pathlib.Path(m['worktree'])
def git(*args): return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(w),*args]).decode().strip()
def snapshot():
 return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'parent':git('rev-parse','HEAD^'),'status':git('status','--porcelain=v1','--untracked-files=all'),'tracked':git('ls-files').splitlines(),'fullsource':{n:sha(w/n) for n in full},'inputs':{n:sha(n) for n in inputs},'tools':{n:{'sha256':sha(n),'resolved':str(pathlib.Path(n).resolve())} for n in tools},'assets':{n:sha(P/n) for n in assets},'manifest':sha(P/'SHA256SUMS'),'executing_python':sha(pathlib.Path(sys.executable).resolve())}
def write(n,v):
 with (OUT/n).open('x') as f: json.dump(v,f,indent=2,sort_keys=True); f.write('\n')
pre = snapshot()
assert pre['head'] == m['commit'] and pre['tree'] == m['tree'] and pre['parent'] == m['base'] and not pre['status']
assert set(pre['tracked']) == set(full) and pre['fullsource'] == full and pre['inputs'] == inputs and pre['tools'] == tools and pre['assets'] == assets
assert pre['executing_python'] == m['python_binary_sha256']
assert tools[m['go_binary']]['sha256'] == m['go_binary_sha256'] and tools[m['python_binary']]['sha256'] == m['python_binary_sha256']
assert all(sha(P/n) == digest for n,digest in m['pins'].items())
write('preflight.json',{'snapshot':pre,'argv':m['request']['argv'],'cwd':str(w),'env_i_six':m['request']['effective_child_environment'],'GOROOT_present':False,'compile_only':True,'default_vet':True,'binary_execution_count':0})
with open(m['request']['shared_lock'],'a') as gate:
 try: fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:
  write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','binary_execution_count':0}); raise SystemExit(75)
 assert snapshot() == pre
 start = time.monotonic()
 with (OUT/'compile.stdout').open('xb') as stdout, (OUT/'compile.stderr').open('xb') as stderr:
  proc = subprocess.Popen(m['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True)
  write('started.json',{'runner_native_pid':os.getpid(),'outer_native_pid':proc.pid,'process_group':proc.pid,'pid_scope':'native nice/timeout wrapper, not nested Go PID','argv':m['request']['argv'],'epoch':time.time(),'compile_only':True,'binary_execution_count':0})
  print(json.dumps({'state':'STARTED_COMPILE_ONLY','pid':proc.pid,'output':str(OUT)}),flush=True)
  rc = proc.wait()
 elapsed = time.monotonic()-start
 post = snapshot()
 artifact = {'path':str(binary),'exists':os.path.lexists(binary),'never_executed_by_runner':True}
 if binary.is_file() and not binary.is_symlink():
  os.chmod(binary,0o600,follow_symlinks=False)
  data = binary.read_bytes()
  artifact.update({'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'magic_hex':data[:4].hex(),'mode':oct(stat.S_IMODE(binary.stat().st_mode)),'regular_file':stat.S_ISREG(binary.stat().st_mode)})
 success = rc == 0 and pre == post and artifact.get('regular_file') and artifact.get('magic_hex') == '7f454c46' and artifact.get('bytes',0)>64 and artifact.get('mode') == '0o600'
 receipt = {'state':'COMPILE_PASS' if success else 'NOT_QUALIFIED','exit_code':rc,'wall_seconds':elapsed,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'binary':artifact,'binary_execution_count':0,'default_vet':True,'stdout_sha256':sha(OUT/'compile.stdout'),'stderr_sha256':sha(OUT/'compile.stderr'),'scope':'One true compile/link with default vet; no test binary, package init, fixture, native or cloud execution.'}
 write('receipt.json',receipt)
 with (OUT/'SHA256SUMS').open('x') as f:
  for p in sorted(OUT.iterdir()):
   if p.name!='SHA256SUMS': f.write(sha(p)+'  '+p.name+'\n')
 print(json.dumps({'state':receipt['state'],'exit_code':rc,'wall_seconds':elapsed,'receipt':str(OUT/'receipt.json')}),flush=True)
 fcntl.flock(gate,fcntl.LOCK_UN)
raise SystemExit(0 if success else 1)
