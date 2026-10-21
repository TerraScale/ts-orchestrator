import fcntl,hashlib,json,pathlib,resource,subprocess,time,sys
OUT=pathlib.Path(__file__).parent
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def write(name,value):
 with (OUT/name).open('x') as f: json.dump(value,f,indent=2); f.write('\n')
m=json.loads((OUT/'request.json').read_bytes()); w=pathlib.Path(m['worktree']); output=OUT/'binaries'; launched=False
manifest=json.loads((OUT/'fullsource-manifest.json').read_bytes())
def git(*args):return subprocess.check_output([m['tools']['git']['path'],'-C',str(w),*args]).decode().strip()
def snapshot():
 assert sorted(filter(None,git('ls-files','-z').split('\0')))==sorted(x['path'] for x in manifest)
 for item in manifest: assert sha(w/item['path'])==item['sha256']
 for tool in m['tools'].values(): assert sha(tool['path'])==tool['sha256']
 return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1','--untracked-files=all'),'manifest_sha256':sha(OUT/'fullsource-manifest.json'),'request_sha256':sha(OUT/'request.json'),'wrapper_sha256':sha(__file__),'tools':m['tools']}
try:
 seal=json.loads((OUT/'final-seal.json').read_bytes())
 for a in seal['artifacts']: assert sha(OUT/a['path'])==a['sha256']
 assert sha(__file__)==m['wrapper_sha256'] and sha(OUT/'fullsource-manifest.json')==m['fullsource_manifest_sha256']
 pre=snapshot(); assert pre['head']==m['commit'] and pre['tree']==m['tree'] and not pre['status']
 assert output.is_dir() and not list(output.iterdir())
 write('preflight.json',{'source':pre,'argv':m['request']['argv'],'environment':m['environment'],'compile_only':True,'binary_execution_count':0})
 with open(m['request']['shared_lock'],'a') as gate:
  try: fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError: write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','binary_execution_count':0});sys.exit(75)
  start=time.monotonic()
  with (OUT/'compile.stdout').open('xb') as stdout,(OUT/'compile.stderr').open('xb') as stderr:
   proc=subprocess.Popen(m['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True);launched=True
   write('started.json',{'pid':proc.pid,'argv':m['request']['argv'],'epoch':time.time()})
   print(json.dumps({'state':'STARTED_COMPILE_ONLY','pid':proc.pid,'output':str(OUT)}),flush=True);rc=proc.wait()
  binaries=[]
  for p in sorted(output.iterdir()):
   p.chmod(0o600); wire=p.read_bytes(); binaries.append({'path':str(p),'sha256':sha(p),'bytes':len(wire),'magic_hex':wire[:4].hex(),'mode':oct(p.stat().st_mode&0o777),'never_executed':True})
  post=snapshot(); success=rc==0 and pre==post and {pathlib.Path(x['path']).name for x in binaries}==set(m['expected_binaries']) and all(x['magic_hex']=='7f454c46' for x in binaries)
  receipt={'state':'COMPILE_PASS' if success else 'NOT_QUALIFIED','exit_code':rc,'wall_seconds':time.monotonic()-start,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'binaries':binaries,'binary_execution_count':0,'stdout_sha256':sha(OUT/'compile.stdout'),'stderr_sha256':sha(OUT/'compile.stderr'),'scope':'true test-c compile/link only; no init/test execution, runtime proof, or canonical adoption'}
  write('receipt.json',receipt);print(json.dumps(receipt),flush=True);fcntl.flock(gate,fcntl.LOCK_UN)
 sys.exit(0 if success else 1)
except Exception as error:
 for p in output.iterdir():
  if p.is_file():p.chmod(0o600)
 if not (OUT/'receipt.json').exists():write('receipt.json',{'state':'WRAPPER_FAILURE_NOT_QUALIFIED' if launched else 'PREFLIGHT_DENIED_NOT_LAUNCHED','reason':type(error).__name__,'binary_execution_count':0})
 raise
