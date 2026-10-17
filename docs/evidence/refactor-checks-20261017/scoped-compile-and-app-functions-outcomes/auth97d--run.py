import fcntl,hashlib,json,pathlib,resource,subprocess,time
OUT=pathlib.Path(__file__).parent
def sha(b):return hashlib.sha256(b).hexdigest()
def write(name,value):
 with (OUT/name).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
m=json.loads((OUT/'request.json').read_bytes());w=pathlib.Path(m['worktree']);output=OUT/'binaries'
assert sha(pathlib.Path(__file__).read_bytes())==m['wrapper_sha256']
assert sha((OUT/'fullsource-manifest.json').read_bytes())==m['fullsource_manifest_sha256']
manifest=json.loads((OUT/'fullsource-manifest.json').read_bytes())
def git(*args):return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(w),*args]).decode().strip()
def snapshot():
 tracked=git('ls-files','-z').split('\0');assert sorted(filter(None,tracked))==sorted(x['path'] for x in manifest)
 for item in manifest:assert sha((w/item['path']).read_bytes())==item['sha256']
 return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1','--untracked-files=all'),'fullsource_manifest_sha256':sha((OUT/'fullsource-manifest.json').read_bytes()),'go_sha256':sha(pathlib.Path(m['go_binary']).read_bytes()),'python_sha256':sha(pathlib.Path(m['python_binary']).read_bytes()),'wrapper_sha256':sha(pathlib.Path(__file__).read_bytes()),'request_sha256':sha((OUT/'request.json').read_bytes())}
pre=snapshot();assert pre['head']==m['commit'] and pre['tree']==m['tree'] and not pre['status']
assert pre['go_sha256']==m['go_binary_sha256'] and pre['python_sha256']==m['python_binary_sha256']
assert output.is_dir() and not list(output.iterdir())
write('preflight.json',{'source':pre,'argv':m['request']['argv'],'environment':m['environment'],'compile_only':True,'binary_execution_count':0})
with open(m['request']['shared_lock'],'a') as gate:
 try:fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED'});raise SystemExit(75)
 start=time.monotonic()
 with (OUT/'compile.stdout').open('xb') as stdout,(OUT/'compile.stderr').open('xb') as stderr:
  proc=subprocess.Popen(m['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True)
  write('started.json',{'pid':proc.pid,'argv':m['request']['argv'],'epoch':time.time()})
  print(json.dumps({'state':'STARTED_COMPILE_ONLY','pid':proc.pid,'output':str(OUT)}),flush=True)
  rc=proc.wait()
 elapsed=time.monotonic()-start;post=snapshot();binaries=[]
 for p in sorted(output.iterdir()):
  p.chmod(0o600);wire=p.read_bytes();binaries.append({'path':str(p),'sha256':sha(wire),'bytes':len(wire),'magic_hex':wire[:4].hex(),'mode':oct(p.stat().st_mode&0o777),'never_executed':True})
 success=rc==0 and pre==post and {pathlib.Path(x['path']).name for x in binaries}==set(m['expected_binaries']) and all(x['magic_hex']=='7f454c46' for x in binaries)
 receipt={'state':'COMPILE_PASS' if success else 'NOT_QUALIFIED','exit_code':rc,'wall_seconds':elapsed,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'binaries':binaries,'binary_execution_count':0,'stdout_sha256':sha((OUT/'compile.stdout').read_bytes()),'stderr_sha256':sha((OUT/'compile.stderr').read_bytes()),'scope':'true test-c compile/link only; no binary execution, runtime proof or canonical adoption claim'}
 write('receipt.json',receipt);print(json.dumps(receipt),flush=True);fcntl.flock(gate,fcntl.LOCK_UN)
raise SystemExit(0 if success else 1)
