import fcntl,hashlib,json,os,pathlib,re,resource,subprocess,sys,time
OUT=pathlib.Path(__file__).parent
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def write(name,value):
 with (OUT/name).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
m=json.loads((OUT/'request.json').read_bytes());w=pathlib.Path(m['worktree']);manifest=json.loads((OUT/'fullsource-manifest.json').read_bytes())
launched=False;copied=OUT/'runtime-region.test'
def git(*args):return subprocess.check_output([m['tools']['git']['path'],'-C',str(w),*args]).decode().strip()
def snapshot():
 assert sorted(filter(None,git('ls-files','-z').split('\0')))==sorted(x['path'] for x in manifest)
 for item in manifest:assert sha(w/item['path'])==item['sha256']
 for tool in m['tools'].values():assert sha(tool['path'])==tool['sha256']
 assert sha(m['binary']['path'])==m['binary']['sha256']
 assert pathlib.Path(m['binary']['path']).stat().st_mode&0o777==0o600
 assert sha(m['compile_receipt']['path'])==m['compile_receipt']['sha256']
 return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1','--untracked-files=all'),'manifest_sha256':sha(OUT/'fullsource-manifest.json'),'request_sha256':sha(OUT/'request.json'),'wrapper_sha256':sha(__file__),'binary_sha256':sha(m['binary']['path']),'compile_receipt_sha256':sha(m['compile_receipt']['path']),'tools':m['tools']}
try:
 seal=json.loads((OUT/'final-seal.json').read_bytes())
 for a in seal['artifacts']:assert sha(OUT/a['path'])==a['sha256']
 assert sha(__file__)==m['wrapper_sha256'] and sha(OUT/'fullsource-manifest.json')==m['fullsource_manifest_sha256']
 assert os.geteuid()!=0
 pre=snapshot();assert pre['head']==m['commit'] and pre['tree']==m['tree'] and not pre['status']
 assert not copied.exists()
 write('preflight.json',{'source':pre,'argv':m['request']['argv'],'environment':m['environment'],'runtime_scope':m['scope'],'original_binary_execution_count':0})
 with open(m['request']['shared_lock'],'a') as gate:
  try:fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','runtime_binary_execution_count':0});sys.exit(75)
  copied.write_bytes(pathlib.Path(m['binary']['path']).read_bytes());copied.chmod(0o500)
  assert sha(copied)==m['binary']['sha256']
  start=time.monotonic()
  with (OUT/'runtime.stdout').open('xb') as stdout,(OUT/'runtime.stderr').open('xb') as stderr:
   proc=subprocess.Popen(m['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True);launched=True
   write('started.json',{'pid':proc.pid,'argv':m['request']['argv'],'epoch':time.time(),'binary_sha256':sha(copied)})
   print(json.dumps({'state':'STARTED_LOCAL_PROVISION_SCENARIO','pid':proc.pid,'output':str(OUT)}),flush=True);rc=proc.wait()
  copied.chmod(0o600)
  raw=(OUT/'runtime.stdout').read_text(errors='replace');runs=re.findall(r'^=== RUN\s+(\S+)\s*$',raw,re.M);passes=re.findall(r'^\s*--- PASS: (\S+) \(',raw,re.M);fails=re.findall(r'^\s*--- (?:FAIL|SKIP): (\S+) \(',raw,re.M)
  post=snapshot();expected=set(m['expected_test_identities']);success=rc==0 and pre==post and set(runs)==expected and len(runs)==len(expected) and set(passes)==expected and len(passes)==len(expected) and not fails and raw.rstrip().endswith('PASS') and sha(copied)==m['binary']['sha256']
  receipt={'state':'LOCAL_PROVISION_SCENARIO_PASS' if success else 'NOT_QUALIFIED','exit_code':rc,'wall_seconds':time.monotonic()-start,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'runs':runs,'passes':passes,'fail_or_skip':fails,'runtime_binary_execution_count':1,'original_compile_binary_execution_count':0,'runtime_binary':{'path':str(copied),'sha256':sha(copied),'mode':oct(copied.stat().st_mode&0o777)},'stdout_sha256':sha(OUT/'runtime.stdout'),'stderr_sha256':sha(OUT/'runtime.stderr'),'scope':m['scope'],'resource_limits':m['resource_limits']}
  write('receipt.json',receipt);print(json.dumps(receipt),flush=True);fcntl.flock(gate,fcntl.LOCK_UN)
 sys.exit(0 if success else 1)
except Exception as error:
 if copied.is_file():copied.chmod(0o600)
 if not (OUT/'receipt.json').exists():write('receipt.json',{'state':'WRAPPER_FAILURE_NOT_QUALIFIED' if launched else 'PREFLIGHT_DENIED_NOT_LAUNCHED','reason':type(error).__name__,'runtime_binary_execution_count':1 if launched else 0})
 raise
