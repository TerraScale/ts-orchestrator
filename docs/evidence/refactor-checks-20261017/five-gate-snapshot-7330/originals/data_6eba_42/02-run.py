import collections,fcntl,hashlib,json,os,pathlib,resource,signal,subprocess,time
OUT=pathlib.Path(__file__).parent
RAW=(OUT/'request.json').read_bytes()
assert hashlib.sha256(RAW).hexdigest()=='3e7a3331fabf002dbd3d507365cfd854b5ef68dd26a329c0b3d6a885d2d2f451'
R=json.loads(RAW); W=pathlib.Path(R['worktree']); ENV=R['environment']
assert dict(os.environ)==ENV

def write(name,data):
 with (OUT/name).open('x') as f:json.dump(data,f,indent=2,sort_keys=True);f.write('\n')
def git(*args):return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(W),*args],env=ENV).decode()
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def seal():
 assert git('rev-parse','HEAD').strip()==R['commit'] and git('rev-parse','HEAD^{tree}').strip()==R['tree']
 assert not git('status','--porcelain=v1','--untracked-files=all')
 for e in R['source']:
  p=W/e['path']; b=os.readlink(p).encode() if e['mode']=='120000' else p.read_bytes()
  assert hashlib.sha256(b).hexdigest()==e['sha256'],e['path']
 for e in R['tools']:
  p=pathlib.Path(e['path']);assert str(p.resolve())==e['resolved'] and sha(p)==e['sha256'],e['path']
 return {'commit':R['commit'],'tree':R['tree'],'clean':True,'source_files':len(R['source']),'tool_count':len(R['tools'])}
def processes():
 result=[]
 for p in pathlib.Path('/proc').glob('[0-9]*'):
  try:
   stat=(p/'stat').read_text(); tail=stat[stat.rfind(')')+2:].split()
   result.append({'pid':int(p.name),'ppid':int(tail[1]),'pgrp':int(tail[2]),'comm':(p/'comm').read_text().strip()})
  except (OSError,ValueError,IndexError):pass
 return result
assert not (OUT/'started.json').exists() and not (OUT/'receipt.json').exists()
with open(R['lock'],'a') as gate:
 try:fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:
  write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED'});raise SystemExit(75)
 pre=seal(); memory={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())}; load=os.getloadavg()[0]; compilers=[p for p in processes() if p['comm']=='compile']
 write('preflight.json',{'source':pre,'mem_available':memory['MemAvailable'],'load1':load,'compilers':compilers,'argv':R['argv'],'environment':ENV})
 assert memory['MemAvailable']>=16*1024**3 and load<12 and len(compilers)<=4,'resource gate'
 started=time.monotonic()
 with (OUT/'stdout.jsonl').open('xb') as stdout,(OUT/'stderr.log').open('xb') as stderr:
  child=subprocess.Popen(R['argv'],cwd=W,env=ENV,start_new_session=True,stdout=stdout,stderr=stderr)
  write('started.json',{'pid':child.pid,'pgrp':child.pid,'argv':R['argv'],'runner_pid':os.getpid()})
  print(json.dumps({'state':'STARTED','pid':child.pid,'packet':str(OUT)}),flush=True)
  code=child.wait()
 remaining=[p for p in processes() if p['pgrp']==child.pid]
 if remaining:
  os.killpg(child.pid,signal.SIGTERM); end=time.monotonic()+5
  while time.monotonic()<end:
   remaining=[p for p in processes() if p['pgrp']==child.pid]
   if not remaining:break
   time.sleep(.05)
  if remaining:os.killpg(child.pid,signal.SIGKILL)
 post=seal();events=[];malformed=[]
 for i,line in enumerate((OUT/'stdout.jsonl').read_text().splitlines(),1):
  try:events.append(json.loads(line))
  except (ValueError,TypeError):malformed.append(i)
 expected=collections.Counter((p,t) for p,names in R['expected_packages'].items() for t in names)
 run=collections.Counter((e.get('Package'),e['Test']) for e in events if e.get('Action')=='run' and e.get('Test'))
 passed=collections.Counter((e.get('Package'),e['Test']) for e in events if e.get('Action')=='pass' and e.get('Test'))
 packages=collections.Counter(e.get('Package') for e in events if e.get('Action')=='pass' and not e.get('Test'))
 bad=[e for e in events if e.get('Action') in ['fail','skip']]
 success=code==0 and pre==post and not remaining and not malformed and not bad and run==passed==expected and packages==collections.Counter(R['expected_packages'].keys())
 receipt={'state':'PASS' if success else 'NOT_QUALIFIED','exit_code':code,'wall_seconds':time.monotonic()-started,'source_pre':pre,'source_post':post,'expected_outcomes':sum(expected.values()),'run_count':sum(run.values()),'pass_count':sum(passed.values()),'package_passes':dict(packages),'bad':bad,'malformed':malformed,'remaining_group_processes':remaining,'stdout_sha256':sha(OUT/'stdout.jsonl'),'stderr_sha256':sha(OUT/'stderr.log'),'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
 write('receipt.json',receipt)
 print(json.dumps(receipt),flush=True)
raise SystemExit(0 if success else 1)
