import datetime,fcntl,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
packet=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
request_path=packet/'request.json'
assert sha(request_path.read_bytes())==sys.argv[1], 'request hash changed'
assert sha(Path(__file__).read_bytes())==sys.argv[2], 'runner hash changed'
r=json.loads(request_path.read_text()); root=Path(r['worktree']); env=r['env']
os.umask(0o077)
def write(name,value):
 p=packet/name;p.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');return sha(p.read_bytes())
def git(*args):
 return subprocess.check_output(['/run/current-system/sw/bin/git','--no-optional-locks',*args],cwd=root,env=env).decode().strip()
def source():
 assert git('rev-parse','HEAD')==r['head'] and git('rev-parse','HEAD^{tree}')==r['tree']
 assert not git('status','--porcelain'), 'source dirty'
 manifest=Path(r['manifest']);assert sha(manifest.read_bytes())==r['manifest_sha256']
 frozen=json.loads(manifest.read_text());entries={}
 raw=subprocess.check_output(['/run/current-system/sw/bin/git','--no-optional-locks','ls-files','--stage','-z'],cwd=root,env=env)
 for item in raw.split(b'\0'):
  if not item:continue
  meta,path=item.split(b'\t',1);mode,oid,stage=meta.decode().split();assert stage=='0'
  name=os.fsdecode(path);p=root/name;data=os.fsencode(os.readlink(p)) if p.is_symlink() else p.read_bytes()
  entries[name]={'mode':mode,'oid':oid,'sha256':sha(data),'bytes':len(data)}
 assert entries==frozen['entries'], 'source differs from full frozen manifest'
 return {'head':r['head'],'tree':r['tree'],'status':'clean','count':len(entries),'aggregate_sha256':sha(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()),'entries':entries}
def tools():
 base=Path('/home/mariogk/.local/share/mise/installs/go/1.27.1')
 paths=[base/'bin/go',base/'bin/gofmt',*(base/'pkg/tool/linux_amd64'/name for name in ['compile','asm','link','vet']),Path(sys.executable),Path('/run/current-system/sw/bin/nice'),Path('/run/current-system/sw/bin/timeout'),Path('/run/current-system/sw/bin/git')]
 pins={str(p):{'resolved':str(p.resolve()),'sha256':sha(p.read_bytes())} for p in paths}
 freeze=Path(r['tools_freeze']);assert sha(freeze.read_bytes())==r['tools_freeze_sha256']
 assert pins==json.loads(freeze.read_text()), 'tool differs from frozen pin'
 return pins
def resources():
 mem={line.split(':')[0]:int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines() if line.split(':')[0] in ['MemAvailable','MemTotal']}
 compilers=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdecimal():continue
  try:
   exe=(p/'exe').resolve()
   if exe.name=='compile':compilers.append({'pid':int(p.name),'exe':str(exe)})
  except (OSError,RuntimeError):pass
 return {'memory':mem,'load':list(os.getloadavg()),'compilers':compilers}
def owned_group(proc):
 members=[]
 for path in Path('/proc').glob('[0-9]*'):
  try:
   wire=(path/'stat').read_text();fields=wire[wire.rfind(')')+2:].split()
   if int(fields[2])==proc.pid or int(path.name)==proc.pid:members.append(int(path.name))
  except (OSError,ValueError,IndexError):pass
 return members
def reap_group(proc):
 for sig in (signal.SIGTERM,signal.SIGKILL):
  proc.poll()
  if not owned_group(proc):break
  try:os.killpg(proc.pid,sig);group_cleanup.append(signal.Signals(sig).name)
  except ProcessLookupError:pass
  deadline=time.monotonic()+5
  while time.monotonic()<deadline:
   proc.poll()
   if not owned_group(proc):break
   time.sleep(.05)
 proc.poll()
 return owned_group(proc)
def interrupted(signum,frame):
 raise RuntimeError('runner interrupted by signal '+str(signum))
receipt={'head':r['head'],'tree':r['tree'],'request_sha256':sys.argv[1],'runner_sha256':sys.argv[2],'argv':r['argv'],'env':env,'executed':False,'artifact_executed':False,'lock_acquired':False,'locks_released':False,'utc_start':datetime.datetime.now(datetime.UTC).isoformat()}
lock=None;proc=None;pre=None;pretools=None;started=time.monotonic();group_cleanup=[]
old_handlers={sig:signal.signal(sig,interrupted) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
try:
 assert not (packet/'receipt.json').exists() and not (packet/'running.json').exists(), 'single-use packet already consumed'
 assert not (packet/'oci.test').exists(), 'output already exists'
 lock=open(r['lock'],'a+');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 receipt['lock_acquired']=True
 pre=source();pretools=tools();receipt['source_pre_sha256']=write('source-pre.json',pre);receipt['tool_pre_sha256']=write('tools-pre.json',pretools)
 first=resources();receipt['resources_start']=first
 assert first['memory']['MemAvailable']>=16*1024**3, 'available RAM below16GiB'
 assert first['load'][0]<12, 'load1 at least12'
 assert len(first['compilers'])<4, 'four existing compilers'
 with open(packet/'stdout.log','wb') as out,open(packet/'stderr.log','wb') as err:
  proc=subprocess.Popen(r['argv'],cwd=root,env=env,stdout=out,stderr=err,start_new_session=True)
  receipt['executed']=True;receipt['process_group']=proc.pid
  write('running.json',receipt)
  print(json.dumps({'event':'launched','pid':proc.pid,'packet':str(packet),'request_sha256':sys.argv[1],'runner_sha256':sys.argv[2]}),flush=True)
  try:receipt['exit_code']=proc.wait(timeout=250)
  except subprocess.TimeoutExpired:
   receipt['timed_out']=True
   raise RuntimeError('runner250s deadline exceeded; strict final cleanup required')
 receipt['process_group_empty']=not owned_group(proc)
 assert receipt['process_group_empty'], 'owned compiler group remains after leader exit; strict final cleanup required'
 receipt['state']='COMPILE_PASS_NO_EXECUTION' if receipt['exit_code']==0 else 'COMPILE_FAIL_STOPPED_FIRST_FAILURE'
except BaseException as e:
 receipt['state']='RUNNER_REFUSAL_OR_ERROR';receipt['error']=repr(e)
finally:
 for sig in old_handlers:signal.signal(sig,signal.SIG_IGN)
 remaining=[]
 if proc is not None:
  try:remaining=reap_group(proc)
  except BaseException as e:
   receipt['state']='RUNNER_REFUSAL_OR_ERROR';receipt['cleanup_error']=repr(e);remaining=owned_group(proc)
  if remaining:
   receipt['state']='FAILED_CLEANUP_PENDING'
   receipt['cleanup_pending']={'remaining_group_processes':remaining,'lock_held':receipt['lock_acquired']}
   receipt['cleanup']=group_cleanup;receipt['wall_seconds']=time.monotonic()-started
   try:write('receipt.json',receipt)
   except BaseException:pass
   try:print(json.dumps({'event':'cleanup_pending','state':receipt['state'],'remaining_group_processes':remaining,'lock_held':receipt['lock_acquired'],'packet':str(packet)}),flush=True)
   except BaseException:pass
   while remaining:
    proc.poll();time.sleep(.05);remaining=owned_group(proc)
   receipt['state']='RUNNER_REFUSAL_OR_ERROR';receipt['cleanup_pending']['resolved']='OWNED_GROUP_ABSENT'
  proc.poll();receipt['process_group_empty']=True;receipt['cleanup_owned_group_after']='ABSENT'
  if 'exit_code' not in receipt:receipt['exit_code']=proc.returncode
 try:
  artifact=packet/'oci.test'
  if artifact.exists():
   artifact.chmod(0o600);data=artifact.read_bytes();receipt['artifact']={'path':str(artifact),'sha256':sha(data),'mode':oct(artifact.stat().st_mode&0o777),'bytes':len(data),'elf':data[:4]==b'\x7fELF','executed':False}
  if receipt.get('exit_code')==0:assert receipt.get('artifact',{}).get('elf') and receipt['artifact']['mode']=='0o600' and receipt['artifact']['bytes']>0, 'missing or invalid compiled ELF'
 except BaseException as e:
  receipt['state']='RUNNER_REFUSAL_OR_ERROR';receipt['artifact_error']=repr(e)
 try:
  post=source();receipt['source_post_sha256']=write('source-post.json',post);receipt['source_unchanged']=pre==post
  assert receipt['source_unchanged'], 'source changed or pre-source identity unavailable'
 except BaseException as e:
  receipt['state']='RUNNER_REFUSAL_OR_ERROR';receipt['source_post_error']=repr(e)
 try:
  posttools=tools();receipt['tool_post_sha256']=write('tools-post.json',posttools);receipt['tools_unchanged']=pretools==posttools
  assert receipt['tools_unchanged'], 'tools changed or pre-tool identity unavailable'
 except BaseException as e:
  receipt['state']='RUNNER_REFUSAL_OR_ERROR';receipt['tools_post_error']=repr(e)
 if lock is not None:
  if receipt['lock_acquired']:fcntl.flock(lock,fcntl.LOCK_UN)
  lock.close()
 receipt['locks_released']=True;receipt['cleanup']=group_cleanup;receipt['resources_end']=resources();receipt['wall_seconds']=time.monotonic()-started;receipt['utc_end']=datetime.datetime.now(datetime.UTC).isoformat()
 receipt['logs']={p.name:sha(p.read_bytes()) for p in [packet/'stdout.log',packet/'stderr.log'] if p.exists()}
 receiptsha=write('receipt.json',receipt)
 seal={p.name:sha(p.read_bytes()) for p in packet.iterdir() if p.is_file() and p.name!='FINAL-SEAL.json'}
 write('FINAL-SEAL.json',seal)
 print(json.dumps({'event':'terminal','state':receipt['state'],'exit_code':receipt.get('exit_code'),'wall_seconds':receipt['wall_seconds'],'receipt_sha256':receiptsha,'final_seal_sha256':sha((packet/'FINAL-SEAL.json').read_bytes()),'packet':str(packet),'locks_released':True}),flush=True)
 if (packet/'stderr.log').exists():print((packet/'stderr.log').read_text()[-18000:],flush=True)
 for sig,handler in old_handlers.items():signal.signal(sig,handler)
sys.exit(0 if receipt['state']=='COMPILE_PASS_NO_EXECUTION' else 1)
