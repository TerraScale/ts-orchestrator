import datetime,fcntl,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
packet=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
request_path=packet/'request.json'
assert sha(request_path.read_bytes())==sys.argv[1], 'request hash changed'
assert sha(Path(__file__).read_bytes())==sys.argv[2], 'runner hash changed'
r=json.loads(request_path.read_text()); root=Path(r['worktree']); env=r['env']
def write(name,value):
 p=packet/name;p.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');return sha(p.read_bytes())
def git(*args):
 return subprocess.check_output(['/run/current-system/sw/bin/git',*args],cwd=root,env=env).decode().strip()
def source():
 assert git('rev-parse','HEAD')==r['head'] and git('rev-parse','HEAD^{tree}')==r['tree']
 assert not git('status','--porcelain'), 'source dirty'
 paths=subprocess.check_output(['/run/current-system/sw/bin/git','ls-files','-z'],cwd=root,env=env).split(b'\0')
 entries={}
 for path in paths:
  if not path:continue
  p=root/os.fsdecode(path)
  entries[os.fsdecode(path)]=sha(os.fsencode(os.readlink(p))) if p.is_symlink() else sha(p.read_bytes())
 manifest=Path(r['manifest']);assert sha(manifest.read_bytes())==r['manifest_sha256']
 for path,digest in json.loads(manifest.read_text())['files'].items():
  p=root/path
  assert (sha(p.read_bytes()) if p.is_file() else None)==digest, 'manifest path changed: '+path
 return {'head':r['head'],'tree':r['tree'],'status':'clean','count':len(entries),'aggregate_sha256':sha(json.dumps(entries,sort_keys=True,separators=(',',':')).encode()),'files':entries}
def tools():
 base=Path('/home/mariogk/.local/share/mise/installs/go/1.27.1')
 paths=[base/'bin/go',*(base/'pkg/tool/linux_amd64'/name for name in ['compile','asm','link','vet']),Path(sys.executable),Path('/run/current-system/sw/bin/nice'),Path('/run/current-system/sw/bin/timeout'),Path('/run/current-system/sw/bin/git')]
 return {str(p):{'resolved':str(p.resolve()),'sha256':sha(p.read_bytes())} for p in paths}
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
receipt={'head':r['head'],'tree':r['tree'],'request_sha256':sys.argv[1],'runner_sha256':sys.argv[2],'argv':r['argv'],'env':env,'executed':False,'artifact_executed':False,'locks_released':False,'utc_start':datetime.datetime.now(datetime.UTC).isoformat()}
lock=None;proc=None;started=time.monotonic();group_cleanup=[]
try:
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
   os.killpg(proc.pid,signal.SIGTERM);group_cleanup.append('runner250s_TERM');
   try:receipt['exit_code']=proc.wait(timeout=5)
   except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);group_cleanup.append('runner255s_KILL');receipt['exit_code']=proc.wait()
 receipt['wall_seconds']=time.monotonic()-started
 for sig,delay in [(signal.SIGTERM,0.2),(signal.SIGKILL,0.1)]:
  try:os.killpg(proc.pid,0)
  except ProcessLookupError:break
  os.killpg(proc.pid,sig);group_cleanup.append(signal.Signals(sig).name);time.sleep(delay)
 try:os.killpg(proc.pid,0);receipt['process_group_empty']=False
 except ProcessLookupError:receipt['process_group_empty']=True
 artifact=packet/'terrascale-orchestrator'
 if artifact.exists():
  artifact.chmod(0o600);receipt['artifact']={'path':str(artifact),'sha256':sha(artifact.read_bytes()),'mode':oct(artifact.stat().st_mode&0o777),'bytes':artifact.stat().st_size,'elf':artifact.read_bytes()[:4]==b'\x7fELF','executed':False}
 post=source();posttools=tools();receipt['source_post_sha256']=write('source-post.json',post);receipt['tool_post_sha256']=write('tools-post.json',posttools)
 receipt['source_unchanged']=pre==post;receipt['tools_unchanged']=pretools==posttools
 assert receipt['source_unchanged'] and receipt['tools_unchanged'] and receipt['process_group_empty']
 receipt['state']='COMPILE_PASS_NO_EXECUTION' if receipt['exit_code']==0 else 'COMPILE_FAIL_STOPPED_FIRST_FAILURE'
except BaseException as e:
 receipt['state']='RUNNER_REFUSAL_OR_ERROR';receipt['error']=repr(e)
finally:
 if proc is not None and proc.poll() is None:
  try:os.killpg(proc.pid,signal.SIGKILL);proc.wait();group_cleanup.append('final_KILL')
  except ProcessLookupError:pass
 if lock is not None:
  fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
 receipt['locks_released']=True;receipt['cleanup']=group_cleanup;receipt['resources_end']=resources();receipt['wall_seconds']=time.monotonic()-started;receipt['utc_end']=datetime.datetime.now(datetime.UTC).isoformat()
 receipt['logs']={p.name:sha(p.read_bytes()) for p in [packet/'stdout.log',packet/'stderr.log'] if p.exists()}
 receiptsha=write('receipt.json',receipt)
 seal={p.name:sha(p.read_bytes()) for p in packet.iterdir() if p.is_file() and p.name!='FINAL-SEAL.json'}
 write('FINAL-SEAL.json',seal)
 print(json.dumps({'event':'terminal','state':receipt['state'],'exit_code':receipt.get('exit_code'),'wall_seconds':receipt['wall_seconds'],'receipt_sha256':receiptsha,'final_seal_sha256':sha((packet/'FINAL-SEAL.json').read_bytes()),'packet':str(packet),'locks_released':True}),flush=True)
 if (packet/'stderr.log').exists():print((packet/'stderr.log').read_text()[-18000:],flush=True)
sys.exit(0 if receipt['state']=='COMPILE_PASS_NO_EXECUTION' else 1)
