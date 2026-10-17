from pathlib import Path
import subprocess,hashlib,json,os,fcntl,time,datetime,sys
D=Path(__file__).resolve().parent;W=Path('/tmp/ts-qa-zero-config-rank1-dd22a8d0');H='7f504383cc8e8703031e1bb901fbac99223f05ae';T='00fcaa65e0544a967a04c6d656470e4585414fc0'
def sha(b):return hashlib.sha256(b).hexdigest()
def git(*a):return subprocess.check_output(['git',*a],cwd=W)
def state():
 assert git('rev-parse','HEAD').decode().strip()==H and git('rev-parse','HEAD^{tree}').decode().strip()==T and git('status','--porcelain')==b''
 return {p:sha((W/p).read_bytes()) for p in ['scripts/ci/zero-config-check.py','scripts/ci/test_zero_config_check.py']}
pre=state();env={'HOME':'/home/mariogk','PATH':'/home/mariogk/.local/share/mise/installs/go/1.27.1/bin:/run/current-system/sw/bin','LANG':'C.UTF-8','GOMAXPROCS':'2','GOFLAGS':'-p=2','GOTOOLCHAIN':'local'}
argv=['/run/current-system/sw/bin/timeout','--signal=TERM','--kill-after=5s','60s','/run/current-system/sw/bin/nice','-n','19','/home/mariogk/.local/share/mise/installs/python/3.15.0/bin/python3.15','-I','-B','scripts/ci/test_zero_config_check.py','-v']
with open('/tmp/ts-orch-refactor-gate-check.lock','a') as gate:
 fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
 started=datetime.datetime.now(datetime.timezone.utc).isoformat();clock=time.monotonic()
 with (D/'stdout.log').open('xb') as out,(D/'stderr.log').open('xb') as err:r=subprocess.run(argv,cwd=W,env=env,stdout=out,stderr=err)
 elapsed=time.monotonic()-clock;post=state();assert pre==post
 receipt={'state':'PASS' if r.returncode==0 else 'FAIL','source':H,'tree':T,'argv':argv,'environment':env,'cwd':str(W),'started_utc':started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'seconds':elapsed,'exit_code':r.returncode,'pre':pre,'post':post,'gate_exclusive_nonblocking':True,'Python_executable_sha256':sha(Path(sys.executable).read_bytes()),'expected_test_methods':10,'source_counted_temp_git_scenarios':16,'Go_executed':False,'logs':{n:{'bytes':(D/n).stat().st_size,'sha256':sha((D/n).read_bytes())} for n in ['stdout.log','stderr.log']}}
 with (D/'receipt.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
 print(json.dumps({'receipt':str(D/'receipt.json'),'receipt_sha256':sha((D/'receipt.json').read_bytes()),'state':receipt['state'],'seconds':elapsed,'exit_code':r.returncode}));sys.exit(r.returncode)
