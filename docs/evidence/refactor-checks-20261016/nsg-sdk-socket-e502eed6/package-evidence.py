from pathlib import Path,PurePosixPath
import subprocess,hashlib,json,io,tarfile,gzip,collections
D=Path(__file__).resolve().parent; W=Path('/tmp/ts-terrabase-nsg-sdk-socket'); REL='docs/evidence/refactor-checks-20261016/nsg-sdk-socket-e502eed6'; DOC=W/REL; PACKET=D/'packet'
HEAD='e502eed69cd2c020448b94c6970d9bacd8942cd8';TREE='31d1fd6d1811db28dfa86b1207ab492b02aab2c8';PARENT='7512c426670cef4558c94ee62350fd1f29b850e9'
ROOTS={
'proposal-frozen':Path('/tmp/ts-f2-nsg-source-proposal-c466da0d-20261016-5bf8f0cd'),
'source-original':Path('/tmp/ts-terrabase-nsg-sdk-socket-source-7e297694-aa2f8ca1'),
'source-adoption':Path('/tmp/ts-terrabase-nsg-adoption-7512c426-e5qlu52u'),
'compile/setup-only-failure':Path('/tmp/ts-terrabase-nsg-first-compile-e502eed6-l5dnaznl'),
'compile/default-pass':Path('/tmp/ts-terrabase-nsg-first-compile-e502eed6-5tui3_md'),
'runtime/default-once-pass':Path('/tmp/ts-terrabase-nsg-first-runtime-e502eed6-lkrfgaqf'),
'runtime/audit':Path('/tmp/ts-terrabase-nsg-runtime-audit-e502eed6-_67odo8g')}
QAS={
'source-review':('/tmp/ts-qa-nsg-source-review-7e297694-20261017T002315Z-a63c8705.json','edff615d49a7f23986699defaf1accb48ab4763fb5d33be3606f059a543d5788'),
'adoption-review':('/tmp/ts-qa-nsg-adoption-review-e502eed6-20261017T003240Z-b45aa092.json','30e06e7590254efea2332c2c68015c099b70c41d4f61285ffddec7ea27f7203b'),
'compile-review':('/tmp/ts-qa-nsg-compile-review-e502eed6-20261017T003555Z-1ede43db.json','14499a516b515c2b47784c50ee9af273ec2f6da7ee9427a64a454405609bfece'),
'runtime-review':('/tmp/ts-qa-nsg-runtime-review-e502eed6-20261017T004042Z-a0b19e2b.json','fc3131b7428c6b37225a91e3a5ccaa529118bde9888b03598165d5829776e009')}
KNOWN={
'source-original':'33d88efcdc2e9483da9124056696ab2d114b177683551b1ff31f1ce3a05bf9f4',
'source-adoption':'217a9b6764345fc829abb620983ac2653f51942101ae8a8a75fcf51d2321bbf9',
'compile/setup-only-failure':'a49749de420c10d065eb191a2a69aa6c59d31f0a7f41f9c2377abe6e4f8b9516',
'compile/default-pass':'e68f9b99321170685e2ed2fa26ce8a67973a93cad8883e3579e67131cbab1a16',
'runtime/default-once-pass':'c360dbb8de60a1b4655f4b4ebaad739ec935dccbe1042640ed4eb47f804e39af',
'runtime/audit':'78a8e463202df874ea9346d530f7fe7cf2c57d000c1c322b33de96ccf65ba092'}
OMIT=ROOTS['compile/default-pass']/'terrabase-default.test'
def sha(b):return hashlib.sha256(b).hexdigest()
def jb(x):return (json.dumps(x,indent=2)+'\n').encode()
def write(p,b):
 p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
def git(*args):return subprocess.check_output(['git',*args],cwd=W)
def fi(p,metadata=False):
 p=Path(p);s=p.stat();d={'path':str(p),'sha256':sha(p.read_bytes()),'bytes':s.st_size}
 if metadata:d.update(mode=s.st_mode,mtime_ns=s.st_mtime_ns)
 return d
def identity():
 assert git('rev-parse','HEAD').decode().strip()==HEAD and git('rev-parse','HEAD^{tree}').decode().strip()==TREE and git('show','-s','--format=%P','HEAD').decode().strip()==PARENT
 assert git('diff','--binary')==b'' and git('diff','--cached','--binary')==b''
 source=W/'internal/terrabase/oci_live_test.go';assert sha(source.read_bytes())=='da7665e5f1e8ab5a73f7e5735dd29423712bef6ad8e739193ef017240d298c22'
 bindings=json.loads((ROOTS['source-original']/'source-review.json').read_text())['unchanged_bound_files']
 for b in bindings:assert sha((W/b['path']).read_bytes())==b['sha256'] and git('rev-parse',HEAD+':'+b['path']).decode().strip()==b['git_blob']
 assert len(bindings)==12
 return {'head':HEAD,'tree':TREE,'sole_parent':PARENT,'source_sha256':sha(source.read_bytes()),'bound_repository_files':bindings,'index_entries_sha256':sha(git('ls-files','--stage')),'tracked_diff_empty':True,'staged_diff_empty':True}
assert not DOC.exists() and not PACKET.exists() and git('status','--porcelain=v1')==b''
pre=identity(); inputs=[]
for prefix,root in ROOTS.items():
 mp=root/'artifact-manifest.json';m=json.loads(mp.read_text())
 if prefix in KNOWN:assert sha(mp.read_bytes())==KNOWN[prefix]
 for a in m['artifacts']:
  p=Path(a['path']);p=p if p.is_absolute() else root/p;data=p.read_bytes();assert sha(data)==a['sha256'] and len(data)==a.get('bytes',a.get('size'))
 for p in sorted(root.rglob('*')):
  if p.is_dir():continue
  assert p.is_file() and not p.is_symlink();inputs.append({'archive_relative_path':prefix+'/'+p.relative_to(root).as_posix(),'original':fi(p,True),'omit_binary':p==OMIT})
for name,(location,expected) in QAS.items():
 p=Path(location);assert sha(p.read_bytes())==expected;inputs.append({'archive_relative_path':'qa/'+name+'.json','original':fi(p,True),'omit_binary':False})
assert len(inputs)==96 and sum(i['omit_binary'] for i in inputs)==1
binary=fi(OMIT,True);assert binary['sha256']=='4f4f2028c16710980ad465dbcdeefc1d346d9bb8c785d2ceb62922cfaec02220' and binary['bytes']==18854243
PACKET.mkdir()
for item in inputs:
 if not item['omit_binary']:write(PACKET/item['archive_relative_path'],Path(item['original']['path']).read_bytes())
assert len([p for p in PACKET.rglob('*') if p.is_file()])==95
omission={'variant':'default terrabase test compile','original_binary_location':str(OMIT),'sha256':binary['sha256'],'bytes':binary['bytes'],'original_binary_retained':True,'compiled_binary_executed_directly':False,'runtime_note':'Separate granted go test runtime generated/executed its own temporary test binary; the retained go test -c binary was never invoked.','reason':'Compiled executable bytes intentionally excluded from archive; original compile artifact manifest retained byte-for-byte, including its original binary entry.','original_receipt_archive_member':'packet/compile/default-pass/receipt.json','original_manifest_archive_member':'packet/compile/default-pass/artifact-manifest.json','original_manifest_sha256':KNOWN['compile/default-pass']}
write(PACKET/'omitted-binary.json',jb(omission))
README='''# NSG ingress through signed SDK sockets

Exact qualified source `e502eed69cd2c020448b94c6970d9bacd8942cd8`, tree `31d1fd6d1811db28dfa86b1207ab492b02aab2c8`, sole parent `7512c426670cef4558c94ee62350fd1f29b850e9`. The original accepted `7e297694` candidate was mechanically adopted with identical full-index patch and Go bytes. Only `internal/terrabase/oci_live_test.go` changes in that source commit. The original isolated `TestPeerPortOpen`, `peerPortOpen`, `liveEnv` and regional/profile/quota/image prefix remain retained and unchanged.

Default terrabase compilation passed once in 37.423481 seconds. The compiled binary was never invoked and its bytes are omitted; its exact 18,854,243-byte size, SHA256 and untouched original manifest/receipt provenance remain. The prior setup-only failure invoked no Go: `/usr/bin/timeout` was absent on NixOS; the fresh corrected wrapper used the installed timeout/nice paths. Both wrappers and terminal receipts remain unchanged.

Exactly one granted default runtime passed: root `TestPeerPortOpenThroughSDKObservedHosts` and five serial leaves `cidr`, `nsg`, `destination_miss`, `sender_nsg_miss`, `sender_cidr_miss`, with no skips, retries or extras. Wall 2.621893s; root 0.90s; package 0.913s. Thirty-five exact GETs (15 Compute, 20 VirtualNetwork) completed on five distinct localhost endpoints. Every request sequence/query/empty body and written response status/content type/no-page/completion/byte count/SHA256 matched. Ten ordered outcomes were allow/allow, allow/allow, deny/allow, deny/allow, deny/allow. Full decoded instances/attachments/VNICs/rules/peers/ordered-pair assertions passed by pinned source plus leaf PASS; raw logs print exchanges and peer/pair summaries, not full decoded structs.

This qualifies the synthetic localhost HTTP OCI SDK observation path and static ingress assessments. SDK signing-header structure is checked, not cryptographic signature validity or instance-principal federation. The existing one-page list traversal and source-port/Direction/IsValid/IsStateless limitations remain. Live OCI/host acceptance, production DNS/TLS, real peer TCP/egress/routing/security lists/listeners, replication, F3 witnesses, short/tagged/race/full-package runs, isolated-test removal and global migration closure remain unqualified.

The deterministic archive preserves the original frozen proposal/source/adoption packets, all four source/adoption/compile/runtime QA reviews, setup failure, corrected compile and runtime wrappers/argv/environment/prepost/logs/receipts/manifests, runtime audit/contract/static-response proof, complete source/patches, and per-member checksums/provenance. Archived original manifests are historical input records; the compile manifest deliberately still references the omitted binary. `omitted-binary.json` explains the omission. No old packet or source bytes were edited. Packaging creates documents only; no runner, commit, integration, push or cloud operation occurred.
'''
write(PACKET/'README.md',README.encode());write(PACKET/'packaging/package-evidence.py',Path(__file__).read_bytes())
provenance={'candidate':HEAD,'tree':TREE,'sole_parent':PARENT,'original_candidate':'7e2976940436a9e164bc6a5d38fdf7eade7d7b0a','source_sha256':pre['source_sha256'],'full_index_patch_sha256':'fb724ef244ed75dfc3eaed0a7436d7dbb3858bc5d82cef7af4a708adb4defa23','scope':'Evidence packaging only; no source edit, runner, Git mutation, integration, push or cloud. New docs remain untracked.','input_count_including_omitted_binary':96,'archived_original_file_count':95,'inputs':inputs,'omitted_binary':omission,'packaging_script':fi(__file__),'tar_policy':{'format':'USTAR','sorted_names':True,'regular_files_only':True,'mode':'0644','uid':0,'gid':0,'uname':'','gname':'','mtime':0},'gzip_policy':{'filename':'','mtime':0,'compresslevel':9},'manifest_policy':'packet/MEMBERS.json describes every payload except itself and packet/SHA256SUMS to avoid circular hashes; packet/SHA256SUMS describes every other archive member, including MEMBERS.json. External package.json enumerates every archive member including both.','accepted_qualification':'Source review + byte-identical parent adoption + one default package compile + one exact-root default runtime only.','original_test_retained':'TestPeerPortOpen remains byte-identical and is not retired.','runtime_metadata_evidence_limit':'Full decoded struct assertion success follows pinned source plus passing leaves; raw logs do not print full decoded structs.','future_publication':'Parent review/publication not performed by this script.'}
write(PACKET/'provenance.json',jb(provenance))
payload=sorted(p for p in PACKET.rglob('*') if p.is_file());assert len(payload)==99
write(PACKET/'MEMBERS.json',jb({'members':[{'path':p.relative_to(PACKET).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in payload],'excludes':['MEMBERS.json','SHA256SUMS'],'reason':'No circular self-hashes; external package.json inventories every archive member.'}))
write(PACKET/'SHA256SUMS',''.join(sha(p.read_bytes())+'  '+p.relative_to(PACKET).as_posix()+'\n' for p in sorted(PACKET.rglob('*')) if p.is_file()).encode())
files=sorted(p for p in PACKET.rglob('*') if p.is_file());assert len(files)==101

def build_tar():
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as tf:
  for p in files:
   data=p.read_bytes();ti=tarfile.TarInfo('packet/'+p.relative_to(PACKET).as_posix());ti.size=len(data);ti.mode=0o644;ti.uid=ti.gid=0;ti.uname=ti.gname='';ti.mtime=0;ti.type=tarfile.REGTYPE;tf.addfile(ti,io.BytesIO(data))
 return out.getvalue()
def compress(data):
 out=io.BytesIO()
 with gzip.GzipFile(fileobj=out,mode='wb',filename='',compresslevel=9,mtime=0) as gz:gz.write(data)
 return out.getvalue()
tar=build_tar();gz=compress(tar);assert build_tar()==tar and compress(tar)==gz and gzip.decompress(gz)==tar and gz[4:8]==b'\0\0\0\0' and gz[8]==2
write(D/'packet.tar',tar);write(D/'packet.tar.gz',gz);inventory=[]
with tarfile.open(fileobj=io.BytesIO(gz),mode='r:gz') as tf:
 assert len(tf.getmembers())==101
 for m in tf.getmembers():
  path=PurePosixPath(m.name);assert path.parts[0]=='packet' and not path.is_absolute() and '..' not in path.parts and m.isfile()
  assert (m.mode,m.mtime,m.uid,m.gid,m.uname,m.gname)==(0o644,0,0,0,'','')
  data=tf.extractfile(m).read();p=PACKET/Path(*path.parts[1:]);assert data==p.read_bytes()
  inventory.append({'name':m.name,'sha256':sha(data),'bytes':len(data),'mode':m.mode,'mtime':m.mtime,'uid':m.uid,'gid':m.gid,'uname':m.uname,'gname':m.gname})
assert all(not m['name'].endswith('terrabase-default.test') for m in inventory)
for item in inputs:assert fi(item['original']['path'],True)==item['original']
post=identity();assert pre==post
package={'candidate':HEAD,'qualified_commit':HEAD,'qualified_tree':TREE,'sole_parent':PARENT,'archive_path':str(D/'packet.tar.gz'),'archive_sha256':sha(gz),'archive_bytes':len(gz),'uncompressed_tar_sha256':sha(tar),'uncompressed_tar_bytes':len(tar),'archive_member_count':101,'archive_members':inventory,'deterministic_tar_rebuild_byte_equal':True,'deterministic_gzip_rebuild_byte_equal':True,'gzip_roundtrip_exact_bytes':True,'every_member_matches_original_or_new_packet':True,'safe_regular_members_only':True,'root_SHA256SUMS_sha256':sha((PACKET/'SHA256SUMS').read_bytes()),'MEMBERS_json_sha256':sha((PACKET/'MEMBERS.json').read_bytes()),'raw_runtime_jsonl_sha256':'c9487c0dfa9b64f95bd6a0bdb30565558ffdd19424beab1371f5c4c163d64fea','QA_reviews':{k:{'path':v[0],'sha256':v[1]} for k,v in QAS.items()},'binary_omitted':omission,'original_binary_untouched':binary,'all_96_original_inputs_unchanged':True,'source_and_index_unchanged':True,'pre_identity':pre,'post_identity':post,'packaging_script':fi(__file__),'packaging_operations':'Documents only; no Go/build/test/vet/lint/runner/runtime/server/commit/stage/integration/push/cloud/new agents.','publication_state':'Prepared untracked docs on exact qualified source worktree; parent publication pending.'}
write(D/'PACKAGE.json',jb(package));DOC.mkdir()
for name,data in {'README.md':README.encode(),'evidence.tar.gz':gz,'package.json':jb(package),'provenance.json':jb(provenance),'package-evidence.py':Path(__file__).read_bytes()}.items():write(DOC/name,data)
write(DOC/'SHA256SUMS',''.join(sha(p.read_bytes())+'  '+p.name+'\n' for p in sorted(DOC.iterdir()) if p.is_file()).encode())
expected=[REL+'/'+name for name in sorted(['README.md','evidence.tar.gz','package.json','provenance.json','package-evidence.py','SHA256SUMS'])];actual=git('ls-files','--others','--exclude-standard').decode().splitlines();assert actual==expected,(actual,expected)
assert git('diff','--name-only')==b'' and git('diff','--cached','--name-only')==b'' and identity()==pre
for item in inputs:assert fi(item['original']['path'],True)==item['original']
for line in (DOC/'SHA256SUMS').read_text().splitlines():
 h,n=line.split('  ',1);assert sha((DOC/n).read_bytes())==h
report={'state':'PACKAGED_NOT_COMMITTED_HOLD','evidence_directory':str(D),'docs_directory':str(DOC),'head':HEAD,'tree':TREE,'parent':PARENT,'staged_docs':[],'untracked_docs':expected,'archive_sha256':sha(gz),'archive_bytes':len(gz),'archive_member_count':101,'uncompressed_tar_sha256':sha(tar),'member_inventory':str(DOC/'package.json'),'packaging_script':fi(__file__),'docs_files':[fi(p) for p in sorted(DOC.iterdir())],'all_prior_inputs_96_unchanged':True,'compiled_binary_bytes_omitted':True,'no_source_or_index_changes':True,'no_new_runner_commit_integration_push_cloud':True}
write(D/'PACKAGING-REPORT.json',jb(report));print(json.dumps(report,indent=2))
