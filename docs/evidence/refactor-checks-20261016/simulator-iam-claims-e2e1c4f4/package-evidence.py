from pathlib import Path,PurePosixPath
import gzip,hashlib,io,json,struct,tarfile,zlib
D=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
package=json.loads((D/'package.json').read_text());blob=(D/'evidence.tar.gz').read_bytes()
assert sha(blob)==package['archive_sha256'] and blob[:10]==bytes.fromhex('1f8b08000000000002ff')
raw=gzip.decompress(blob);assert sha(raw)==package['uncompressed_tar_sha256']
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tf:
 members=tf.getmembers();names=[m.name for m in members];assert names==sorted(names) and len(names)==len(set(names))
 data={}
 for m in members:
  p=PurePosixPath(m.name);assert p.parts[0]=='packet' and not p.is_absolute() and '..' not in p.parts and m.isfile()
  assert (m.mode,m.uid,m.gid,m.uname,m.gname,m.mtime)==(0o644,0,0,'','',0)
  data[m.name]=tf.extractfile(m).read()
 assert [{'name':m.name,'sha256':sha(data[m.name]),'bytes':len(data[m.name])} for m in members]==package['archive_members']
for line in data['packet/SHA256SUMS'].decode().splitlines():
 h,n=line.split('  ',1);assert sha(data['packet/'+n])==h
for e in json.loads(data['packet/MEMBERS.json'])['members']:
 assert sha(data['packet/'+e['path']])==e['sha256'] and len(data['packet/'+e['path']])==e['bytes']
for e in json.loads(data['packet/provenance.json'])['inputs']:
 b=data['packet/'+e['archive_relative_path']];assert sha(b)==e['original']['sha256'] and len(b)==e['original']['bytes']
rebuilt=bytearray()
for name in sorted(data):
 b=data[name];h=tarfile.TarInfo(name);h.mode=0o644;h.uid=h.gid=h.mtime=0;h.uname=h.gname='';h.type=tarfile.REGTYPE;h.size=len(b)
 rebuilt.extend(h.tobuf(format=tarfile.USTAR_FORMAT));rebuilt.extend(b);rebuilt.extend(bytes((-len(b))%512))
rebuilt.extend(bytes(1024));rebuilt.extend(bytes((-len(rebuilt))%tarfile.RECORDSIZE));assert bytes(rebuilt)==raw
c=zlib.compressobj(9,zlib.DEFLATED,-zlib.MAX_WBITS)
again=bytes.fromhex('1f8b08000000000002ff')+c.compress(raw)+c.flush()+struct.pack('<II',zlib.crc32(raw)&0xffffffff,len(raw)&0xffffffff)
assert again==blob
for line in (D/'SHA256SUMS').read_text().splitlines():
 h,n=line.split('  ',1);assert sha((D/n).read_bytes())==h
print(json.dumps({'archive_sha256':sha(blob),'members':len(members),'all_member_original_hashes_verified':True,'independent_tar_rebuild_byte_equal':True,'independent_gzip_rebuild_byte_equal':True,'no_extraction_or_writes':True},indent=2))
