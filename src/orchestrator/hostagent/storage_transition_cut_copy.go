package hostagent

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json/v2"
 "errors"
 "io"
 "io/fs"
 "os"
 "path"
 "strings"
 "syscall"

 "terrascale.tech/orchestrator/src/orchestrator/controltransition"
)

type cutTreeEntry struct { Path string; Directory bool; Bytes int64; SHA256 string }
type cutTree struct { SHA256 string; Files int64; Bytes int64; Device uint64; Inode uint64 }

// inspectCutTree hashes file content and ordered relative names independently
// of ownership metadata. Links and special files never enter the copy scope.
func inspectCutTree(ctx context.Context, root *os.Root, limits controltransition.Limits) (cutTree,error) {
 var result cutTree
 info,err:=root.Stat(".");if err!=nil{return result,err}; st,ok:=info.Sys().(*syscall.Stat_t);if !ok{return result,errors.New("hostagent: source identity unavailable")};result.Device,result.Inode=uint64(st.Dev),st.Ino
 hash:=sha256.New();count:=int64(0)
 err=fs.WalkDir(root.FS(),".",func(name string,d fs.DirEntry,walkErr error)error{
  if walkErr!=nil{return walkErr};if err:=ctx.Err();err!=nil{return err};count++;if count>limits.MaxStoreFiles{return errors.New("hostagent: source file count exceeds plan")}
  if strings.HasSuffix(name,".storage-copy-partial"){return errors.New("hostagent: source uses reserved copy name")}
  entry:=cutTreeEntry{Path:name,Directory:d.IsDir()}
  info,err:=root.Lstat(name);if err!=nil{return err};st,ok:=info.Sys().(*syscall.Stat_t);if !ok || info.Mode()&os.ModeSymlink!=0{return errors.New("hostagent: unsafe source entry")}
  if !info.IsDir(){
   if !info.Mode().IsRegular() || st.Nlink!=1{return errors.New("hostagent: source links and special files refused")}
   if info.Size()<0 || info.Size()>limits.MaxStoreBytes-result.Bytes{return errors.New("hostagent: source exceeds byte bound")}
   f,err:=root.Open(name);if err!=nil{return err};opened,err:=f.Stat();if err!=nil || !os.SameFile(info,opened){f.Close();return errors.New("hostagent: source changed during open")}
   h:=sha256.New();n,readErr:=io.Copy(h,io.LimitReader(f,info.Size()+1));closeErr:=f.Close();if err:=errors.Join(readErr,closeErr);err!=nil{return err};if n!=info.Size(){return errors.New("hostagent: source changed while hashing")}
   entry.Bytes=n;entry.SHA256=hex.EncodeToString(h.Sum(nil));result.Bytes+=n;result.Files++
  }
  raw,err:=json.Marshal(entry);if err!=nil{return err};hash.Write(raw);hash.Write([]byte{'\n'});return nil
 });if err!=nil{return cutTree{},err};result.SHA256=hex.EncodeToString(hash.Sum(nil));return result,nil
}

// copyCutTree resumes only exact completed files. A fixed private temporary
// name belongs to this plan's copy operation and is never authoritative. Each
// file and directory is synced before the final independent whole-tree read.
func copyCutTree(ctx context.Context, source,destination *os.Root, limits controltransition.Limits) error {
 err:=fs.WalkDir(source.FS(),".",func(name string,d fs.DirEntry,walkErr error)error{
  if walkErr!=nil{return walkErr};if err:=ctx.Err();err!=nil{return err}
  if d.IsDir(){if name!="."{if err:=destination.Mkdir(name,0700);err!=nil && !errors.Is(err,fs.ErrExist){return err}};info,err:=destination.Lstat(name);if err!=nil || !info.IsDir() || info.Mode()&os.ModeSymlink!=0{return errors.New("hostagent: unsafe copy directory")};return nil}
  info,err:=source.Lstat(name);if err!=nil || !info.Mode().IsRegular(){return errors.New("hostagent: unsafe copy source")}
  if info.Size()<0 || info.Size()>limits.MaxStoreBytes{return errors.New("hostagent: copy file exceeds bound")}
  // Existing complete files are compared, never replaced to force recovery.
  if existing,err:=destination.Lstat(name);err==nil{if !existing.Mode().IsRegular() || existing.Size()!=info.Size(){return errors.New("hostagent: conflicting copy file")};return compareCutFile(source,destination,name)}else if !errors.Is(err,fs.ErrNotExist){return err}
  temporary:=name+".storage-copy-partial"
  if old,err:=destination.Lstat(temporary);err==nil{st,ok:=old.Sys().(*syscall.Stat_t);if !ok || !old.Mode().IsRegular() || st.Nlink!=1 || int(st.Uid)!=os.Geteuid(){return errors.New("hostagent: unsafe partial copy")};if err:=destination.Remove(temporary);err!=nil{return err}}else if !errors.Is(err,fs.ErrNotExist){return err}
  input,err:=source.Open(name);if err!=nil{return err};defer input.Close()
  output,err:=destination.OpenFile(temporary,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
  n,copyErr:=io.Copy(output,io.LimitReader(input,info.Size()+1));if copyErr==nil && n!=info.Size(){copyErr=errors.New("hostagent: source changed during copy")};if copyErr==nil{copyErr=output.Sync()};closeErr:=output.Close();if err:=errors.Join(copyErr,closeErr);err!=nil{return err}
  if err:=ctx.Err();err!=nil{return err};if err:=destination.Rename(temporary,name);err!=nil{return err};return syncCutDirectory(destination,path.Dir(name))
 });if err!=nil{return err}
 return fs.WalkDir(destination.FS(),".",func(name string,d fs.DirEntry,err error)error{if err!=nil{return err};if d.IsDir(){return syncCutDirectory(destination,name)};return nil})
}
func syncCutDirectory(root *os.Root,name string)error{f,err:=root.Open(name);if err!=nil{return err};return errors.Join(f.Sync(),f.Close())}
func compareCutFile(a,b *os.Root,name string)error{
 left,err:=a.Open(name);if err!=nil{return err};defer left.Close();right,err:=b.Open(name);if err!=nil{return err};defer right.Close()
 lh,rh:=sha256.New(),sha256.New();if _,err:=io.Copy(lh,left);err!=nil{return err};if _,err:=io.Copy(rh,right);err!=nil{return err};if hex.EncodeToString(lh.Sum(nil))!=hex.EncodeToString(rh.Sum(nil)){return errors.New("hostagent: retained copy content differs")};return nil
}
