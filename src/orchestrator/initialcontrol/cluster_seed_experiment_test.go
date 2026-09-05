package initialcontrol

import (
 "context"
 "fmt"
 "path/filepath"
 "reflect"
 "testing"
 "time"

 "github.com/nats-io/nats.go/jetstream"
)

// Bounded experiment: cluster identity exists before any R1 stream.
func TestClusterSeedExperiment(t *testing.T) {
 ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second); defer cancel()
 brokers := make([]*profilePromotionBroker, 3)
 for i, name := range []string{"GRU_SOURCE", "SFO_PEER", "FRA_PEER"} {
  brokers[i] = &profilePromotionBroker{name:name, store:filepath.Join(t.TempDir(),"store"),port:profilePromotionPort(t),route:profilePromotionPort(t)}
  defer brokers[i].stop()
 }
 source := brokers[0]
 // Distinct helper pointer allows an explicit route to this server itself.
 self := &profilePromotionBroker{route:source.route}
 source.start(t,true,[]*profilePromotionBroker{self},1<<30)
 profilePromotionWait(t,"single-member metadata leader",func()bool { j,e:=source.s.Jsz(nil); return e==nil && j.Meta!=nil && j.Meta.Size==1 && j.Meta.Leader==source.name })
 t.Log("single GRU clustered metadata peer ready with self route")
 nc, js := source.client(t,"GLOBAL_CONTROL")
 stream,e:=js.CreateStream(ctx,jetstream.StreamConfig{Name:"PROMOTION",Subjects:[]string{"promotion"},Replicas:1,Storage:jetstream.FileStorage}); if e!=nil { t.Fatal(e) }
 for i:=0;i<3;i++ { if _,e=js.Publish(ctx,"promotion",[]byte(fmt.Sprintf("record-%d",i)));e!=nil {t.Fatal(e)} }
 consumer,e:=stream.CreateOrUpdateConsumer(ctx,jetstream.ConsumerConfig{Durable:"CHECKPOINT",AckPolicy:jetstream.AckExplicitPolicy,AckWait:time.Hour,Replicas:1});if e!=nil{t.Fatal(e)}
 batch,e:=consumer.Fetch(2,jetstream.FetchMaxWait(time.Second));if e!=nil{t.Fatal(e)}
 i:=0;for msg:=range batch.Messages(){if i==0 {if e=msg.DoubleAck(ctx);e!=nil{t.Fatal(e)}};i++};if batch.Error()!=nil||i!=2{t.Fatalf("fetch %d %v",i,batch.Error())}
 before,e:=stream.Info(ctx);if e!=nil{t.Fatal(e)}
 cbefore,e:=consumer.Info(ctx);if e!=nil{t.Fatal(e)}
 records:=make([]*jetstream.RawStreamMsg,3)
 for i:=range records{records[i],e=stream.GetMsg(ctx,uint64(i+1));if e!=nil{t.Fatal(e)}}
 brokers[1].start(t,true,brokers,1<<30);brokers[2].start(t,true,brokers,1<<30)
 profilePromotionWait(t,"three metadata peers",func()bool{j,e:=source.s.Jsz(nil);return e==nil&&j.Meta!=nil&&j.Meta.Size==3&&j.Meta.Leader!=""})
 config:=before.Config;config.Replicas=3;stream,e=js.UpdateStream(ctx,config);if e!=nil{t.Fatal(e)}
 cc:=cbefore.Config;cc.Replicas=3;consumer,e=stream.CreateOrUpdateConsumer(ctx,cc);if e!=nil{t.Fatal(e)}
 verify:=func()bool{
  si,se:=stream.Info(ctx);ci,ce:=consumer.Info(ctx)
  if se!=nil||ce!=nil||si.Cluster==nil||ci.Cluster==nil||len(si.Cluster.Replicas)!=2||len(ci.Cluster.Replicas)!=2{return false}
  for _,r:=range si.Cluster.Replicas{if !r.Current||r.Offline{return false}};for _,r:=range ci.Cluster.Replicas{if !r.Current||r.Offline{return false}}
  if !si.Created.Equal(before.Created)||!ci.Created.Equal(cbefore.Created)||!reflect.DeepEqual(si.State,before.State)||ci.Delivered.Consumer!=cbefore.Delivered.Consumer||ci.Delivered.Stream!=cbefore.Delivered.Stream||ci.AckFloor.Consumer!=cbefore.AckFloor.Consumer||ci.AckFloor.Stream!=cbefore.AckFloor.Stream||ci.NumAckPending!=cbefore.NumAckPending||ci.NumPending!=cbefore.NumPending {t.Errorf("identity/state mismatch streamCreated=%v consumerCreated=%v state=%v/%v checkpoints=%+v/%+v",si.Created.Equal(before.Created),ci.Created.Equal(cbefore.Created),si.State,before.State,ci,cbefore);return false}
  for i,want:=range records{got,e:=stream.GetMsg(ctx,uint64(i+1));if e!=nil{return false};if !reflect.DeepEqual(got,want){t.Errorf("record changed %d",i);return false}}
  return true
 }
 profilePromotionWait(t,"promoted exact records/checkpoints/Created",verify)
 t.Logf("R3 promotion preserves Created stream=%s consumer=%s, records=3 delivered=%d ackFloor=%d pendingAcks=%d",before.Created,cbefore.Created,cbefore.Delivered.Consumer,cbefore.AckFloor.Consumer,cbefore.NumAckPending)
 nc.Close();for _,b:=range brokers{b.stop()};for _,b:=range brokers{b.start(t,true,brokers,1<<30)}
 _,js=source.client(t,"GLOBAL_CONTROL")
 profilePromotionWait(t,"restart stream available",func()bool{var e error;stream,e=js.Stream(ctx,"PROMOTION");return e==nil})
 profilePromotionWait(t,"restart consumer available",func()bool{var e error;consumer,e=stream.Consumer(ctx,"CHECKPOINT");return e==nil})
 profilePromotionWait(t,"restarted exact records/checkpoints/Created",verify)
 t.Log("full three-broker restart preserves exact records/checkpoints/Created")
}
