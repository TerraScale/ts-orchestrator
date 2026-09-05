package initialcontrol

import (
	"sort"
)

// SnapshotPermissions authorizes the public snapshot transport for exactly the
// retained profile. Chunk acknowledgements are scoped to each admitted stream;
// no provisioner, application, consumer mutation, or election subjects are added.
func SnapshotPermissions(cell, instance string, global bool) (publish, subscribe []string, err error) {
	p, err := buildProfiles(cell, instance)
	if err != nil {
		return nil, nil, err
	}
	profile := p.Regional
	if global {
		profile = p.Global
	}
	// Account inventory enumeration detects streams outside the admitted
	// profile; it does not grant snapshot or message access to those streams.
	publish = []string{"$JS.API.STREAM.NAMES"}
	names := make([]string, 0, len(profile.Streams)+len(profile.KV)+len(profile.Objects))
	for _, stream := range profile.Streams {
		names = append(names, stream.Name)
	}
	for _, bucket := range profile.KV {
		names = append(names, "KV_"+bucket.Bucket)
	}
	for _, bucket := range profile.Objects {
		names = append(names, "OBJ_"+bucket.Bucket)
	}
	for _, name := range names {
		publish = append(publish, "$JS.API.STREAM.INFO."+name, "$JS.API.STREAM.SNAPSHOT."+name, "$JS.SNAPSHOT.ACK."+name+".>", "$JS.API.CONSUMER.NAMES."+name, "$JS.API.CONSUMER.INFO."+name+".*")
	}
	sort.Strings(publish)
	return publish, []string{"_INBOX.>"}, nil
}

// Permissions returns the closed NKey permissions for this temporary runtime.
// Provisioner connections are closed before either authority worker starts.
func Permissions(cell, instance string, global, provisioner bool) (publish, subscribe []string, err error) {
	p, err := buildProfiles(cell, instance)
	if err != nil {
		return nil, nil, err
	}
	if provisioner {
		return []string{"$JS.API.>", "$KV.>", "$O.>"}, []string{"_INBOX.>"}, nil
	}
	profile := p.Regional
	if global {
		profile = p.Global
	}
	publish = []string{"$JS.API.INFO"}
	for _, s := range profile.Streams {
		publish = append(publish, "$JS.API.STREAM.INFO."+s.Name)
	}
	for _, s := range profile.KV {
		name := "KV_" + s.Bucket
		publish = append(publish, "$JS.API.STREAM.INFO."+name, "$JS.API.STREAM.MSG.GET."+name, "$JS.API.DIRECT.GET."+name, "$JS.API.DIRECT.GET."+name+".>")
	}
	for _, s := range profile.Objects {
		publish = append(publish, "$JS.API.STREAM.INFO.OBJ_"+s.Bucket)
	}
	for _, c := range profile.Consumers {
		publish = append(publish, "$JS.API.CONSUMER.INFO."+c.Stream+".*")
	}
	key := "authority.regional"
	if global {
		key = "authority.global"
	}
	publish = append(publish, "$KV.ORCH_LEADERS."+key)
	if !global {
		publish = append(publish, "$KV.ORCH_RUNTIME.controller."+instance, "$JS.API.CONSUMER.CREATE.KV_ORCH_RUNTIME.>", "$JS.API.CONSUMER.DELETE.KV_ORCH_RUNTIME.*", "$JS.API.CONSUMER.INFO.KV_ORCH_RUNTIME.*", "$JS.API.CONSUMER.MSG.NEXT.KV_ORCH_RUNTIME.*")
	}
	sort.Strings(publish)
	return publish, []string{"_INBOX.>"}, nil
}
