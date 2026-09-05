package initialcontrol

import (
	"sort"
)

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
