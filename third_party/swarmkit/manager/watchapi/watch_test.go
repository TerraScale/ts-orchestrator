package watchapi

import (
	"context"
	"testing"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/state/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatch(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Stop()

	ctx := context.Background()

	// Watch for node creates
	watch, err := ts.Client.Watch(ctx, &api.WatchRequest{
		Entries: []*api.WatchRequest_WatchEntry{
			{
				Kind:   "node",
				Action: api.WatchActionKindCreate,
			},
		},
	})
	assert.NoError(t, err)

	// Should receive an initial message that indicates the watch is ready
	msg, err := watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, &api.WatchMessage{}, msg)

	createNode(t, ts, "id1", api.NodeRoleManager, api.NodeMembershipAccepted, api.NodeStatus_READY)
	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindCreate, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id1", msg.Events[0].Object.GetNode().ID)

	watch.CloseSend()

	// Watch for node creates that match a name prefix and a custom index, or
	// are managers
	watch, err = ts.Client.Watch(ctx, &api.WatchRequest{
		Entries: []*api.WatchRequest_WatchEntry{
			{
				Kind:   "node",
				Action: api.WatchActionKindCreate,
				Filters: []*api.SelectBy{
					{
						By: &api.SelectBy_NamePrefix{
							NamePrefix: "east",
						},
					},
					{
						By: &api.SelectBy_Custom{
							Custom: &api.SelectByCustom{
								Index: "myindex",
								Value: "myval",
							},
						},
					},
				},
			},
			{
				Kind:   "node",
				Action: api.WatchActionKindCreate,
				Filters: []*api.SelectBy{
					{
						By: &api.SelectBy_Role{
							Role: api.NodeRoleManager,
						},
					},
				},
			},
		},
	})
	assert.NoError(t, err)

	// Should receive an initial message that indicates the watch is ready
	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, &api.WatchMessage{}, msg)

	createNode(t, ts, "id2", api.NodeRoleManager, api.NodeMembershipAccepted, api.NodeStatus_READY)
	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindCreate, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id2", msg.Events[0].Object.GetNode().ID)

	// Shouldn't be seen by the watch
	createNode(t, ts, "id3", api.NodeRoleWorker, api.NodeMembershipAccepted, api.NodeStatus_READY)

	// Shouldn't be seen either - no hostname
	node := &api.Node{
		ID: "id4",
		Spec: api.NodeSpec{
			Annotations: api.Annotations{
				Indices: []api.IndexEntry{
					{Key: "myindex", Val: "myval"},
				},
			},
		},
		Role: api.NodeRoleWorker,
	}
	err = ts.Store.Update(func(tx store.Tx) error {
		return store.CreateNode(tx, node)
	})
	assert.NoError(t, err)

	// Shouldn't be seen either - hostname doesn't match filter
	node = &api.Node{
		ID: "id5",
		Description: &api.NodeDescription{
			Hostname: "west-40",
		},
		Spec: api.NodeSpec{
			Annotations: api.Annotations{
				Indices: []api.IndexEntry{
					{Key: "myindex", Val: "myval"},
				},
			},
		},
		Role: api.NodeRoleWorker,
	}
	err = ts.Store.Update(func(tx store.Tx) error {
		return store.CreateNode(tx, node)
	})
	assert.NoError(t, err)

	// This one should be seen
	node = &api.Node{
		ID: "id6",
		Description: &api.NodeDescription{
			Hostname: "east-95",
		},
		Spec: api.NodeSpec{
			Annotations: api.Annotations{
				Indices: []api.IndexEntry{
					{Key: "myindex", Val: "myval"},
				},
			},
		},
		Role: api.NodeRoleWorker,
	}
	err = ts.Store.Update(func(tx store.Tx) error {
		return store.CreateNode(tx, node)
	})
	assert.NoError(t, err)

	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindCreate, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id6", msg.Events[0].Object.GetNode().ID)

	watch.CloseSend()
}

func TestWatchMultipleActions(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Stop()

	ctx := context.Background()

	// Watch for node creates
	watch, err := ts.Client.Watch(ctx, &api.WatchRequest{
		Entries: []*api.WatchRequest_WatchEntry{
			{
				Kind:   "node",
				Action: api.WatchActionKindCreate | api.WatchActionKindRemove,
			},
		},
	})
	assert.NoError(t, err)

	// Should receive an initial message that indicates the watch is ready
	msg, err := watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, &api.WatchMessage{}, msg)

	createNode(t, ts, "id1", api.NodeRoleManager, api.NodeMembershipAccepted, api.NodeStatus_READY)
	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindCreate, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id1", msg.Events[0].Object.GetNode().ID)

	// Update should not be seen
	err = ts.Store.Update(func(tx store.Tx) error {
		node := store.GetNode(tx, "id1")
		require.NotNil(t, node)
		node.Role = api.NodeRoleWorker
		return store.UpdateNode(tx, node)
	})
	assert.NoError(t, err)

	// Delete should be seen
	err = ts.Store.Update(func(tx store.Tx) error {
		return store.DeleteNode(tx, "id1")
	})
	assert.NoError(t, err)
	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindRemove, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id1", msg.Events[0].Object.GetNode().ID)

	watch.CloseSend()
}

func TestWatchIncludeOldObject(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Stop()

	ctx := context.Background()

	// Watch for node updates
	watch, err := ts.Client.Watch(ctx, &api.WatchRequest{
		Entries: []*api.WatchRequest_WatchEntry{
			{
				Kind:   "node",
				Action: api.WatchActionKindUpdate,
			},
		},
		IncludeOldObject: true,
	})
	assert.NoError(t, err)

	// Should receive an initial message that indicates the watch is ready
	msg, err := watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, &api.WatchMessage{}, msg)

	createNode(t, ts, "id1", api.NodeRoleManager, api.NodeMembershipAccepted, api.NodeStatus_READY)

	err = ts.Store.Update(func(tx store.Tx) error {
		node := store.GetNode(tx, "id1")
		require.NotNil(t, node)
		node.Role = api.NodeRoleWorker
		return store.UpdateNode(tx, node)
	})
	assert.NoError(t, err)

	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindUpdate, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id1", msg.Events[0].Object.GetNode().ID)
	assert.Equal(t, api.NodeRoleWorker, msg.Events[0].Object.GetNode().Role)
	require.NotNil(t, msg.Events[0].OldObject.GetNode())
	assert.Equal(t, "id1", msg.Events[0].OldObject.GetNode().ID)
	assert.Equal(t, api.NodeRoleManager, msg.Events[0].OldObject.GetNode().Role)

	watch.CloseSend()

	clusterCtx, stopClusterWatch := context.WithCancel(t.Context())
	defer stopClusterWatch()
	entries := []*api.WatchRequest_WatchEntry{{Kind: "cluster", Action: api.WatchActionKindCreate | api.WatchActionKindUpdate | api.WatchActionKindRemove}}
	resumeFrom := msg.Version
	watch, err = ts.Client.Watch(clusterCtx, &api.WatchRequest{Entries: entries, IncludeOldObject: true})
	require.NoError(t, err)
	msg, err = watch.Recv()
	require.NoError(t, err)
	assert.Equal(t, &api.WatchMessage{}, msg)
	cluster := &api.Cluster{
		ID: "cluster1",
		Spec: api.ClusterSpec{
			Annotations: api.Annotations{Name: store.DefaultClusterName, Labels: map[string]string{"revision": "first"}},
			CAConfig:    api.CAConfig{SigningCACert: []byte("signing-cert"), SigningCAKey: []byte("signing-key")},
		},
		RootCA: api.RootCA{CACert: []byte("public-ca"), CAKey: []byte("private-ca"),
			RootRotation: &api.RootRotation{CACert: []byte("public-next-ca"), CAKey: []byte("private-next-ca"), CrossSignedCACert: []byte("public-cross-cert")}},
		NetworkBootstrapKeys: []*api.EncryptionKey{{Key: []byte("network-key")}},
		UnlockKeys:           []*api.EncryptionKey{{Key: []byte("unlock-key")}},
		DefaultAddressPool:   []string{"10.42.0.0/16"}, SubnetSize: 24, VXLANUDPPort: 4789,
	}
	assertPublicCluster := func(object *api.Object, revision string) {
		t.Helper()
		public := object.GetCluster()
		require.NotNil(t, public)
		assert.Equal(t, cluster.ID, public.ID)
		assert.Equal(t, store.DefaultClusterName, public.Spec.Annotations.Name)
		assert.Equal(t, revision, public.Spec.Annotations.Labels["revision"])
		assert.Equal(t, cluster.DefaultAddressPool, public.DefaultAddressPool)
		assert.Equal(t, cluster.SubnetSize, public.SubnetSize)
		assert.Equal(t, cluster.VXLANUDPPort, public.VXLANUDPPort)
		assert.Equal(t, cluster.RootCA.CACert, public.RootCA.CACert)
		require.NotNil(t, public.RootCA.RootRotation)
		assert.Equal(t, cluster.RootCA.RootRotation.CACert, public.RootCA.RootRotation.CACert)
		assert.Equal(t, cluster.RootCA.RootRotation.CrossSignedCACert, public.RootCA.RootRotation.CrossSignedCACert)
		assert.Empty(t, public.Spec.CAConfig.SigningCACert)
		assert.Empty(t, public.Spec.CAConfig.SigningCAKey)
		assert.Empty(t, public.RootCA.CAKey)
		assert.Empty(t, public.RootCA.RootRotation.CAKey)
		assert.Empty(t, public.NetworkBootstrapKeys)
		assert.Empty(t, public.UnlockKeys)
	}
	require.NoError(t, ts.Store.Update(func(tx store.Tx) error { return store.CreateCluster(tx, cluster) }))
	msg, err = watch.Recv()
	require.NoError(t, err)
	require.Len(t, msg.Events, 1)
	assert.Equal(t, api.WatchActionKindCreate, msg.Events[0].Action)
	assert.Nil(t, msg.Events[0].OldObject)
	assertPublicCluster(msg.Events[0].Object, "first")
	versions := []*api.Version{msg.Version}
	var privateCurrent *api.Cluster
	require.NoError(t, ts.Store.Update(func(tx store.Tx) error {
		current := store.GetCluster(tx, cluster.ID)
		require.NotNil(t, current)
		current.Spec.Annotations.Labels["revision"] = "next"
		current.RootCA.CAKey = []byte("renewed-private-ca")
		if err := store.UpdateCluster(tx, current); err != nil {
			return err
		}
		privateCurrent = current.Copy()
		return nil
	}))
	msg, err = watch.Recv()
	require.NoError(t, err)
	require.Len(t, msg.Events, 1)
	assert.Equal(t, api.WatchActionKindUpdate, msg.Events[0].Action)
	assertPublicCluster(msg.Events[0].Object, "next")
	assertPublicCluster(msg.Events[0].OldObject, "first")
	versions = append(versions, msg.Version)
	ts.Store.View(func(tx store.ReadTx) { assert.Equal(t, privateCurrent, store.GetCluster(tx, cluster.ID)) })
	require.NoError(t, ts.Store.Update(func(tx store.Tx) error { return store.DeleteCluster(tx, cluster.ID) }))
	msg, err = watch.Recv()
	require.NoError(t, err)
	require.Len(t, msg.Events, 1)
	assert.Equal(t, api.WatchActionKindRemove, msg.Events[0].Action)
	assert.Nil(t, msg.Events[0].OldObject)
	assertPublicCluster(msg.Events[0].Object, "next")
	versions = append(versions, msg.Version)
	watch.CloseSend()

	watch, err = ts.Client.Watch(clusterCtx, &api.WatchRequest{Entries: entries, ResumeFrom: resumeFrom})
	require.NoError(t, err)
	msg, err = watch.Recv()
	require.NoError(t, err)
	assert.Equal(t, &api.WatchMessage{}, msg)
	for i, action := range []api.WatchActionKind{api.WatchActionKindCreate, api.WatchActionKindUpdate, api.WatchActionKindRemove} {
		msg, err = watch.Recv()
		require.NoError(t, err)
		require.Len(t, msg.Events, 1)
		assert.Equal(t, action, msg.Events[0].Action)
		assert.Equal(t, versions[i], msg.Version)
		assert.Nil(t, msg.Events[0].OldObject)
		revision := "next"
		if action == api.WatchActionKindCreate {
			revision = "first"
		}
		assertPublicCluster(msg.Events[0].Object, revision)
	}
	watch.CloseSend()
}

func TestWatchResumeFrom(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Stop()

	ctx := context.Background()

	createNode(t, ts, "id1", api.NodeRoleManager, api.NodeMembershipAccepted, api.NodeStatus_READY)
	node2 := createNode(t, ts, "id2", api.NodeRoleManager, api.NodeMembershipAccepted, api.NodeStatus_READY)

	// Watch for node creates, starting from after the first node creation.
	watch, err := ts.Client.Watch(ctx, &api.WatchRequest{
		Entries: []*api.WatchRequest_WatchEntry{
			{
				Kind:   "node",
				Action: api.WatchActionKindCreate,
			},
		},
		ResumeFrom: &node2.Meta.Version,
	})
	assert.NoError(t, err)

	// Should receive an initial message that indicates the watch is ready
	msg, err := watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, &api.WatchMessage{}, msg)

	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindCreate, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id2", msg.Events[0].Object.GetNode().ID)
	assert.Equal(t, node2.Meta.Version.Index+3, msg.Version.Index)

	// Create a new node
	node3 := createNode(t, ts, "id3", api.NodeRoleManager, api.NodeMembershipAccepted, api.NodeStatus_READY)

	msg, err = watch.Recv()
	assert.NoError(t, err)
	assert.Equal(t, api.WatchActionKindCreate, msg.Events[0].Action)
	require.NotNil(t, msg.Events[0].Object.GetNode())
	assert.Equal(t, "id3", msg.Events[0].Object.GetNode().ID)
	assert.Equal(t, node3.Meta.Version.Index+3, msg.Version.Index)

	watch.CloseSend()
}
