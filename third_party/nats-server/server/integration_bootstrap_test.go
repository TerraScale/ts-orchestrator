// Copyright 2016-2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"flag"
	"os"
	"testing"
)

// https://github.com/golang/go/issues/31859
func TestMain(m *testing.M) {
	flag.StringVar(&testDefaultClusterCompression, "cluster_compression", _EMPTY_, "Test with this compression level as the default")
	flag.StringVar(&testDefaultLeafNodeCompression, "leafnode_compression", _EMPTY_, "Test with this compression level as the default")
	flag.Parse()
	initSublist := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "test.bench" {
			initSublist = true
		}
	})
	if initSublist {
		benchSublistSubs = make([]*subscription, 0, 256*1024)
		toks := []string{"synadia", "nats", "jetstream", "nkeys", "jwt", "deny", "auth", "drain"}
		subsInit("", toks)
		for i := 0; i < len(benchSublistSubs); i++ {
			benchSublistSl.Insert(benchSublistSubs[i])
		}
		addWildcards()
	}
	os.Exit(m.Run())
}
