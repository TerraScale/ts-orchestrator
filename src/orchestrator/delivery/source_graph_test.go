package delivery

import "testing"

func TestParseDeployDescriptor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		content          string
		wantErr          bool
		wantDependencies int
	}{
		{
			name: "current",
			content: `{
				"repository":"TerraScale/current",
				"dependencies":[{"source":"src/","target":"test","reason":"source changes require tests"}],
				"prProfiles":[{"name":"test","resourceWeight":"heavy","commands":[{"description":"test","command":"go","arguments":["test","./..."]}]}],
				"releaseProfiles":[],
				"buildTargets":[],
				"candidate":{"genericPackageName":"candidate","retentionDays":7},
				"promotion":{"strategy":"package","endpoints":[]},
				"services":[]
			}`,
		},
		{name: "profile object", content: `{"repository":"TerraScale/current","prProfiles":{}}`, wantErr: true},
		{name: "malformed dependency edge", content: `{"repository":"TerraScale/current","dependencies":[{"source":"src/","target":"test"}]}`, wantErr: true},
		{name: "dependency edge wrong type", content: `{"repository":"TerraScale/current","dependencies":["src/"]}`, wantErr: true},
		{name: "duplicate nested member", content: `{"repository":"TerraScale/current","prProfiles":[{"name":"static","name":"build"}]}`, wantErr: true},
		{name: "case-insensitive duplicate member", content: `{"repository":"TerraScale/current","prProfiles":[{"name":"static","NAME":"build"}]}`, wantErr: true},
		{name: "unknown nested member", content: `{"repository":"TerraScale/current","prProfiles":[{"name":"static","unexpected":true}]}`, wantErr: true},
		{name: "unknown member", content: `{"repository":"TerraScale/current","schemaVersion":9}`, wantErr: true},
		{name: "case-insensitive top-level duplicate", content: `{"repository":"TerraScale/current","REPOSITORY":"TerraScale/other"}`, wantErr: true},
		{name: "retired schema", content: `{"apiVersion":"terrascale.ci/v3","repository":"TerraScale/current","nodes":[]}`, wantErr: true},
		{name: "ordinary build target may omit output", content: `{"repository":"TerraScale/current","buildTargets":[{"name":"artifact","commands":[{"description":"build","command":"go","arguments":["build"]}]}]}`},
		{name: "unsafe build output", content: `{"repository":"TerraScale/current","buildTargets":[{"name":"artifact","outputPath":"artifacts/../escape","commands":[{"description":"build","command":"go","arguments":["build"]}]}]}`, wantErr: true},
		{name: "invalid resource weight", content: `{"repository":"TerraScale/current","prProfiles":[{"name":"static","resourceWeight":"urgent","commands":[{"description":"static","command":"go","arguments":[]}]}]}`, wantErr: true},
		{name: "candidate release binds output", content: `{"repository":"TerraScale/current","releaseProfiles":[{"name":"release","candidateTarget":"artifact","entrypoint":"tests/run","arguments":[],"minimumExpectedTests":1}],"buildTargets":[{"name":"artifact","outputPath":"artifacts/candidate/artifact","commands":[{"description":"build","command":"go","arguments":["build"]}]}]}`},
		{name: "candidate release target missing", content: `{"repository":"TerraScale/current","releaseProfiles":[{"name":"release","candidateTarget":"missing","entrypoint":"tests/run","arguments":[],"minimumExpectedTests":1}]}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository, dependencies, err := parseDescriptor([]byte(test.content))
			if (err != nil) != test.wantErr {
				t.Fatalf("parseDescriptor() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil {
				if repository != "TerraScale/current" {
					t.Fatalf("parseDescriptor() repository = %q", repository)
				}
				if len(dependencies) != test.wantDependencies {
					t.Fatalf("parseDescriptor() dependencies = %v, want %d repository dependencies", dependencies, test.wantDependencies)
				}
			}
		})
	}
}

func TestParseDeployDescriptorRejectsExcessiveNesting(t *testing.T) {
	t.Parallel()
	content := `{"repository":"TerraScale/current","services":`
	for i := 0; i < maximumDeployDescriptorDepth+1; i++ {
		content += `[`
	}
	content += `{}`
	for i := 0; i < maximumDeployDescriptorDepth+1; i++ {
		content += `]`
	}
	content += `}`
	if _, _, err := parseDescriptor([]byte(content)); err == nil {
		t.Fatal("parseDescriptor() accepted a descriptor deeper than the Deploy JSON bound")
	}
}

func TestCIDescriptorPathUsesDeployConfiguration(t *testing.T) {
	t.Parallel()
	if CIDescriptorPath != ".terrascale/deploy.json" {
		t.Fatalf("CIDescriptorPath = %q", CIDescriptorPath)
	}
}
