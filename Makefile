.PHONY: check build test publish

SOLUTION ?= TerraScale.Orchestrator.slnx
CONFIGURATION ?= Release

check: build test

build:
	nice -n 19 dotnet build "$(SOLUTION)" --configuration "$(CONFIGURATION)" --nologo

test:
	nice -n 19 dotnet test "$(SOLUTION)" --configuration "$(CONFIGURATION)" --no-build

publish:
	nice -n 19 dotnet publish src/TerraScale.Orchestrator/TerraScale.Orchestrator.csproj --configuration "$(CONFIGURATION)" --nologo
