#!/usr/bin/env dotnet run
#:include check-nuget-vulnerabilities.lib.cs

return TerraScale.Ci.CheckNugetVulnerabilities.Run(args);
