using System.Reflection;
using System.Text;
using System.Globalization;
using TerraScale.Orchestrator.Contracts.Resources;

namespace TerraScale.Orchestrator.ModelTests;

/// <summary>Closed admitted-role and non-representability coverage for INV-017.</summary>
public sealed class ResourceContractTests
{
    [Test]
    public async Task MetadataValueObjectsProduceStableCanonicalProjection()
    {
        var first = Metadata();
        var second = Metadata();
        const string expected = "apiVersion=terrascale.io/orchestrator/v1|id=workload-platform|generation=2|" +
                                "resourceVersion=9|owner=RegionalController:gru-controller|" +
                                "createdBy=GitOps:release-controller|audit=reconcile-12345678";

        await Assert.That(first).IsEqualTo(second);
        await Assert.That(first.ToCanonicalString()).IsEqualTo(expected);
        await Assert.That(Encoding.UTF8.GetString(first.GetCanonicalDigestInput())).IsEqualTo(expected);
    }

    [Test]
    public async Task ApiVersionFailsClosedForEveryUnknownOrNoncanonicalValue()
    {
        await Assert.That(ApiVersion.Parse("terrascale.io/orchestrator/v1")).IsSameReferenceAs(ApiVersion.V1);
        foreach (var value in new[] { "", "v1", "terrascale.io/orchestrator/v2", "TERRASCALE.IO/ORCHESTRATOR/V1", " terrascale.io/orchestrator/v1" })
        {
            await Assert.That(Throws<ArgumentException>(() => ApiVersion.Parse(value))).IsTrue();
        }
    }

    [Test]
    public async Task CanonicalIdentifiersAreBoundedAndRejectDefaultLikeValues()
    {
        await Assert.That(new ResourceId("a").Value).IsEqualTo("a");
        await Assert.That(new ResourceId($"a{new string('1', 62)}").Value.Length).IsEqualTo(63);
        foreach (var value in new[] { "", "A", "a_1", "a/1", "-a", "a-", "a..b", $"a{new string('1', 63)}" })
        {
            await Assert.That(Throws<ArgumentException>(() => new ResourceId(value))).IsTrue();
        }

        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new Generation(0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new ResourceVersion(0))).IsTrue();
    }

    [Test]
    public async Task OwnershipCreationActorAndAuditIdRejectUnknownOrNoncanonicalValues()
    {
        var id = new ResourceId("controller");
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new ResourceOwnership((AuthorityKind)0, id))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new CreationActor((CreationActorKind)999, id))).IsTrue();
        await Assert.That(new AuditCorrelationId("operation-17").Value).IsEqualTo("operation-17");
        foreach (var value in new[] { "", "Operation-17", "operation/17", " operation-17", "operation-17 " })
        {
            await Assert.That(Throws<ArgumentException>(() => new AuditCorrelationId(value))).IsTrue();
        }
    }

    [Test]
    public async Task ClosedCatalogContainsExactlyEveryV1Role()
    {
        var roles = AllRoles();
        var expected = Enum.GetValues<RoleKind>();

        await Assert.That(roles.Count).IsEqualTo(expected.Length);
        await Assert.That(roles.Select(role => role.Kind).Order().ToArray()).IsEquivalentTo(expected);
        await Assert.That(roles.Select(role => role.Kind).Distinct().Count()).IsEqualTo(roles.Count);
    }

    [Test]
    public async Task UnresolvedImplementationsAreRequiredTaggedInputsWithNoConcreteDefault()
    {
        var metrics = new ApprovedImplementationCatalogKey(ImplementationDomain.MetricsStore, new("owner-selected-metrics"));
        var telemetry = new ApprovedImplementationCatalogKey(ImplementationDomain.RegionalTelemetry, new("owner-selected-telemetry"));
        var vpn = new ApprovedImplementationCatalogKey(ImplementationDomain.Vpn, new("owner-selected-vpn"));

        await Assert.That(new MetricsStoreRole(metrics).Implementation).IsSameReferenceAs(metrics);
        await Assert.That(new RegionalTelemetryAgentRole(telemetry).Implementation).IsSameReferenceAs(telemetry);
        await Assert.That(new VpnCoordinationRelayRole(vpn).Implementation).IsSameReferenceAs(vpn);
        await Assert.That(Throws<ArgumentException>(() => new MetricsStoreRole(vpn))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new RegionalTelemetryAgentRole(metrics))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new VpnCoordinationRelayRole(telemetry))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new ApprovedImplementationCatalogKey((ImplementationDomain)0, new("unknown")))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new ApprovedImplementationCatalogKey((ImplementationDomain)999, new("unknown")))).IsTrue();
        await Assert.That(typeof(ApprovedImplementationCatalogKey).GetConstructors()
            .SelectMany(constructor => constructor.GetParameters())
            .Any(parameter => parameter.ParameterType == typeof(string))).IsFalse();

        foreach (var type in new[] { typeof(MetricsStoreRole), typeof(RegionalTelemetryAgentRole), typeof(VpnCoordinationRelayRole) })
        {
            await Assert.That(type.GetConstructor(Type.EmptyTypes) is null).IsTrue();
        }

        foreach (var dangerous in new[] { "/usr/bin/tool", "image:latest", "https://packages.invalid/tool", "bash -c command" })
        {
            await Assert.That(Throws<ArgumentException>(() => new ResourceId(dangerous))).IsTrue();
        }
    }

    [Test]
    public async Task DescriptorDefensivelyCopiesAndStablyOrdersEveryCollection()
    {
        var runtimes = new List<RuntimeDriver> { RuntimeDriver.OciContainer, RuntimeDriver.NativeSystemd };
        var ports = new List<NetworkPort> { new(TransportProtocol.Udp, 9000), new(TransportProtocol.Tcp, 443) };
        var capabilities = new List<RoleCapability> { RoleCapability.TelemetryIngest, RoleCapability.PublicHttp };
        var volumes = new List<VolumePurpose> { VolumePurpose.TelemetrySpool, VolumePurpose.LogData };
        var secrets = new List<SecretProfileReference> { new(new("z-profile")), new(new("a-profile")) };
        var healthSignals = new List<HealthSignal> { HealthSignal.Readiness, HealthSignal.ProcessLiveness };
        var descriptor = Descriptor(runtimes, ports, capabilities, volumes, secrets, healthSignals);
        var before = descriptor.ToCanonicalString();

        runtimes.Clear(); ports.Clear(); capabilities.Clear(); volumes.Clear(); secrets.Clear(); healthSignals.Clear();

        await Assert.That(descriptor.AllowedRuntimes.Count).IsEqualTo(2);
        await Assert.That(descriptor.Ports.Count).IsEqualTo(2);
        await Assert.That(descriptor.Capabilities.Count).IsEqualTo(2);
        await Assert.That(descriptor.VolumePurposes.Count).IsEqualTo(2);
        await Assert.That(descriptor.SecretProfiles.Count).IsEqualTo(2);
        await Assert.That(descriptor.Health.Signals.Count).IsEqualTo(2);
        await Assert.That(descriptor.ToCanonicalString()).IsEqualTo(before);
    }

    [Test]
    public async Task PermutedDescriptorsHaveStructuralEqualityAndIdenticalDigestInput()
    {
        var first = Descriptor(
            [RuntimeDriver.NativeSystemd, RuntimeDriver.OciContainer],
            [new(TransportProtocol.Tcp, 443), new(TransportProtocol.Udp, 9000)],
            [RoleCapability.PublicHttp, RoleCapability.TelemetryIngest],
            [VolumePurpose.LogData, VolumePurpose.TelemetrySpool],
            [new(new("a-profile")), new(new("z-profile"))],
            [HealthSignal.ProcessLiveness, HealthSignal.Readiness]);
        var second = Descriptor(
            [RuntimeDriver.OciContainer, RuntimeDriver.NativeSystemd],
            [new(TransportProtocol.Udp, 9000), new(TransportProtocol.Tcp, 443)],
            [RoleCapability.TelemetryIngest, RoleCapability.PublicHttp],
            [VolumePurpose.TelemetrySpool, VolumePurpose.LogData],
            [new(new("z-profile")), new(new("a-profile"))],
            [HealthSignal.Readiness, HealthSignal.ProcessLiveness]);

        await Assert.That(first).IsEqualTo(second);
        await Assert.That(first.ToCanonicalString()).IsEqualTo(second.ToCanonicalString());
        await Assert.That(Convert.ToHexString(first.GetCanonicalDigestInput())).IsEqualTo(Convert.ToHexString(second.GetCanonicalDigestInput()));
        await Assert.That(first.GetHashCode()).IsEqualTo(second.GetHashCode());
        var invariantProjection = first.ToCanonicalString();
        var invariantDigestInput = Convert.ToHexString(first.GetCanonicalDigestInput());

        var originalCulture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            await Assert.That(first.ToCanonicalString()).IsEqualTo(invariantProjection);
            await Assert.That(Convert.ToHexString(first.GetCanonicalDigestInput())).IsEqualTo(invariantDigestInput);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
        }
    }

    [Test]
    public async Task DescriptorConstructionOrderingProjectionAndHashAreCultureIndependent()
    {
        var invariant = DescriptorUnderCulture(CultureInfo.InvariantCulture);
        var arabic = DescriptorUnderCulture(CultureInfo.GetCultureInfo("ar-SA"));
        var turkish = DescriptorUnderCulture(CultureInfo.GetCultureInfo("tr-TR"));

        await Assert.That(arabic.SecretProfiles.Select(profile => profile.ProfileId.Value).ToArray())
            .IsEquivalentTo(invariant.SecretProfiles.Select(profile => profile.ProfileId.Value).ToArray());
        await Assert.That(string.Join(',', arabic.SecretProfiles.Select(profile => profile.ProfileId.Value)))
            .IsEqualTo(string.Join(',', invariant.SecretProfiles.Select(profile => profile.ProfileId.Value)));
        await Assert.That(string.Join(',', turkish.SecretProfiles.Select(profile => profile.ProfileId.Value)))
            .IsEqualTo(string.Join(',', invariant.SecretProfiles.Select(profile => profile.ProfileId.Value)));
        await Assert.That(arabic.ToCanonicalString()).IsEqualTo(invariant.ToCanonicalString());
        await Assert.That(turkish.ToCanonicalString()).IsEqualTo(invariant.ToCanonicalString());
        await Assert.That(arabic.GetHashCode()).IsEqualTo(invariant.GetHashCode());
        await Assert.That(turkish.GetHashCode()).IsEqualTo(invariant.GetHashCode());
    }

    [Test]
    public async Task EveryDescriptorCollectionRejectsDuplicates()
    {
        await Assert.That(Throws<ArgumentException>(() => Descriptor(runtimes: [RuntimeDriver.NativeSystemd, RuntimeDriver.NativeSystemd]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Descriptor(ports: [new(TransportProtocol.Tcp, 443), new(TransportProtocol.Tcp, 443)]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Descriptor(capabilities: [RoleCapability.PublicHttp, RoleCapability.PublicHttp]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Descriptor(volumes: [VolumePurpose.LogData, VolumePurpose.LogData]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Descriptor(secrets: [new(new("profile")), new(new("profile"))]))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Descriptor(health: [HealthSignal.Readiness, HealthSignal.Readiness]))).IsTrue();
    }

    [Test]
    public async Task EveryPublicEnumInputRejectsUnknownAndDefaultValues()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new NetworkPort((TransportProtocol)0, 443))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new NetworkPort(TransportProtocol.Tcp, 0))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new HealthContract([(HealthSignal)0]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new PlacementConstraints(null, (FailureDomainSpread)0, false))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(runtimes: [(RuntimeDriver)0]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(runtimes: [(RuntimeDriver)999]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(capabilities: [(RoleCapability)0]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(capabilities: [(RoleCapability)999]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(volumes: [(VolumePurpose)0]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(volumes: [(VolumePurpose)999]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(health: [(HealthSignal)999]))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => new NetworkPort((TransportProtocol)999, 443))).IsTrue();
        await Assert.That(Throws<ArgumentOutOfRangeException>(() => Descriptor(scaling: (ScalingControllerOwner)0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => Descriptor(runtimes: []))).IsTrue();
    }

    [Test]
    public async Task ResourceBoundsRejectNegativeAndInvertedDimensions()
    {
        await Assert.That(Throws<ArgumentOutOfRangeException>(() =>
            new ResourceEnvelope(-1, 0, 0, 0, 0, 0, 0, 0))).IsTrue();
        await Assert.That(Throws<ArgumentException>(() => new ResourceBounds(
            new(2, 0, 0, 0, 0, 0, 0, 0), new(1, 0, 0, 0, 0, 0, 0, 0)))).IsTrue();
    }

    [Test]
    public async Task ReflectionProvesRoleUnionIsClosedAndEveryCaseIsSealed()
    {
        var baseConstructors = typeof(AdmittedRole).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic);
        var cases = typeof(AdmittedRole).Assembly.GetTypes()
            .Where(type => type.BaseType == typeof(AdmittedRole)).ToArray();

        await Assert.That(baseConstructors).IsNotEmpty();
        await Assert.That(baseConstructors.All(constructor => constructor.IsAssembly)).IsTrue();
        await Assert.That(baseConstructors.Any(constructor => constructor.IsPublic || constructor.IsFamily ||
                                                               constructor.IsFamilyOrAssembly)).IsFalse();
        await Assert.That(cases.Length).IsEqualTo(Enum.GetValues<RoleKind>().Length);
        await Assert.That(cases.All(type => type.IsSealed && type.IsPublic)).IsTrue();
    }

    [Test]
    public async Task ReflectionProvesDescriptorCannotRepresentDangerousExecutionOrPrivileges()
    {
        var forbiddenNames = new[]
        {
            "executable", "command", "argument", "image", "pulltag", "hostpath", "unittext",
            "systemddirective", "privileged", "linuxcapability", "natspermission", "permission",
        };
        var names = typeof(RoleDescriptor).GetMembers(BindingFlags.Instance | BindingFlags.Public)
            .Select(member => member.Name)
            .Concat(typeof(RoleDescriptor).GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                .SelectMany(constructor => constructor.GetParameters())
                .Select(parameter => parameter.Name ?? string.Empty))
            .Select(name => name.Replace("_", "", StringComparison.Ordinal).ToLowerInvariant())
            .ToArray();

        foreach (var forbidden in forbiddenNames)
        {
            await Assert.That(names.Any(name => name.Contains(forbidden, StringComparison.Ordinal))).IsFalse();
        }

        await Assert.That(typeof(RoleDescriptor).GetProperties().Any(property => property.PropertyType == typeof(string))).IsFalse();
        await Assert.That(typeof(RoleDescriptor).GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .SelectMany(constructor => constructor.GetParameters())
            .Any(parameter => parameter.ParameterType == typeof(string))).IsFalse();
        await Assert.That(typeof(AdmittedRole).Assembly.GetTypes()
            .Where(type => type.BaseType == typeof(AdmittedRole))
            .SelectMany(type => type.GetProperties(BindingFlags.Instance | BindingFlags.Public))
            .Any(property => property.PropertyType == typeof(string))).IsFalse();

        var forbiddenTypes = new[] { typeof(Type), typeof(Delegate), typeof(Action), typeof(Func<>), typeof(System.Diagnostics.Process) };
        var safeSurfaceTypes = new[]
        {
            typeof(RoleDescriptor), typeof(AdmittedRole), typeof(NetworkPort), typeof(HealthContract),
            typeof(PlacementConstraints), typeof(ResourceBounds), typeof(ResourceEnvelope),
            typeof(ApprovedImplementationCatalogKey), typeof(SecretProfileReference),
        }.Concat(typeof(AdmittedRole).Assembly.GetTypes().Where(type => type.BaseType == typeof(AdmittedRole)));
        var exposedTypes = safeSurfaceTypes.SelectMany(type => type.GetProperties(BindingFlags.Instance | BindingFlags.Public)
                .Select(property => property.PropertyType)
                .Concat(type.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
                    .SelectMany(constructor => constructor.GetParameters())
                    .Select(parameter => parameter.ParameterType)))
            .ToArray();
        await Assert.That(exposedTypes.Any(type => forbiddenTypes.Contains(type) ||
                                                   (type.IsGenericType && forbiddenTypes.Contains(type.GetGenericTypeDefinition())))).IsFalse();
        await Assert.That(exposedTypes.Any(IsStringCollection)).IsFalse();
    }

    [Test]
    public async Task ReflectionProvesExternalConsumersCannotSynthesizeDescriptors()
    {
        var publicConstructors = typeof(RoleDescriptor).GetConstructors(BindingFlags.Instance | BindingFlags.Public);
        var internalConstructors = typeof(RoleDescriptor).GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic);
        var publicFactories = typeof(RoleDescriptor).GetMethods(BindingFlags.Static | BindingFlags.Public)
            .Where(method => method.ReturnType == typeof(RoleDescriptor)).ToArray();

        await Assert.That(publicConstructors).IsEmpty();
        await Assert.That(internalConstructors).IsNotEmpty();
        await Assert.That(internalConstructors.All(constructor => constructor.IsAssembly)).IsTrue();
        await Assert.That(publicFactories).IsEmpty();
    }

    [Test]
    public async Task CanonicalDescriptorProjectionContainsReferencesNotSecretValues()
    {
        const string secretValue = "p@ss word\nprivate-key-bytes";
        await Assert.That(Throws<ArgumentException>(() => new ResourceId(secretValue))).IsTrue();
        var descriptor = Descriptor(secrets: [new(new("platform-identity-profile"))]);

        await Assert.That(descriptor.ToCanonicalString()).Contains("secrets=platform-identity-profile");
        await Assert.That(descriptor.ToCanonicalString()).DoesNotContain(secretValue);
        await Assert.That(typeof(SecretProfileReference).GetConstructors().SelectMany(constructor => constructor.GetParameters())
            .Any(parameter => parameter.ParameterType == typeof(string) || parameter.ParameterType == typeof(byte[]))).IsFalse();
    }

    private static ResourceMetadata Metadata() => new(
        ApiVersion.V1,
        new("workload-platform"),
        new(2),
        new(9),
        new(AuthorityKind.RegionalController, new("gru-controller")),
        new(CreationActorKind.GitOps, new("release-controller")),
        new("reconcile-12345678"));

    private static List<AdmittedRole> AllRoles() =>
    [
        new PlatformRole(), new AuthenticationRole(), new CustomerDashboardRole(), new TerraBaseMemberRole(),
        new OrchestratorRole(), new ControlNatsServerRole(), new ProductNatsServerRole(), new GrafanaRole(),
        new MetricsStoreRole(new(ImplementationDomain.MetricsStore, new("owner-selected-metrics"))),
        new LokiRole(), new TempoRole(), new AlertmanagerRole(), new OtlpIngestRole(), new SyntheticCheckRole(),
        new RegionalTelemetryAgentRole(new(ImplementationDomain.RegionalTelemetry, new("owner-selected-telemetry"))),
        new VpnCoordinationRelayRole(new(ImplementationDomain.Vpn, new("owner-selected-vpn"))),
        new RoutePolicyControllerRole(), new CiRunnerRole(),
    ];

    private static RoleDescriptor Descriptor(
        IEnumerable<RuntimeDriver>? runtimes = null,
        IEnumerable<NetworkPort>? ports = null,
        IEnumerable<RoleCapability>? capabilities = null,
        IEnumerable<VolumePurpose>? volumes = null,
        IEnumerable<SecretProfileReference>? secrets = null,
        IEnumerable<HealthSignal>? health = null,
        ScalingControllerOwner scaling = ScalingControllerOwner.Stateless) => new(
        ApiVersion.V1,
        new PlatformRole(),
        runtimes ?? [RuntimeDriver.OciContainer],
        ports ?? [new(TransportProtocol.Tcp, 443)],
        capabilities ?? [RoleCapability.PublicHttp],
        volumes ?? [],
        secrets ?? [new(new("platform-identity"))],
        new HealthContract(health ?? [HealthSignal.ApplicationLiveness, HealthSignal.Readiness]),
        new PlacementConstraints(new("compact"), FailureDomainSpread.PreferDistinct, false),
        scaling,
        new ResourceBounds(new(1, 1, 0, 0, 1, 1, 1, 0), new(8, 16, 8, 32, 8, 1024, 4096, 0)));

    private static RoleDescriptor DescriptorUnderCulture(CultureInfo culture)
    {
        var original = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = culture;
            return Descriptor(
                ports: [new(TransportProtocol.Udp, 9000), new(TransportProtocol.Tcp, 443)],
                secrets: [new(new("z-profile")), new(new("a.z-profile")), new(new("a-profile")), new(new("az-profile"))]);
        }
        finally
        {
            CultureInfo.CurrentCulture = original;
        }
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static bool IsStringCollection(Type type)
    {
        if (type == typeof(string))
        {
            return false;
        }

        if (type.IsArray)
        {
            return type.GetElementType() == typeof(string);
        }

        return type.GetInterfaces().Append(type).Any(candidate => candidate.IsGenericType &&
            candidate.GetGenericTypeDefinition() == typeof(IEnumerable<>) &&
            candidate.GetGenericArguments()[0] == typeof(string));
    }
}
