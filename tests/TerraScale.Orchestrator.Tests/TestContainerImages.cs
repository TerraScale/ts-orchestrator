namespace TerraScale.Orchestrator.Tests;

/// <summary>
/// Digest-pinned container images used by test-owned Podman fixtures. Mirrors the repository
/// validation limits: owned lab processes may use at most 20 GiB of the 24 GiB aggregate cap.
/// </summary>
internal static class TestContainerImages
{
    public const string Nats = "docker.io/library/nats@sha256:a42e284980d105c1b668d553175b4c7abc9b7187c5e9859baf4f1d564772b85f";
}

internal static class TestValidationLimits
{
    public const long PodMemoryLimitBytes = 20L * 1024 * 1024 * 1024;
}
