namespace TsOrch.Agent;

internal static partial class AgentLog
{
    [LoggerMessage(1000, LogLevel.Information, "Placement {PlacementId} ready on {Image} ({ConfigHash}) host port {HostPort}")]
    public static partial void PlacementReady(this ILogger logger, string placementId, string image, string configHash, int? hostPort);

    [LoggerMessage(1001, LogLevel.Warning, "Edge routes did not switch placement {PlacementId} to port {HostPort} in time; retiring previous container anyway")]
    public static partial void RouteSwitchTimedOut(this ILogger logger, string placementId, int hostPort);

    [LoggerMessage(1002, LogLevel.Warning, "Edge routes still referenced placement {PlacementId} after the drain window")]
    public static partial void RouteDrainTimedOut(this ILogger logger, string placementId);

    [LoggerMessage(1003, LogLevel.Error, "Placement {PlacementId} on {Image} failed: {Reason}")]
    public static partial void PlacementFailed(this ILogger logger, string placementId, string image, string reason);

    [LoggerMessage(1004, LogLevel.Information, "Swapping placement {PlacementId} to {Image} ({ConfigHash}), stop-start {StopStart}")]
    public static partial void PlacementSwapping(this ILogger logger, string placementId, string image, string configHash, bool stopStart);

    [LoggerMessage(1005, LogLevel.Information, "Retiring placement {PlacementId} removed from desired state")]
    public static partial void PlacementRetiring(this ILogger logger, string placementId);

    [LoggerMessage(1006, LogLevel.Warning, "Ignoring desired revision {Revision} older than {Current}")]
    public static partial void StaleDesiredIgnored(this ILogger logger, long revision, long current);

    [LoggerMessage(1007, LogLevel.Information, "Secret refresh requested for {ServiceName} ({Placements} placements)")]
    public static partial void SecretRefreshRequested(this ILogger logger, string serviceName, int placements);

    [LoggerMessage(1008, LogLevel.Error, "Listing managed containers failed: {Reason}")]
    public static partial void ReconcileListFailed(this ILogger logger, string reason);

    [LoggerMessage(1009, LogLevel.Warning, "Secrets for placement {PlacementId} unavailable; keeping the running container: {Reason}")]
    public static partial void SecretResolveDeferred(this ILogger logger, string placementId, string reason);

    [LoggerMessage(1100, LogLevel.Warning, "Image GC failed: {Reason}")]
    public static partial void ImageGcFailed(this ILogger logger, string reason);

    [LoggerMessage(1101, LogLevel.Information, "Image GC removed {ImageId}")]
    public static partial void ImageRemoved(this ILogger logger, string imageId);

    [LoggerMessage(1102, LogLevel.Debug, "Image GC kept {ImageId}: {Reason}")]
    public static partial void ImageRemovalSkipped(this ILogger logger, string imageId, string reason);

    [LoggerMessage(1200, LogLevel.Warning, "Edge metrics file {Path} is unreadable: {Reason}")]
    public static partial void EdgeMetricsUnreadable(this ILogger logger, string path, string reason);

    [LoggerMessage(1201, LogLevel.Debug, "Stats for container {ContainerId} unavailable: {Reason}")]
    public static partial void ContainerStatsUnavailable(this ILogger logger, string containerId, string reason);

    [LoggerMessage(1300, LogLevel.Information, "Drain started: {Reason}")]
    public static partial void DrainStarted(this ILogger logger, string reason);

    [LoggerMessage(1301, LogLevel.Information, "Drain complete")]
    public static partial void DrainCompleted(this ILogger logger);

    [LoggerMessage(1302, LogLevel.Information, "{MountPath} is not a dedicated block device mount; reporting current size without growing")]
    public static partial void VolumeGrowSkipped(this ILogger logger, string mountPath);

    [LoggerMessage(1303, LogLevel.Information, "Grew {MountPath} to {SizeGiB} GiB")]
    public static partial void VolumeGrown(this ILogger logger, string mountPath, int sizeGiB);

    [LoggerMessage(1304, LogLevel.Error, "Growing {MountPath} failed: {Reason}")]
    public static partial void VolumeGrowFailed(this ILogger logger, string mountPath, string reason);

    [LoggerMessage(1305, LogLevel.Information, "Agent {Version} is already current")]
    public static partial void UpgradeAlreadyCurrent(this ILogger logger, string version);

    [LoggerMessage(1306, LogLevel.Information, "Agent {Version} installed")]
    public static partial void UpgradeInstalled(this ILogger logger, string version);

    [LoggerMessage(1307, LogLevel.Warning, "Exiting so systemd restarts ts-orch-agent on {Version}")]
    public static partial void UpgradeRestarting(this ILogger logger, string version);

    [LoggerMessage(1308, LogLevel.Error, "Agent upgrade to {Version} failed: {Reason}")]
    public static partial void UpgradeFailed(this ILogger logger, string version, string reason);

    [LoggerMessage(1400, LogLevel.Information, "Enrolled as node {NodeId}")]
    public static partial void Enrolled(this ILogger logger, string nodeId);

    [LoggerMessage(1401, LogLevel.Debug, "Loaded enrollment for node {NodeId}")]
    public static partial void EnrollmentLoaded(this ILogger logger, string nodeId);

    [LoggerMessage(1402, LogLevel.Warning, "Stored enrollment is unusable, re-enrolling: {Reason}")]
    public static partial void EnrollmentStateCorrupt(this ILogger logger, string reason);

    [LoggerMessage(1403, LogLevel.Warning, "Backplane rejected the node token; credentials removed for re-enrollment")]
    public static partial void CredentialsForgotten(this ILogger logger);

    [LoggerMessage(1404, LogLevel.Error, "Enrollment failed ({Code}): {Reason}")]
    public static partial void EnrollFailed(this ILogger logger, string code, string reason);

    [LoggerMessage(1500, LogLevel.Information, "Connecting to {Url}")]
    public static partial void Connecting(this ILogger logger, Uri url);

    [LoggerMessage(1501, LogLevel.Information, "Connected to backplane as {NodeId}")]
    public static partial void Connected(this ILogger logger, string nodeId);

    [LoggerMessage(1502, LogLevel.Warning, "Backplane rejected the WebSocket with {Status}")]
    public static partial void ConnectRejected(this ILogger logger, int status);

    [LoggerMessage(1503, LogLevel.Warning, "Backplane connection failed: {Reason}")]
    public static partial void ConnectFailed(this ILogger logger, string reason);

    [LoggerMessage(1504, LogLevel.Information, "Backplane session for {NodeId} ended")]
    public static partial void SessionEnded(this ILogger logger, string nodeId);

    [LoggerMessage(1505, LogLevel.Error, "Backplane session loop faulted")]
    public static partial void SessionLoopFaulted(this ILogger logger, Exception exception);

    [LoggerMessage(1506, LogLevel.Information, "Reconnecting in {Delay}")]
    public static partial void Reconnecting(this ILogger logger, TimeSpan delay);

    [LoggerMessage(1507, LogLevel.Warning, "Ignoring invalid backplane message: {Reason}")]
    public static partial void BackplaneMessageInvalid(this ILogger logger, string reason);

    [LoggerMessage(1508, LogLevel.Warning, "Backplane message of {Bytes} bytes exceeds the limit")]
    public static partial void MessageTooLarge(this ILogger logger, int bytes);

    [LoggerMessage(1509, LogLevel.Debug, "WebSocket close failed: {Reason}")]
    public static partial void CloseFailed(this ILogger logger, string reason);

    [LoggerMessage(1600, LogLevel.Debug, "Wrote edge routes revision {Revision}")]
    public static partial void RoutesWritten(this ILogger logger, long revision);

    [LoggerMessage(1601, LogLevel.Warning, "Ignoring routes revision {Revision} older than {Current}")]
    public static partial void StaleRoutesIgnored(this ILogger logger, long revision, long current);

    [LoggerMessage(1602, LogLevel.Information, "Wrote TLS bundle revision {Revision}")]
    public static partial void TlsWritten(this ILogger logger, long revision);

    [LoggerMessage(1603, LogLevel.Warning, "Ignoring stale TLS revision {Revision}")]
    public static partial void StaleTlsIgnored(this ILogger logger, long revision);

    [LoggerMessage(1604, LogLevel.Error, "Writing {Path} failed: {Reason}")]
    public static partial void EdgeWriteFailed(this ILogger logger, string path, string reason);

    [LoggerMessage(1700, LogLevel.Error, "Session {RequestId} faulted")]
    public static partial void SessionFaulted(this ILogger logger, string requestId, Exception exception);

    [LoggerMessage(1701, LogLevel.Debug, "Session {RequestId} stopped")]
    public static partial void SessionStopped(this ILogger logger, string requestId);

    [LoggerMessage(1702, LogLevel.Information, "Exec {RequestId} in {ContainerName}")]
    public static partial void ExecStarted(this ILogger logger, string requestId, string containerName);
}
