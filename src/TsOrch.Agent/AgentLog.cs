namespace TsOrch.Agent;

internal static partial class AgentLog
{
    [LoggerMessage(1000, LogLevel.Information, "Placement {PlacementId} ready on {Image} ({ConfigHash}) host port {HostPort}")]
    public static partial void PlacementReady(ILogger logger, string placementId, string image, string configHash, int? hostPort);

    [LoggerMessage(1001, LogLevel.Warning, "Edge did not acknowledge routes for placement {PlacementId} on port {HostPort}; keeping previous containers")]
    public static partial void RouteSwitchTimedOut(ILogger logger, string placementId, int hostPort);

    [LoggerMessage(1002, LogLevel.Warning, "Edge routes still referenced placement {PlacementId} after the drain window")]
    public static partial void RouteDrainTimedOut(ILogger logger, string placementId);

    [LoggerMessage(1003, LogLevel.Error, "Placement {PlacementId} on {Image} failed: {Reason}")]
    public static partial void PlacementFailed(ILogger logger, string placementId, string image, string reason);

    [LoggerMessage(1004, LogLevel.Information, "Swapping placement {PlacementId} to {Image} ({ConfigHash}), stop-start {StopStart}")]
    public static partial void PlacementSwapping(ILogger logger, string placementId, string image, string configHash, bool stopStart);

    [LoggerMessage(1005, LogLevel.Information, "Retiring placement {PlacementId} removed from desired state")]
    public static partial void PlacementRetiring(ILogger logger, string placementId);

    [LoggerMessage(1006, LogLevel.Warning, "Ignoring desired revision {Revision} older than {Current}")]
    public static partial void StaleDesiredIgnored(ILogger logger, long revision, long current);

    [LoggerMessage(1007, LogLevel.Information, "Secret refresh requested for {ServiceName} ({Placements} placements)")]
    public static partial void SecretRefreshRequested(ILogger logger, string serviceName, int placements);

    [LoggerMessage(1008, LogLevel.Error, "Listing managed containers failed: {Reason}")]
    public static partial void ReconcileListFailed(ILogger logger, string reason);

    [LoggerMessage(1009, LogLevel.Warning, "Secrets for placement {PlacementId} unavailable; keeping the running container: {Reason}")]
    public static partial void SecretResolveDeferred(ILogger logger, string placementId, string reason);

    [LoggerMessage(1010, LogLevel.Warning, "Cleaning up container {ContainerId} failed: {Reason}")]
    public static partial void ContainerCleanupFailed(ILogger logger, string containerId, string reason);

    [LoggerMessage(1011, LogLevel.Warning, "Recording image history failed: {Reason}")]
    public static partial void ImageHistoryFailed(ILogger logger, string reason);

    [LoggerMessage(1012, LogLevel.Warning, "Regional OCIR mirror pull for {MirrorImage} failed ({Reason}); falling back to {CanonicalImage}")]
    public static partial void RegionalMirrorFallback(ILogger logger, string mirrorImage, string canonicalImage, string reason);

    [LoggerMessage(1013, LogLevel.Debug, "Reading failure logs for container {ContainerId} failed: {Reason}")]
    public static partial void FailureLogReadFailed(ILogger logger, string containerId, string reason);

    [LoggerMessage(1100, LogLevel.Warning, "Image GC failed: {Reason}")]
    public static partial void ImageGcFailed(ILogger logger, string reason);

    [LoggerMessage(1101, LogLevel.Information, "Image GC removed {ImageId}")]
    public static partial void ImageRemoved(ILogger logger, string imageId);

    [LoggerMessage(1102, LogLevel.Debug, "Image GC kept {ImageId}: {Reason}")]
    public static partial void ImageRemovalSkipped(ILogger logger, string imageId, string reason);

    [LoggerMessage(1200, LogLevel.Warning, "Edge metrics file {Path} is unreadable: {Reason}")]
    public static partial void EdgeMetricsUnreadable(ILogger logger, string path, string reason);

    [LoggerMessage(1201, LogLevel.Debug, "Stats for container {ContainerId} unavailable: {Reason}")]
    public static partial void ContainerStatsUnavailable(ILogger logger, string containerId, string reason);

    [LoggerMessage(1300, LogLevel.Information, "Drain started: {Reason}")]
    public static partial void DrainStarted(ILogger logger, string reason);

    [LoggerMessage(1301, LogLevel.Information, "Drain complete")]
    public static partial void DrainCompleted(ILogger logger);

    [LoggerMessage(1309, LogLevel.Warning, "Node drain incomplete: {Reason}")]
    public static partial void DrainFailed(ILogger logger, string reason);

    [LoggerMessage(1310, LogLevel.Warning, "Refreshing systemd units after agent upgrade failed: {Reason}")]
    public static partial void SystemdReloadFailed(ILogger logger, string reason);

    [LoggerMessage(1202, LogLevel.Warning, "Docker OOM event subscription interrupted: {Reason}")]
    public static partial void OomSubscriptionInterrupted(ILogger logger, string reason);

    [LoggerMessage(1302, LogLevel.Information, "{MountPath} is not a dedicated block device mount; reporting current size without growing")]
    public static partial void VolumeGrowSkipped(ILogger logger, string mountPath);

    [LoggerMessage(1303, LogLevel.Information, "Grew {MountPath} to {SizeGiB} GiB")]
    public static partial void VolumeGrown(ILogger logger, string mountPath, int sizeGiB);

    [LoggerMessage(1304, LogLevel.Error, "Growing {MountPath} failed: {Reason}")]
    public static partial void VolumeGrowFailed(ILogger logger, string mountPath, string reason);

    [LoggerMessage(1305, LogLevel.Information, "Agent {Version} is already current")]
    public static partial void UpgradeAlreadyCurrent(ILogger logger, string version);

    [LoggerMessage(1306, LogLevel.Information, "Agent {Version} installed")]
    public static partial void UpgradeInstalled(ILogger logger, string version);

    [LoggerMessage(1307, LogLevel.Warning, "Exiting so systemd restarts ts-orch-agent on {Version}")]
    public static partial void UpgradeRestarting(ILogger logger, string version);

    [LoggerMessage(1308, LogLevel.Error, "Agent upgrade to {Version} failed: {Reason}")]
    public static partial void UpgradeFailed(ILogger logger, string version, string reason);

    [LoggerMessage(1400, LogLevel.Information, "Enrolled as node {NodeId}")]
    public static partial void Enrolled(ILogger logger, string nodeId);

    [LoggerMessage(1401, LogLevel.Debug, "Loaded enrollment for node {NodeId}")]
    public static partial void EnrollmentLoaded(ILogger logger, string nodeId);

    [LoggerMessage(1402, LogLevel.Warning, "Stored enrollment is unusable, re-enrolling: {Reason}")]
    public static partial void EnrollmentStateCorrupt(ILogger logger, string reason);

    [LoggerMessage(1403, LogLevel.Warning, "Backplane rejected the node token; credentials removed for re-enrollment")]
    public static partial void CredentialsForgotten(ILogger logger);

    [LoggerMessage(1404, LogLevel.Error, "Enrollment failed ({Code}): {Reason}")]
    public static partial void EnrollFailed(ILogger logger, string code, string reason);

    [LoggerMessage(1500, LogLevel.Information, "Connecting to {Url}")]
    public static partial void Connecting(ILogger logger, Uri url);

    [LoggerMessage(1501, LogLevel.Information, "Connected to backplane as {NodeId}")]
    public static partial void Connected(ILogger logger, string nodeId);

    [LoggerMessage(1502, LogLevel.Warning, "Backplane rejected the WebSocket with {Status}")]
    public static partial void ConnectRejected(ILogger logger, int status);

    [LoggerMessage(1503, LogLevel.Warning, "Backplane connection failed: {Reason}")]
    public static partial void ConnectFailed(ILogger logger, string reason);

    [LoggerMessage(1504, LogLevel.Information, "Backplane session for {NodeId} ended")]
    public static partial void SessionEnded(ILogger logger, string nodeId);

    [LoggerMessage(1505, LogLevel.Error, "Backplane session loop faulted")]
    public static partial void SessionLoopFaulted(ILogger logger, Exception exception);

    [LoggerMessage(1506, LogLevel.Information, "Reconnecting in {Delay}")]
    public static partial void Reconnecting(ILogger logger, TimeSpan delay);

    [LoggerMessage(1507, LogLevel.Warning, "Ignoring invalid backplane message: {Reason}")]
    public static partial void BackplaneMessageInvalid(ILogger logger, string reason);

    [LoggerMessage(1508, LogLevel.Warning, "Backplane message of {Bytes} bytes exceeds the limit")]
    public static partial void MessageTooLarge(ILogger logger, int bytes);

    [LoggerMessage(1509, LogLevel.Debug, "WebSocket close failed: {Reason}")]
    public static partial void CloseFailed(ILogger logger, string reason);

    [LoggerMessage(1510, LogLevel.Warning, "Backplane WebSocket receive watchdog expired after {Timeout}; reconnecting")]
    public static partial void SessionWatchdogExpired(ILogger logger, TimeSpan timeout);

    [LoggerMessage(1600, LogLevel.Debug, "Wrote edge routes revision {Revision}")]
    public static partial void RoutesWritten(ILogger logger, long revision);

    [LoggerMessage(1605, LogLevel.Debug, "Wrote {PeerCount} cluster peers for revision {Revision}")]
    public static partial void PeersWritten(ILogger logger, long revision, int peerCount);

    [LoggerMessage(1601, LogLevel.Warning, "Ignoring routes revision {Revision} older than {Current}")]
    public static partial void StaleRoutesIgnored(ILogger logger, long revision, long current);

    [LoggerMessage(1602, LogLevel.Information, "Wrote TLS bundle revision {Revision}")]
    public static partial void TlsWritten(ILogger logger, long revision);

    [LoggerMessage(1603, LogLevel.Warning, "Ignoring stale TLS revision {Revision}")]
    public static partial void StaleTlsIgnored(ILogger logger, long revision);

    [LoggerMessage(1604, LogLevel.Error, "Writing {Path} failed: {Reason}")]
    public static partial void EdgeWriteFailed(ILogger logger, string path, string reason);

    [LoggerMessage(1700, LogLevel.Error, "Session {RequestId} faulted")]
    public static partial void SessionFaulted(ILogger logger, string requestId, Exception exception);

    [LoggerMessage(1701, LogLevel.Debug, "Session {RequestId} stopped")]
    public static partial void SessionStopped(ILogger logger, string requestId);

    [LoggerMessage(1702, LogLevel.Information, "Exec {RequestId} in {ContainerName}")]
    public static partial void ExecStarted(ILogger logger, string requestId, string containerName);
}
