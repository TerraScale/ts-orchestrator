namespace TerraScale.Orchestrator.ControlPlane.Networking;

public sealed record NetworkEndpointScope(NetworkCellId Cell, NetworkWorkloadId Workload, NetworkServiceId Service,
    NetworkEndpointId Endpoint, NetworkNodeId Node, NetworkLoadBalancerId LoadBalancer, NetworkBackendId Backend,
    NetworkDnsId Dns, NetworkCertificateRef Certificate, NetworkServiceKind ServiceKind, NetworkExposure Exposure,
    NetworkProtocol Protocol, NetworkPort Port, NetworkOrdinal ServiceGeneration, NetworkOrdinal Epoch, NetworkOperationId Operation)
{
    internal bool Valid => Cell is not null && Workload is not null && Service is not null && Endpoint is not null && Node is not null && LoadBalancer is not null && Backend is not null && Dns is not null && Certificate is not null
    && Enum.IsDefined(ServiceKind) && ServiceKind != NetworkServiceKind.Unknown && Enum.IsDefined(Exposure) && Exposure != NetworkExposure.Unknown
    && Enum.IsDefined(Protocol) && Protocol != NetworkProtocol.Unknown && Port.IsValid && ServiceGeneration.IsValid && Epoch.IsValid && Operation is not null; public override string ToString() => "<network-endpoint-scope>";
}

public sealed record NetworkEndpointEvidence(NetworkEndpointScope Scope, NetworkOrdinal ObservedGeneration, NetworkOrdinal ObservedEpoch,
    NetworkProof RegistryAdmitted, NetworkProof ProcessLive, NetworkProof Ready, NetworkHealth BackendHealth,
    NetworkProof CertificateMatches, NetworkProof TrustProven, NetworkProof PublicApproved, NetworkProof ProductionGates,
    NetworkProof WithdrawalTested, NetworkProof BackendRegistered, NetworkProof BackendPromoted,
    NetworkProof DnsRequestRecorded, NetworkProof DnsObserved, NetworkProof Deregistered, NetworkProof Drained,
    NetworkProof DnsWithdrawalRequested, NetworkProof DnsWithdrawn, NetworkProof LoadBalancerWithdrawalRequested,
    NetworkProof LoadBalancerWithdrawn, NetworkProof DeregistrationRequested);

public static class NetworkEndpointPlanner
{
    public static NetworkDecision PlanRegister(NetworkEndpointScope? expected, NetworkEndpointEvidence? e)
    {
        var trace = expected is null ? null : Trace(expected);
        var code = Validate(expected, e); if (code != NetworkCode.Completed) return NetworkDecision.Hold(code, trace);
        var scope = expected!; var validTrace = trace!;
        if (scope.ServiceKind is NetworkServiceKind.Administration or NetworkServiceKind.Monitoring && scope.Exposure != NetworkExposure.Private)
            return NetworkDecision.Hold(NetworkCode.ForbiddenExposure, trace);
        if (scope.Exposure == NetworkExposure.Public && scope.Protocol == NetworkProtocol.Http)
            return NetworkDecision.Hold(NetworkCode.ForbiddenExposure, trace);
        if (e!.RegistryAdmitted != NetworkProof.Proven) return NetworkDecision.Hold(NetworkCode.DefaultDeny, trace);
        if (e.ProcessLive != NetworkProof.Proven) return NetworkDecision.Hold(NetworkCode.ReadinessRequired, trace);
        if (e.Ready != NetworkProof.Proven) return NetworkDecision.Hold(NetworkCode.ReadinessRequired, trace);
        if (e.BackendHealth != NetworkHealth.Healthy) return NetworkDecision.Hold(NetworkCode.BackendHealthRequired, trace);
        if (e.CertificateMatches != NetworkProof.Proven || e.TrustProven != NetworkProof.Proven) return NetworkDecision.Hold(NetworkCode.CertificateMismatch, trace);
        if (scope.Exposure == NetworkExposure.Public && (e.PublicApproved != NetworkProof.Proven || e.ProductionGates != NetworkProof.Proven || e.WithdrawalTested != NetworkProof.Proven))
            return NetworkDecision.Hold(NetworkCode.PublicApprovalRequired, trace);
        var subject = Subject(NetworkEndpointPlanKind.Register, scope, e);
        if (e.BackendRegistered != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Register, NetworkTarget.Backend, NetworkCode.NextStep, subject, validTrace);
        if (e.BackendPromoted != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Promote, NetworkTarget.LoadBalancer, NetworkCode.NextStep, subject, validTrace);
        if (e.DnsRequestRecorded != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.DnsUpdate, NetworkTarget.Dns, NetworkCode.NextStep, subject, validTrace);
        if (e.DnsObserved != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Observe, NetworkTarget.Dns, NetworkCode.DnsConvergencePending, subject, validTrace);
        return NetworkDecision.Emit(NetworkAction.Verify, NetworkTarget.Ingress, NetworkCode.Completed, subject, validTrace);
    }

    public static NetworkDecision PlanRemoval(NetworkEndpointScope? expected, NetworkEndpointEvidence? e)
    {
        var trace = expected is null ? null : Trace(expected); var code = Validate(expected, e); if (code != NetworkCode.Completed) return NetworkDecision.Hold(code, trace); var scope = expected!; var validTrace = trace!;
        var subject = Subject(NetworkEndpointPlanKind.Removal, scope, e!);
        if (e!.BackendHealth is NetworkHealth.Unknown or NetworkHealth.Stale) return NetworkDecision.Hold(NetworkCode.BackendHealthRequired, trace);
        if (e.DeregistrationRequested != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Deregister, NetworkTarget.Backend, NetworkCode.DeregisterBeforeDrain, subject, validTrace);
        if (e.Deregistered != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Observe, NetworkTarget.Backend, NetworkCode.DeregisterBeforeDrain, subject, validTrace);
        if (e.Drained != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Observe, NetworkTarget.Backend, NetworkCode.DeregisterBeforeDrain, subject, validTrace);
        return NetworkDecision.Emit(NetworkAction.Verify, NetworkTarget.Backend, NetworkCode.Completed, subject, validTrace);
    }

    public static NetworkDecision PlanEmergencyWithdrawal(NetworkEndpointScope? expected, NetworkEndpointEvidence? e)
    {
        var trace = expected is null ? null : Trace(expected); var code = Validate(expected, e); if (code != NetworkCode.Completed) return NetworkDecision.Hold(code, trace); var scope = expected!; var validTrace = trace!;
        var subject = Subject(NetworkEndpointPlanKind.EmergencyWithdrawal, scope, e!);
        if (e!.DnsWithdrawalRequested != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.DnsUpdate, NetworkTarget.Dns, NetworkCode.EmergencyWithdrawal, subject, validTrace);
        if (e.DnsWithdrawn != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Observe, NetworkTarget.Dns, NetworkCode.EmergencyWithdrawal, subject, validTrace);
        if (e.LoadBalancerWithdrawalRequested != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Deregister, NetworkTarget.LoadBalancer, NetworkCode.EmergencyWithdrawal, subject, validTrace);
        if (e.LoadBalancerWithdrawn != NetworkProof.Proven) return NetworkDecision.Emit(NetworkAction.Observe, NetworkTarget.LoadBalancer, NetworkCode.EmergencyWithdrawal, subject, validTrace);
        return NetworkDecision.Emit(NetworkAction.Verify, NetworkTarget.Ingress, NetworkCode.Completed, subject, validTrace);
    }

    private static NetworkCode Validate(NetworkEndpointScope? expected, NetworkEndpointEvidence? e)
    {
        if (expected is null || !expected.Valid || e is null || e.Scope != expected) return NetworkCode.WrongEvidenceScope;
        if (!Enum.IsDefined(e.BackendHealth) || !Enum.IsDefined(e.RegistryAdmitted) || !Enum.IsDefined(e.ProcessLive) || !Enum.IsDefined(e.Ready)
            || !Enum.IsDefined(e.CertificateMatches) || !Enum.IsDefined(e.TrustProven) || !Enum.IsDefined(e.PublicApproved) || !Enum.IsDefined(e.ProductionGates)
            || !Enum.IsDefined(e.WithdrawalTested) || !Enum.IsDefined(e.BackendRegistered) || !Enum.IsDefined(e.BackendPromoted)
            || !Enum.IsDefined(e.DnsRequestRecorded) || !Enum.IsDefined(e.DnsObserved) || !Enum.IsDefined(e.Deregistered) || !Enum.IsDefined(e.Drained)
            || !Enum.IsDefined(e.DnsWithdrawalRequested) || !Enum.IsDefined(e.DnsWithdrawn) || !Enum.IsDefined(e.LoadBalancerWithdrawalRequested)
            || !Enum.IsDefined(e.LoadBalancerWithdrawn) || !Enum.IsDefined(e.DeregistrationRequested)) return NetworkCode.InvalidInput;
        if (e.ObservedGeneration.Value < expected.ServiceGeneration.Value || e.ObservedEpoch.Value < expected.Epoch.Value) return NetworkCode.StaleGeneration;
        if (e.ObservedGeneration.Value > expected.ServiceGeneration.Value || e.ObservedEpoch.Value > expected.Epoch.Value) return NetworkCode.FutureGeneration;
        return NetworkCode.Completed;
    }
    private static NetworkEndpointIntentSubject Subject(NetworkEndpointPlanKind kind, NetworkEndpointScope scope, NetworkEndpointEvidence evidence) => new(kind, scope, evidence);
    private static NetworkNumericTrace Trace(NetworkEndpointScope x) => new(x.ServiceGeneration, x.Epoch, 0, 0);
}
