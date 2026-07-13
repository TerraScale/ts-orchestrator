using System.Collections.ObjectModel;

namespace TerraScale.Orchestrator.ControlPlane.Messaging;

public static class MessagingPolicyEngine
{
    private const string Requirement = "INV-005";
    private static readonly StringComparer Ordinal = StringComparer.Ordinal;

    public static MessagingDecision DecideTopology(MessagingTopologyPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var errors = ValidateTopology(policy);
        if (errors.Count != 0) return Held(errors);
        var intents = new MessagingIntent[]
        {
            new ConfigurePlaneIntent(policy.Control),
            new ConfigurePlaneIntent(policy.Product),
        }.OrderBy(static intent => ((ConfigurePlaneIntent)intent).Policy.Plane).ToArray();
        return Decision(intents, [], Trace(intents, MessagingTraceCode.ConfigurationAccepted));
    }

    public static MessagingDecision DecideReplacement(ReplacementRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var basic = ValidateReplacementInput(request);
        if (basic is not null) return Held([basic]);
        var operation = request.Proposed;
        if (request.Observation is null)
        {
            var observe = new ObserveClusterIntent(operation.OperationId, operation.Cluster,
                operation.MinimumObservationSequence, operation.MaximumObservationSequence);
            return Decision([observe], [], [new(1, MessagingTraceCode.ObservationRequired, observe.Action)]);
        }

        var observationError = ValidateObservation(request.Policy, operation, request.Observation, request.MaximumIdentityLength);
        if (observationError is not null) return Held([observationError]);
        var observation = request.Observation;
        var failed = observation.Peers.SingleOrDefault(peer => peer.Server == operation.FailedServer && peer.Peer == operation.FailedPeer);
        if (failed is null)
        {
            if (request.Persisted != operation) return Held([Error(MessagingErrorCode.ConflictingEvidence, operation)]);
            var completedReplacement = observation.Peers.SingleOrDefault(peer =>
                peer.Server == operation.ReplacementServer && peer.Peer == operation.ReplacementPeer);
            if (completedReplacement is null || completedReplacement.Health != PeerHealth.Current ||
                !completedReplacement.CaughtUp || !completedReplacement.OwnershipProven || !ReplicasVerified(request.Policy, observation) ||
                observation.Peers.Count(static peer => peer.Health == PeerHealth.Current && peer.OwnershipProven) < request.Policy.MembershipFloor)
                return Held([Error(MessagingErrorCode.IncompleteObservation, operation)]);
            return Decision([], [], [new(1, MessagingTraceCode.ReplacementComplete, MessagingAction.Observe)]);
        }
        if (failed.Store == StoreClassification.Ambiguous)
            return Held([Error(MessagingErrorCode.StoreAmbiguous, operation)]);
        if (failed.Health != PeerHealth.Failed || !failed.ProcessFenced)
            return Held([Error(MessagingErrorCode.ReplacementConflict, operation)]);
        if (failed.Store == StoreClassification.Surviving)
        {
            var proofError = ValidateSurvivingStoreProof(operation, observation, failed, request.MaximumIdentityLength);
            if (proofError is not null) return Held([proofError]);
        }

        if (request.Persisted is null)
        {
            var persist = new ConfigureReplacementIntent(operation);
            return Decision([persist], [], [new(1, MessagingTraceCode.ReplacementMustPersist, persist.Action)]);
        }
        if (request.Persisted != operation)
            return Held([Error(MessagingErrorCode.ReplacementConflict, operation)]);
        var currentPeers = observation.Peers.Count(static peer => peer.Health == PeerHealth.Current && peer.OwnershipProven);
        if (currentPeers < request.Policy.MembershipFloor - 1)
            return Held([Error(MessagingErrorCode.MembershipFloorViolation, operation)]);
        if (failed.Store == StoreClassification.Surviving)
            return DecideSurvivingStore(request.Policy, operation, observation, failed, request.MaximumIdentityLength);
        if (failed.Store != StoreClassification.Lost)
            return Held([Error(MessagingErrorCode.ReplacementConflict, operation)]);

        var replacements = observation.Peers.Where(peer =>
            peer.Server == operation.ReplacementServer || peer.Peer == operation.ReplacementPeer).ToArray();
        if (replacements.Length == 0)
        {
            var add = new AddPeerIntent(operation.OperationId, operation.Cluster, operation.ReplacementServer,
                operation.ReplacementPeer, operation.ReplacementPlacement, operation.AuthorityEpoch);
            return Decision([add], [], [new(1, MessagingTraceCode.ReplacementAddRequired, add.Action)]);
        }
        if (replacements.Length != 1 || replacements[0].Server != operation.ReplacementServer ||
            replacements[0].Peer != operation.ReplacementPeer || replacements[0].Health != PeerHealth.Current)
            return Held([Error(MessagingErrorCode.ConflictingEvidence, operation)]);

        var replacement = replacements[0];
        if (!replacement.CaughtUp || !replacement.OwnershipProven)
        {
            var wait = new WaitCatchupIntent(operation.OperationId, operation.Cluster,
                operation.ReplacementPeer, observation.MembershipSequence);
            return Decision([wait], [], [new(1, MessagingTraceCode.ReplacementCatchupRequired, wait.Action)]);
        }

        if (!ReplicasVerified(request.Policy, observation))
        {
            var wait = new WaitCatchupIntent(operation.OperationId, operation.Cluster,
                operation.ReplacementPeer, observation.MembershipSequence);
            return Decision([wait], [], [new(1, MessagingTraceCode.ReplicaVerificationRequired, wait.Action)]);
        }
        if (currentPeers < request.Policy.MembershipFloor)
            return Held([Error(MessagingErrorCode.RemovalUnsafe, operation)]);

        if (observation.Peers.Any(peer => peer.Server == operation.FailedServer && peer.Peer == operation.FailedPeer))
        {
            var remove = new RemovePeerIntent(operation.OperationId, operation.Cluster,
                operation.FailedServer, operation.FailedPeer, operation.ReplacementPeer,
                observation.MembershipSequence, operation.AuthorityEpoch);
            return Decision([remove], [], [new(1, MessagingTraceCode.FailedPeerRemovalAllowed, remove.Action)]);
        }

        return Decision([], [], [new(1, MessagingTraceCode.ReplacementComplete, MessagingAction.Observe)]);
    }

    private static MessagingDecision DecideSurvivingStore(
        PlanePolicy policy,
        ReplacementOperation operation,
        ClusterObservation observation,
        PeerObservation failed,
        int maximumIdentityLength)
    {
        var proofError = ValidateSurvivingStoreProof(operation, observation, failed, maximumIdentityLength);
        if (proofError is not null) return Held([proofError]);
        var proof = failed.SurvivingStoreProof!;
        if (proof.ActiveAttachment is not null && proof.ActiveAttachment != operation.ReplacementServer)
            return Held([Error(MessagingErrorCode.ConflictingEvidence, operation)]);
        if (proof.ActiveAttachment == operation.ReplacementServer)
        {
            var replayed = observation.Peers.SingleOrDefault(peer =>
                peer.Server == operation.ReplacementServer && peer.Peer == operation.ReplacementPeer);
            if (replayed is not null && replayed.Health == PeerHealth.Current && replayed.CaughtUp &&
                replayed.OwnershipProven && ReplicasVerified(policy, observation))
                return Decision([], [], [new(1, MessagingTraceCode.ReplacementComplete, MessagingAction.Observe)]);
            var observe = new ObserveClusterIntent(operation.OperationId, operation.Cluster,
                operation.MinimumObservationSequence, operation.MaximumObservationSequence);
            return Decision([observe], [], [new(1, MessagingTraceCode.ObservationRequired, observe.Action)]);
        }

        var intent = new ReattachSurvivingStoreIntent(
            operation.OperationId, operation.Plane, operation.Cell, operation.Cluster,
            operation.FailedServer, operation.ReplacementServer, operation.ReplacementPeer,
            proof.Store, proof.StoreGeneration, proof.ObservedMembershipSequence, proof.OwnershipEpoch);
        return Decision([intent], [], [new(1, MessagingTraceCode.SurvivingStoreReattachRequired, intent.Action)]);
    }

    private static MessagingError? ValidateSurvivingStoreProof(
        ReplacementOperation operation,
        ClusterObservation observation,
        PeerObservation failed,
        int maximumIdentityLength)
    {
        var proof = failed.SurvivingStoreProof;
        if (proof is null || !Valid(proof.Store.Value, maximumIdentityLength) || proof.StoreGeneration <= 0 ||
            proof.RecordedOwner != operation.FailedServer || proof.Cell != operation.Cell || proof.Cluster != operation.Cluster ||
            !proof.Compatible)
            return Error(MessagingErrorCode.ConflictingEvidence, operation);
        if (proof.Plane != operation.Plane)
            return Error(MessagingErrorCode.IsolationViolation, operation);
        if (proof.ObservedMembershipSequence < observation.MembershipSequence || proof.OwnershipEpoch < operation.AuthorityEpoch)
            return Error(MessagingErrorCode.StaleEvidence, operation);
        if (proof.ObservedMembershipSequence > observation.MembershipSequence || proof.OwnershipEpoch > operation.AuthorityEpoch)
            return Error(MessagingErrorCode.FutureEvidence, operation);
        return null;
    }

    public static MessagingDecision DecidePartition(PartitionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.MaximumIdentityLength <= 0 || !Valid(request.Cell.Value, request.MaximumIdentityLength) ||
            !Enum.IsDefined(request.Connectivity) || !Enum.IsDefined(request.Scope) ||
            request.CurrentRegionalEpoch <= 0 || request.CommandRegionalEpoch <= 0 ||
            request.AcceptedGlobalGeneration <= 0 || request.CommandGlobalGeneration <= 0 ||
            request.CurrentGlobalEpoch <= 0 || request.CommandGlobalEpoch <= 0)
            return Held([Error(MessagingErrorCode.InvalidInput)]);
        if (request.CommandRegionalEpoch != request.CurrentRegionalEpoch)
            return Held([Error(MessagingErrorCode.StaleAuthority)]);
        if (request.Connectivity == ConnectivityState.RegionalQuorumLost)
            return Held([Error(MessagingErrorCode.PartitionDenied)]);
        if (request.CommandGlobalGeneration != request.AcceptedGlobalGeneration)
            return Held([Error(request.CommandGlobalGeneration < request.AcceptedGlobalGeneration
                ? MessagingErrorCode.StaleEvidence : MessagingErrorCode.FutureEvidence)]);
        if (request.Scope == AuthorityScope.Global &&
            (request.Connectivity != ConnectivityState.Connected || !request.HoldsCurrentGlobalAuthority))
            return Held([Error(MessagingErrorCode.PartitionDenied)]);
        if (request.Scope == AuthorityScope.Global && request.CommandGlobalEpoch != request.CurrentGlobalEpoch)
            return Held([Error(MessagingErrorCode.StaleAuthority)]);
        if (request.Scope == AuthorityScope.Regional && !request.CallerAuthorizesLocalOperation)
            return Held([Error(MessagingErrorCode.PartitionDenied)]);
        MessagingIntent intent = request.Scope == AuthorityScope.Global
            ? new ContinueGlobalIntent(request.Cell, request.CurrentGlobalEpoch, request.AcceptedGlobalGeneration)
            : new ContinueRegionalIntent(request.Cell, request.CurrentRegionalEpoch, request.AcceptedGlobalGeneration);
        return Decision([intent], [], [new(1, MessagingTraceCode.RegionalOperationAllowed, intent.Action)]);
    }

    public static MessagingDecision DecideCompatibility(
        IReadOnlyList<CompatibilityFeature> knownFeatures,
        CompatibilityPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(knownFeatures);
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.CurrentVersion <= 0 || policy.PreviousVersion <= 0 || policy.CurrentVersion - 1 != policy.PreviousVersion ||
            knownFeatures.Count == 0 || knownFeatures.Any(static feature => !Enum.IsDefined(feature)) ||
            knownFeatures.Distinct().Count() != knownFeatures.Count ||
            !knownFeatures.ToHashSet().SetEquals(Enum.GetValues<CompatibilityFeature>()) ||
            policy.Outcomes.Any(static outcome => !Enum.IsDefined(outcome.Feature) || !Enum.IsDefined(outcome.Pair)))
            return Held([Error(MessagingErrorCode.InvalidCatalog)]);

        var expected = knownFeatures
            .SelectMany(static feature => Enum.GetValues<CompatibilityPair>().Select(pair => (feature, pair)))
            .ToHashSet();
        var actual = policy.Outcomes.Select(static outcome => (outcome.Feature, outcome.Pair)).ToArray();
        if (actual.Distinct().Count() != actual.Length)
            return Held([Error(MessagingErrorCode.DuplicateEvidence)]);
        if (!actual.ToHashSet().SetEquals(expected))
            return Held([Error(MessagingErrorCode.IncompleteObservation)]);
        if (policy.Outcomes.Any(static outcome => !outcome.Available))
            return Held([Error(MessagingErrorCode.CompatibilityUnavailable)]);
        return Decision([], [], [new(1, MessagingTraceCode.CompatibilityAccepted, MessagingAction.Configure)]);
    }

    private static List<MessagingError> ValidateTopology(MessagingTopologyPolicy policy)
    {
        var errors = new List<MessagingError>();
        if (policy.Control is null || policy.Product is null || policy.MaximumIdentityLength <= 0 ||
            policy.MaximumSubjectLength <= 0 || policy.MaximumResources <= 0 ||
            policy.KnownFeatures.Count == 0 || policy.KnownFeatures.Any(static feature => !Enum.IsDefined(feature)) ||
            policy.KnownFeatures.Distinct().Count() != policy.KnownFeatures.Count ||
            !policy.KnownFeatures.ToHashSet().SetEquals(Enum.GetValues<CompatibilityFeature>()))
            return [Error(MessagingErrorCode.InvalidCatalog)];
        if (policy.Control.Plane != MessagingPlane.Control || policy.Product.Plane != MessagingPlane.Product)
            errors.Add(Error(MessagingErrorCode.IsolationViolation));
        ValidatePlane(policy.Control, policy, errors);
        ValidatePlane(policy.Product, policy, errors);
        if (policy.Control.Cell != policy.Product.Cell || policy.Control.Cluster == policy.Product.Cluster ||
            Intersects(policy.Control.Servers.Select(static server => server.Server.Value), policy.Product.Servers.Select(static server => server.Server.Value)) ||
            Intersects(policy.Control.Servers.Select(static server => server.Peer.Value), policy.Product.Servers.Select(static server => server.Peer.Value)) ||
            Intersects(policy.Control.Accounts.Select(static account => account.Id.Value), policy.Product.Accounts.Select(static account => account.Id.Value)) ||
            Intersects(policy.Control.Streams.Select(static stream => stream.Id.Value), policy.Product.Streams.Select(static stream => stream.Id.Value)) ||
            Intersects(policy.Control.Buckets.Select(static bucket => bucket.Id.Value), policy.Product.Buckets.Select(static bucket => bucket.Id.Value)) ||
            SubjectOverlap(AllSubjects(policy.Control), AllSubjects(policy.Product)) || policy.Product.Gateways.Count != 0 ||
            policy.Control.Gateways.Contains(policy.Product.Cluster))
            errors.Add(Error(MessagingErrorCode.IsolationViolation));
        return errors.Distinct().OrderBy(static error => error.Code).ToList();
    }

    private static void ValidatePlane(PlanePolicy plane, MessagingTopologyPolicy topology, List<MessagingError> errors)
    {
        var resourceCount = (long)plane.Servers.Count + plane.Accounts.Count + plane.Streams.Count + plane.Buckets.Count;
        if (!Enum.IsDefined(plane.Plane) || !Valid(plane.Cell.Value, topology.MaximumIdentityLength) ||
            !Valid(plane.Cluster.Value, topology.MaximumIdentityLength) || plane.Generation <= 0 ||
            plane.MembershipFloor < 2 || plane.Servers.Count != plane.MembershipFloor || resourceCount > topology.MaximumResources)
        {
            errors.Add(Error(MessagingErrorCode.InvalidInput));
            return;
        }
        if (!Unique(plane.Servers.Select(static value => value.Server.Value)) ||
            !Unique(plane.Servers.Select(static value => value.Peer.Value)) ||
            !Unique(plane.Accounts.Select(static value => value.Id.Value)) ||
            !Unique(plane.Streams.Select(static value => value.Id.Value)) ||
            !Unique(plane.Buckets.Select(static value => value.Id.Value)))
            errors.Add(Error(MessagingErrorCode.DuplicateEvidence));
        if (plane.Servers.Any(server => !Valid(server.Server.Value, topology.MaximumIdentityLength) ||
                !Valid(server.Peer.Value, topology.MaximumIdentityLength) || !Valid(server.Placement.Value, topology.MaximumIdentityLength)) ||
            plane.Gateways.Any(gateway => !Valid(gateway.Value, topology.MaximumIdentityLength)) ||
            plane.Accounts.Any(account => !Valid(account.Id.Value, topology.MaximumIdentityLength) ||
                account.SubjectRoots.Count == 0 || account.SubjectRoots.Any(subject => !Valid(subject, topology.MaximumSubjectLength))))
            errors.Add(Error(MessagingErrorCode.InvalidInput));

        var serverSet = plane.Servers.Select(static server => server.Server).ToHashSet();
        var routeSet = plane.Routes.Select(static route => (route.From, route.To)).ToArray();
        if (routeSet.Distinct().Count() != routeSet.Length || routeSet.Any(route => route.From == route.To ||
                !serverSet.Contains(route.From) || !serverSet.Contains(route.To)) ||
            routeSet.LongLength != (long)plane.Servers.Count * (plane.Servers.Count - 1))
            errors.Add(Error(MessagingErrorCode.IncompleteObservation));

        if (!Unique(plane.Gateways.Select(static gateway => gateway.Value)) || plane.Gateways.Contains(plane.Cluster))
            errors.Add(Error(MessagingErrorCode.ConflictingEvidence));

        foreach (var account in plane.Accounts)
        {
            var otherRoots = plane.Accounts.Where(other => other.Id != account.Id).SelectMany(static other => other.SubjectRoots);
            if (SubjectOverlap(account.SubjectRoots, otherRoots)) errors.Add(Error(MessagingErrorCode.IsolationViolation));
        }

        var accounts = plane.Accounts.Select(static account => account.Id).ToHashSet();
        foreach (var stream in plane.Streams)
        {
            if (!Valid(stream.Id.Value, topology.MaximumIdentityLength) || !accounts.Contains(stream.Account) ||
                !Valid(stream.SubjectRoot, topology.MaximumSubjectLength) || !Valid(stream.Placement.Value, topology.MaximumIdentityLength) ||
                !Enum.IsDefined(stream.Durability) || !Enum.IsDefined(stream.Retention) || !Enum.IsDefined(stream.Discard) ||
                !Enum.IsDefined(stream.Acknowledgement) || !Enum.IsDefined(stream.DiskSyncClass) ||
                stream.Replicas <= 0 || stream.Replicas > plane.Servers.Count || stream.MaximumAgeTicks <= 0 ||
                stream.MaximumBytes <= 0 || stream.DuplicateWindowTicks <= 0)
                errors.Add(Error(MessagingErrorCode.InvalidInput));
            var owningAccount = plane.Accounts.SingleOrDefault(account => account.Id == stream.Account);
            if (owningAccount is not null && !owningAccount.SubjectRoots.Any(root => Contains(root, stream.SubjectRoot)))
                errors.Add(Error(MessagingErrorCode.IsolationViolation));
            ValidateDurability(stream.Durability, stream.Replicas, stream.Acknowledgement, stream.DiskSyncClass, plane, errors);
        }
        foreach (var bucket in plane.Buckets)
        {
            if (!Valid(bucket.Id.Value, topology.MaximumIdentityLength) || !accounts.Contains(bucket.Account) ||
                !Valid(bucket.SubjectRoot, topology.MaximumSubjectLength) || !Valid(bucket.Placement.Value, topology.MaximumIdentityLength) ||
                !Enum.IsDefined(bucket.Durability) || !Enum.IsDefined(bucket.Acknowledgement) || !Enum.IsDefined(bucket.DiskSyncClass) ||
                bucket.Replicas <= 0 || bucket.Replicas > plane.Servers.Count || bucket.MaximumAgeTicks <= 0 || bucket.MaximumBytes <= 0)
                errors.Add(Error(MessagingErrorCode.InvalidInput));
            var owningAccount = plane.Accounts.SingleOrDefault(account => account.Id == bucket.Account);
            if (owningAccount is not null && !owningAccount.SubjectRoots.Any(root => Contains(root, bucket.SubjectRoot)))
                errors.Add(Error(MessagingErrorCode.IsolationViolation));
            ValidateDurability(bucket.Durability, bucket.Replicas, bucket.Acknowledgement, bucket.DiskSyncClass, plane, errors);
        }
    }

    private static void ValidateDurability(MessagingDurability durability, int replicas,
        MessagingAcknowledgement acknowledgement, MessagingDiskSyncClass sync, PlanePolicy plane, List<MessagingError> errors)
    {
        if (durability == MessagingDurability.Critical && (replicas < plane.MembershipFloor || replicas <= 1 ||
            acknowledgement != MessagingAcknowledgement.Replicated || sync != MessagingDiskSyncClass.AcknowledgedWriteStrict))
            errors.Add(Error(MessagingErrorCode.DurabilityViolation));
    }

    private static MessagingError? ValidateReplacementInput(ReplacementRequest request)
    {
        var operation = request.Proposed;
        if (request.Policy is null || operation is null || !Enum.IsDefined(operation.Plane) ||
            operation.Plane != request.Policy.Plane || operation.Cell != request.Policy.Cell || operation.Cluster != request.Policy.Cluster ||
            operation.ConfigurationGeneration != request.Policy.Generation ||
            operation.OperationGeneration <= 0 || operation.AuthorityEpoch <= 0 || operation.ConfigurationGeneration <= 0 ||
            operation.MinimumObservationSequence <= 0 || operation.MaximumObservationSequence < operation.MinimumObservationSequence ||
            operation.FailedServer == operation.ReplacementServer || operation.FailedPeer == operation.ReplacementPeer ||
            request.MaximumIdentityLength <= 0 || !Valid(operation.OperationId.Value, request.MaximumIdentityLength) ||
            !Valid(operation.Cell.Value, request.MaximumIdentityLength) || !Valid(operation.Cluster.Value, request.MaximumIdentityLength) ||
            !Valid(operation.FailedServer.Value, request.MaximumIdentityLength) || !Valid(operation.FailedPeer.Value, request.MaximumIdentityLength) ||
            !Valid(operation.ReplacementServer.Value, request.MaximumIdentityLength) || !Valid(operation.ReplacementPeer.Value, request.MaximumIdentityLength) ||
            !Valid(operation.ReplacementPlacement.Value, request.MaximumIdentityLength))
            return Error(MessagingErrorCode.InvalidInput);
        if (request.Policy.MembershipFloor < 2 || request.Policy.Servers.Count != request.Policy.MembershipFloor ||
            request.Policy.Servers.Any(server => !Valid(server.Server.Value, request.MaximumIdentityLength) ||
                !Valid(server.Peer.Value, request.MaximumIdentityLength)) ||
            request.Policy.Servers.Select(static server => server.Server).Distinct().Count() != request.Policy.Servers.Count ||
            request.Policy.Servers.Select(static server => server.Peer).Distinct().Count() != request.Policy.Servers.Count ||
            request.Policy.Streams.Any(stream => !Valid(stream.Id.Value, request.MaximumIdentityLength) || stream.Replicas <= 0) ||
            request.Policy.Buckets.Any(bucket => !Valid(bucket.Id.Value, request.MaximumIdentityLength) || bucket.Replicas <= 0) ||
            request.Policy.Streams.Select(static stream => stream.Id).Distinct().Count() != request.Policy.Streams.Count ||
            request.Policy.Buckets.Select(static bucket => bucket.Id).Distinct().Count() != request.Policy.Buckets.Count ||
            request.Policy.Servers.All(server => server.Server != operation.FailedServer || server.Peer != operation.FailedPeer) ||
            request.Policy.Servers.Any(server => server.Server == operation.ReplacementServer || server.Peer == operation.ReplacementPeer))
            return Error(MessagingErrorCode.ReplacementConflict, operation);
        return null;
    }

    private static MessagingError? ValidateObservation(
        PlanePolicy policy,
        ReplacementOperation operation,
        ClusterObservation observation,
        int maximumIdentityLength)
    {
        if (!Valid(observation.ObservationId.Value, maximumIdentityLength) || observation.Cluster != operation.Cluster ||
            observation.ConfigurationGeneration <= 0 || observation.MembershipSequence <= 0 ||
            observation.Peers.Any(peer => !Enum.IsDefined(peer.Health) || !Enum.IsDefined(peer.Store) ||
                !Valid(peer.Server.Value, maximumIdentityLength) || !Valid(peer.Peer.Value, maximumIdentityLength)) ||
            observation.StreamReplicas.Any(replica => !Valid(replica.ResourceIdentity, maximumIdentityLength) ||
                replica.CurrentReplicas < 0 || replica.HealthyReplicas < 0 || replica.LastSequence <= 0) ||
            observation.BucketReplicas.Any(replica => !Valid(replica.ResourceIdentity, maximumIdentityLength) ||
                replica.CurrentReplicas < 0 || replica.HealthyReplicas < 0 || replica.LastSequence <= 0))
            return Error(MessagingErrorCode.IncompleteObservation, operation);
        if (observation.ConfigurationGeneration < operation.ConfigurationGeneration || observation.MembershipSequence < operation.MinimumObservationSequence)
            return Error(MessagingErrorCode.StaleEvidence, operation);
        if (observation.ConfigurationGeneration > operation.ConfigurationGeneration || observation.MembershipSequence > operation.MaximumObservationSequence)
            return Error(MessagingErrorCode.FutureEvidence, operation);
        if (observation.Peers.GroupBy(static peer => peer.Server).Any(static group => group.Count() != 1) ||
            observation.Peers.GroupBy(static peer => peer.Peer).Any(static group => group.Count() != 1) ||
            observation.StreamReplicas.GroupBy(static replica => replica.ResourceIdentity, Ordinal).Any(static group => group.Count() != 1) ||
            observation.BucketReplicas.GroupBy(static replica => replica.ResourceIdentity, Ordinal).Any(static group => group.Count() != 1))
            return Error(MessagingErrorCode.DuplicateEvidence, operation);
        var allowedPeers = policy.Servers.Select(static server => (server.Server, server.Peer))
            .Append((operation.ReplacementServer, operation.ReplacementPeer)).ToHashSet();
        if (observation.Peers.Any(peer => !allowedPeers.Contains((peer.Server, peer.Peer))) ||
            observation.StreamReplicas.Any(replica => policy.Streams.All(stream => stream.Id.Value != replica.ResourceIdentity)) ||
            observation.BucketReplicas.Any(replica => policy.Buckets.All(bucket => bucket.Id.Value != replica.ResourceIdentity)))
            return Error(MessagingErrorCode.ConflictingEvidence, operation);
        var failedMatches = observation.Peers.Count(peer => peer.Server == operation.FailedServer && peer.Peer == operation.FailedPeer);
        if (failedMatches > 1) return Error(MessagingErrorCode.ConflictingEvidence, operation);
        return null;
    }

    private static bool ReplicasVerified(PlanePolicy policy, ClusterObservation observation)
    {
        var streams = observation.StreamReplicas.ToDictionary(static value => value.ResourceIdentity, Ordinal);
        var buckets = observation.BucketReplicas.ToDictionary(static value => value.ResourceIdentity, Ordinal);
        return policy.Streams.All(stream => streams.TryGetValue(stream.Id.Value, out var found) &&
                   found.CurrentReplicas == stream.Replicas && found.HealthyReplicas == stream.Replicas) &&
               policy.Buckets.All(bucket => buckets.TryGetValue(bucket.Id.Value, out var found) &&
                   found.CurrentReplicas == bucket.Replicas && found.HealthyReplicas == bucket.Replicas);
    }

    private static IEnumerable<string> AllSubjects(PlanePolicy plane) =>
        plane.Accounts.SelectMany(static account => account.SubjectRoots)
            .Concat(plane.Streams.Select(static stream => stream.SubjectRoot))
            .Concat(plane.Buckets.Select(static bucket => bucket.SubjectRoot));

    private static bool SubjectOverlap(IEnumerable<string> left, IEnumerable<string> right) =>
        left.Any(a => right.Any(b => Overlap(a, b)));

    private static bool Overlap(string left, string right)
    {
        static string Prefix(string value) => value.EndsWith('>') ? value[..^1].TrimEnd('.') : value;
        var a = Prefix(left);
        var b = Prefix(right);
        return Ordinal.Equals(a, b) || a.StartsWith(b + ".", StringComparison.Ordinal) || b.StartsWith(a + ".", StringComparison.Ordinal);
    }

    private static bool Contains(string parent, string child)
    {
        static string Prefix(string value) => value.EndsWith('>') ? value[..^1].TrimEnd('.') : value;
        var root = Prefix(parent);
        var candidate = Prefix(child);
        return Ordinal.Equals(root, candidate) || candidate.StartsWith(root + ".", StringComparison.Ordinal);
    }

    private static bool Intersects(IEnumerable<string> left, IEnumerable<string> right) =>
        left.Intersect(right, Ordinal).Any();
    private static bool Unique(IEnumerable<string> values) => values.Distinct(Ordinal).Count() == values.Count();

    private static bool Valid(string? value, int maximumLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length > maximumLength) return false;
        for (var index = 0; index < value.Length; index++)
        {
            var character = value[index];
            if (char.IsWhiteSpace(character) || char.IsControl(character)) return false;
            if (!char.IsSurrogate(character)) continue;
            if (!char.IsHighSurrogate(character) || index + 1 >= value.Length || !char.IsLowSurrogate(value[index + 1])) return false;
            index++;
        }
        return true;
    }

    private static MessagingDecision Held(IReadOnlyList<MessagingError> errors)
    {
        var ordered = errors.OrderBy(static error => error.Code).ThenBy(static error => error.Operation?.Value, Ordinal).ToArray();
        var first = ordered[0];
        var hold = new HoldMessagingIntent(first.Code, first.Operation, first.Server, first.Peer);
        return Decision([hold], ordered, [new(1, MessagingTraceCode.Held, hold.Action)]);
    }

    private static MessagingDecision Decision(
        IEnumerable<MessagingIntent> intents,
        IEnumerable<MessagingError> errors,
        IEnumerable<MessagingTrace> trace) => new(
        new ReadOnlyCollection<MessagingIntent>(intents.ToArray()),
        new ReadOnlyCollection<MessagingError>(errors.ToArray()),
        new ReadOnlyCollection<MessagingTrace>(trace.ToArray()));

    private static IReadOnlyList<MessagingTrace> Trace(IReadOnlyList<MessagingIntent> intents, MessagingTraceCode code) =>
        new ReadOnlyCollection<MessagingTrace>(intents.Select((intent, index) => new MessagingTrace(index + 1, code, intent.Action)).ToArray());

    private static MessagingError Error(MessagingErrorCode code, ReplacementOperation? operation = null) =>
        new(code, Requirement, operation?.OperationId, operation?.FailedServer, operation?.FailedPeer);
}
