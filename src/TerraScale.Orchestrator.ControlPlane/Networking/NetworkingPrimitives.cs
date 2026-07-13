using System.Globalization;

namespace TerraScale.Orchestrator.ControlPlane.Networking;

internal static class NetworkValueRules
{
    internal static bool Valid(string? value,int maximum)
    {
        if(maximum<=0||string.IsNullOrEmpty(value)||value.Length>maximum)return false;
        for(var i=0;i<value.Length;i++){var c=value[i];if(char.IsWhiteSpace(c)||char.IsControl(c))return false;
            if(char.IsHighSurrogate(c)){if(i+1>=value.Length||!char.IsLowSurrogate(value[++i]))return false;}else if(char.IsLowSurrogate(c))return false;}
        return true;
    }
}
public abstract record NetworkIdentity
{
    protected NetworkIdentity(string value)=>Value=value;
    public string Value{get;}
    public override string ToString()=>Value;
}
public sealed record NetworkCellId:NetworkIdentity{private NetworkCellId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkCellId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkId:NetworkIdentity{private NetworkId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkSubnetId:NetworkIdentity{private NetworkSubnetId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkSubnetId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkNodeId:NetworkIdentity{private NetworkNodeId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkNodeId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkWorkloadId:NetworkIdentity{private NetworkWorkloadId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkWorkloadId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkServiceId:NetworkIdentity{private NetworkServiceId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkServiceId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkEndpointId:NetworkIdentity{private NetworkEndpointId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkEndpointId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkRouteId:NetworkIdentity{private NetworkRouteId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkRouteId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkPeerId:NetworkIdentity{private NetworkPeerId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkPeerId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkTunnelId:NetworkIdentity{private NetworkTunnelId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkTunnelId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkDnsId:NetworkIdentity{private NetworkDnsId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkDnsId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkLoadBalancerId:NetworkIdentity{private NetworkLoadBalancerId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkLoadBalancerId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkBackendId:NetworkIdentity{private NetworkBackendId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkBackendId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkCertificateRef:NetworkIdentity{private NetworkCertificateRef(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkCertificateRef? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}
public sealed record NetworkOperationId:NetworkIdentity{private NetworkOperationId(string v):base(v){}public static bool TryCreate(string? v,int m,out NetworkOperationId? x){x=NetworkValueRules.Valid(v,m)?new(v!):null;return x is not null;}}

public readonly record struct NetworkOrdinal
{private NetworkOrdinal(ulong v)=>Value=v;public ulong Value{get;}public bool IsValid=>Value>0;public static bool TryCreate(ulong v,out NetworkOrdinal x){x=v>0?new(v):default;return x.IsValid;}public override string ToString()=>Value.ToString(CultureInfo.InvariantCulture);}
public readonly record struct NetworkPort
{private NetworkPort(ushort v)=>Value=v;public ushort Value{get;}public bool IsValid=>Value>0;public static bool TryCreate(ushort v,out NetworkPort x){x=v>0?new(v):default;return x.IsValid;}}
public sealed class NetworkAddress:IEquatable<NetworkAddress>
{
    private readonly byte[] _bytes;private NetworkAddress(byte[] bytes)=>_bytes=bytes;
    public static bool TryCreate(byte[]? bytes,out NetworkAddress? x){x=bytes is {Length:4 or 16}?new(bytes.ToArray()):null;return x is not null;}
    public int BitLength=>_bytes.Length*8;internal ReadOnlySpan<byte> Bytes=>_bytes;
    public bool Equals(NetworkAddress? other)=>other is not null&&_bytes.SequenceEqual(other._bytes);public override bool Equals(object? o)=>Equals(o);
    public override int GetHashCode(){var h=new HashCode();foreach(var b in _bytes)h.Add(b);return h.ToHashCode();}public override string ToString()=>"<network-address>";
}
public sealed class NetworkPrefix:IEquatable<NetworkPrefix>
{
    private NetworkPrefix(NetworkAddress address,byte bits){Address=address;Bits=bits;}public NetworkAddress Address{get;}public byte Bits{get;}
    public static bool TryCreate(NetworkAddress? address,byte bits,out NetworkPrefix? x)
    {x=null;if(address is null||bits>address.BitLength)return false;var bytes=address.Bytes;for(var bit=bits;bit<address.BitLength;bit++)if((bytes[bit/8]&(1<<(7-bit%8)))!=0)return false;x=new(address,bits);return true;}
    public bool Contains(NetworkPrefix other){if(Address.BitLength!=other.Address.BitLength||Bits>other.Bits)return false;for(var bit=0;bit<Bits;bit++)if((Address.Bytes[bit/8]&(1<<(7-bit%8)))!=(other.Address.Bytes[bit/8]&(1<<(7-bit%8))))return false;return true;}
    public bool Overlaps(NetworkPrefix other)=>Contains(other)||other.Contains(this);
    public bool Equals(NetworkPrefix? other)=>other is not null&&Bits==other.Bits&&Address.Equals(other.Address);public override bool Equals(object? o)=>Equals(o);public override int GetHashCode()=>HashCode.Combine(Address,Bits);public override string ToString()=>"<network-prefix>";
}

public enum NetworkExposure{Unknown=0,Private,Workload,Public}
public enum NetworkProtocol{Unknown=0,Tcp,Udp,Http,Https}
public enum NetworkTrustPlane{Unknown=0,Control,Product,Telemetry}
public enum NetworkRouteKind{Unknown=0,Local,Peer,ExplicitReplication,EmergencyWithdrawal}
public enum NetworkTunnelState{Unknown=0,Staged,Healthy,Failed}
public enum NetworkBackendState{Unknown=0,Admitted,Registered,Promoted,Deregistered,Drained}
public enum NetworkHealth{Unknown=0,Healthy,Unhealthy,Stale}
public enum NetworkServiceKind{Unknown=0,Product,Monitoring,Administration}
public enum NetworkTopologyShape{Unknown=0,InitialThreeFullMesh,HubAndSpoke,ExplicitReplication}
public enum NetworkProof{Unknown=0,Proven,Contradicted}
public enum NetworkAction{Uninitialized=0,Observe,ConfigureRoute,ConfigureTunnel,Register,Deregister,Promote,DnsUpdate,Rollback,Hold,Verify}
public enum NetworkTarget{None=0,Route,Tunnel,Backend,LoadBalancer,Dns,Ingress,LocalService}
public enum NetworkCode{Uninitialized=0,NextStep,Completed,InvalidInput,WrongEvidenceScope,StaleGeneration,FutureGeneration,Overlap,AmbiguousOwnership,Duplicate,RouteLeak,TrustPlaneCrossover,Reflection,QuadraticMesh,PartitionAuthorityDenied,LocalPolicyRequired,TunnelHealthRequired,DefaultDeny,PublicApprovalRequired,ForbiddenExposure,CertificateMismatch,ReadinessRequired,BackendHealthRequired,DnsConvergencePending,DeregisterBeforeDrain,EmergencyWithdrawal}

public sealed record NetworkNumericTrace(NetworkOrdinal Generation,NetworkOrdinal Epoch,uint RouteCount,uint PeerCount)
{public override string ToString()=>string.Create(CultureInfo.InvariantCulture,$"generation={Generation.Value};epoch={Epoch.Value};routes={RouteCount};peers={PeerCount}");}

public abstract record NetworkIntentSubject{private protected NetworkIntentSubject(){}public override string ToString()=>"<network-intent-subject>";}
public sealed record NetworkRouteIntentSubject(NetworkCellId Cell,NetworkCellId PeerCell,NetworkId Network,NetworkSubnetId Subnet,NetworkRouteId Route,
    NetworkPeerId Peer,NetworkTunnelId Tunnel,NetworkTrustPlane TrustPlane,NetworkRouteKind RouteKind,NetworkPrefix Destination,
    NetworkOrdinal Generation,NetworkOrdinal Epoch,NetworkOperationId Operation):NetworkIntentSubject{public override string ToString()=>"<network-route-intent>";}
public sealed record NetworkEndpointIntentSubject(NetworkCellId Cell,NetworkWorkloadId Workload,NetworkServiceId Service,
    NetworkEndpointId Endpoint,NetworkNodeId Node,NetworkLoadBalancerId LoadBalancer,NetworkBackendId Backend,NetworkDnsId Dns,
    NetworkCertificateRef Certificate,NetworkServiceKind ServiceKind,NetworkExposure Exposure,NetworkProtocol Protocol,NetworkPort Port,
    NetworkOrdinal ServiceGeneration,NetworkOrdinal Epoch,NetworkOperationId Operation):NetworkIntentSubject{public override string ToString()=>"<network-endpoint-intent>";}
public readonly record struct NetworkDecision
{
    private NetworkDecision(NetworkAction a,NetworkTarget t,NetworkCode c,NetworkIntentSubject? s,NetworkNumericTrace? x){Action=a;Target=t;Code=c;Subject=s;Trace=x;}
    public NetworkAction Action{get;}public NetworkTarget Target{get;}public NetworkCode Code{get;}public NetworkIntentSubject? Subject{get;}public NetworkNumericTrace? Trace{get;}
    public bool IsMutationAuthorized=>Action is NetworkAction.ConfigureRoute or NetworkAction.ConfigureTunnel or NetworkAction.Register or NetworkAction.Deregister or NetworkAction.Promote or NetworkAction.DnsUpdate or NetworkAction.Rollback;
    internal static NetworkDecision Emit(NetworkAction a,NetworkTarget t,NetworkCode c,NetworkIntentSubject s,NetworkNumericTrace x)=>new(a,t,c,s,x);
    internal static NetworkDecision Hold(NetworkCode c,NetworkNumericTrace? x=null)=>new(NetworkAction.Hold,NetworkTarget.None,c,null,x);
}
