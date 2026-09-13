using System.Security.Cryptography;
using System.Text;
using TerraScale.Orchestrator.Delivery;

namespace TerraScale.Orchestrator.Tests;

public sealed class ForgejoWebhookVerifierTests
{
    private const string Repository = "TerraScale/TerraScale.Orchestrator";
    private const string Delivery = "f6266f16-1bf3-46a5-9ea4-602e06ead473";
    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");

    [Test]
    public async Task SignedPushProducesRepositoryBoundReplayEvidence()
    {
        var payload = Bytes("""
            {
              "ref": "refs/heads/develop",
              "before": "affe000000000000000000000000000000000001",
              "after": "bffeb74224043ba2feb48d137756c8a9331c449a",
              "repository": { "full_name": "TerraScale/TerraScale.Orchestrator" }
            }
            """);

        var result = Verify(payload, "push");

        await Assert.That(result.Accepted).IsTrue();
        await Assert.That(result.Error).IsEqualTo(ForgejoWebhookError.None);
        await Assert.That(result.Envelope!.Kind).IsEqualTo(ForgejoWebhookKind.Push);
        await Assert.That(result.Envelope.Repository).IsEqualTo(Repository);
        await Assert.That(result.Envelope.BaseRevision).IsEqualTo("affe000000000000000000000000000000000001");
        await Assert.That(result.Envelope.Revision).IsEqualTo("bffeb74224043ba2feb48d137756c8a9331c449a");
        await Assert.That(result.Envelope.SourceRef).IsEqualTo("refs/heads/develop");
        await Assert.That(result.Envelope.IsFork).IsFalse();
        await Assert.That(result.Envelope.DeliveryKey).IsEqualTo($"forgejo-delivery:{Repository}:{Delivery}");
        await Assert.That(result.Envelope.DedupeKey).StartsWith($"forgejo-payload:{Repository}:");
        await Assert.That(result.Envelope.PayloadSha256).Length().IsEqualTo(64);
    }

    [Test]
    public async Task SignedPullRequestPreservesUntrustedForkAndExactHeadRevision()
    {
        var payload = Bytes("""
            {
              "action": "synchronized",
              "number": 42,
              "repository": { "full_name": "TerraScale/TerraScale.Orchestrator" },
              "pull_request": {
                "head": {
                  "ref": "feature/native-ci",
                  "sha": "A123456789ABCDEF0123456789ABCDEF01234567",
                  "repo": { "full_name": "contributor/TerraScale.Orchestrator" }
                },
                "base": {
                  "ref": "develop",
                  "sha": "B123456789ABCDEF0123456789ABCDEF01234567",
                  "repo": { "full_name": "TerraScale/TerraScale.Orchestrator" }
                }
              }
            }
            """);

        var result = Verify(payload, "pull_request");

        await Assert.That(result.Accepted).IsTrue();
        await Assert.That(result.Envelope!.Action).IsEqualTo("synchronized");
        await Assert.That(result.Envelope.SourceRepository).IsEqualTo("contributor/TerraScale.Orchestrator");
        await Assert.That(result.Envelope.BaseRevision).IsEqualTo("b123456789abcdef0123456789abcdef01234567");
        await Assert.That(result.Envelope.Revision).IsEqualTo("a123456789abcdef0123456789abcdef01234567");
        await Assert.That(result.Envelope.SourceRef).IsEqualTo("feature/native-ci");
        await Assert.That(result.Envelope.TargetRef).IsEqualTo("develop");
        await Assert.That(result.Envelope.PullRequestNumber).IsEqualTo(42);
        await Assert.That(result.Envelope.IsFork).IsTrue();
    }

    [Test]
    public async Task SignatureIsVerifiedBeforeUntrustedJsonIsParsed()
    {
        var malformedPayload = Bytes("{ definitely-not-json");

        var result = ForgejoWebhookVerifier.Verify(
            malformedPayload,
            Secret,
            Repository,
            "application/json",
            new string('0', 64),
            Delivery,
            "push");

        await Assert.That(result.Error).IsEqualTo(ForgejoWebhookError.InvalidSignature);
        await Assert.That(result.Envelope).IsNull();
    }

    [Test]
    public async Task SignedPayloadCannotCrossRepositoryBoundaryOrUseAmbiguousFields()
    {
        var otherRepository = Bytes("""
            {"ref":"refs/heads/develop","before":"affe000000000000000000000000000000000001","after":"bffeb74224043ba2feb48d137756c8a9331c449a","repository":{"full_name":"other/repo"}}
            """);
        var duplicateRevision = Bytes("""
            {"ref":"refs/heads/develop","before":"affe000000000000000000000000000000000001","after":"bffeb74224043ba2feb48d137756c8a9331c449a","after":"0000000000000000000000000000000000000000","repository":{"full_name":"TerraScale/TerraScale.Orchestrator"}}
            """);

        await Assert.That(Verify(otherRepository, "push").Error).IsEqualTo(ForgejoWebhookError.RepositoryMismatch);
        await Assert.That(Verify(duplicateRevision, "push").Error).IsEqualTo(ForgejoWebhookError.MalformedPayload);
    }

    [Test]
    public async Task DeliveryAndSignedPayloadIdentitiesDetectReplayAndCollision()
    {
        var firstPayload = PushPayload("refs/heads/develop");
        var secondPayload = PushPayload("refs/heads/main");

        var first = Verify(firstPayload, "push").Envelope!;
        var second = Verify(secondPayload, "push").Envelope!;
        var alteredHeader = ForgejoWebhookVerifier.Verify(
            firstPayload,
            Secret,
            Repository,
            "application/json",
            Signature(firstPayload),
            "7c42695c-8540-4476-9ee3-6c2725647656",
            "push").Envelope!;

        await Assert.That(first.DeliveryKey).IsEqualTo(second.DeliveryKey);
        await Assert.That(first.DedupeKey).IsNotEqualTo(second.DedupeKey);
        await Assert.That(first.PayloadSha256).IsNotEqualTo(second.PayloadSha256);
        await Assert.That(first.DeliveryKey).IsNotEqualTo(alteredHeader.DeliveryKey);
        await Assert.That(first.DedupeKey).IsEqualTo(alteredHeader.DedupeKey);
    }

    [Test]
    public async Task TechnicalBoundsAndClosedEventVocabularyFailClosed()
    {
        var payload = PushPayload("refs/heads/develop");
        var shortSecret = Encoding.UTF8.GetBytes("too-short");

        var weak = ForgejoWebhookVerifier.Verify(payload, shortSecret, Repository, "application/json", Signature(payload), Delivery, "push");
        var wrongContent = ForgejoWebhookVerifier.Verify(payload, Secret, Repository, "text/plain", Signature(payload), Delivery, "push");
        var unsupported = Verify(payload, "issues");

        await Assert.That(weak.Error).IsEqualTo(ForgejoWebhookError.InvalidSecret);
        await Assert.That(wrongContent.Error).IsEqualTo(ForgejoWebhookError.UnsupportedContentType);
        await Assert.That(unsupported.Error).IsEqualTo(ForgejoWebhookError.UnsupportedEvent);
    }

    private static ForgejoWebhookVerification Verify(byte[] payload, string eventName) =>
        ForgejoWebhookVerifier.Verify(payload, Secret, Repository, "application/json; charset=utf-8", Signature(payload), Delivery, eventName);

    private static byte[] PushPayload(string reference) => Bytes($$$"""
        {"ref":"{{{reference}}}","before":"affe000000000000000000000000000000000001","after":"bffeb74224043ba2feb48d137756c8a9331c449a","repository":{"full_name":"TerraScale/TerraScale.Orchestrator"}}
        """);

    private static string Signature(byte[] payload) => Convert.ToHexStringLower(HMACSHA256.HashData(Secret, payload));
    private static byte[] Bytes(string value) => Encoding.UTF8.GetBytes(value);
}

