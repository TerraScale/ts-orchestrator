using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TerraScale.Orchestrator.Protocol;

/// <summary>
/// Canonical versioned representation of every command field covered by a signature. Length
/// prefixes and big-endian integers make the representation unambiguous across implementations.
/// </summary>
internal static class CommandSignedMaterialCodec
{
    private const int MaximumIdentifierCharacters = 16 * 1024;
    private const int MaximumIdentifierBytes = 48 * 1024;
    private const int MaximumPayloadBytes = 1024 * 1024;
    private const int MaximumDigestBytes = 128;
    private const int MaximumEncodedBytes = 2 * 1024 * 1024;
    private static readonly byte[] Magic = "TS-COMMAND-SIGNED-V1\0"u8.ToArray();
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static byte[] Encode(CommandSignedMaterial material)
    {
        ArgumentNullException.ThrowIfNull(material);
        Validate(material);
        var writer = new ArrayBufferWriter<byte>(1024);
        Write(writer, Magic);
        Write(writer, material.ProtocolVersion.Value);
        Write(writer, material.Cell.Value);
        Write(writer, material.AggregateId.Value);
        Write(writer, material.DesiredGeneration.Value);
        Write(writer, material.WriterEpoch.Value);
        Write(writer, material.OperationId.Value);
        Write(writer, material.IdempotencyKey.Value);
        Write(writer, material.IssuedAt.Ticks);
        Write(writer, material.IssuedAt.Offset.Ticks);
        Write(writer, material.ExpiresAt.Ticks);
        Write(writer, material.ExpiresAt.Offset.Ticks);
        Write(writer, material.Attempt.Value);
        Write(writer, material.Payload.Bytes);
        Write(writer, material.PayloadDigest.Bytes);
        if (writer.WrittenCount > MaximumEncodedBytes)
            throw new InvalidDataException("The canonical command signing material exceeded its bound.");
        return writer.WrittenSpan.ToArray();
    }

    internal static byte[] Hash(CommandSignedMaterial material) => SHA256.HashData(Encode(material));

    private static void Validate(CommandSignedMaterial material)
    {
        if (!material.ProtocolVersion.IsValid || !material.Cell.IsValid || !material.AggregateId.IsValid ||
            !material.DesiredGeneration.IsValid || !material.WriterEpoch.IsValid ||
            !material.OperationId.IsValid || !material.IdempotencyKey.IsValid || !material.Attempt.IsValid ||
            material.ExpiresAt < material.IssuedAt || material.Payload is null ||
            material.Payload.Length is < 1 or > MaximumPayloadBytes ||
            material.PayloadDigest is not { IsValid: true } ||
            material.PayloadDigest.Length > MaximumDigestBytes)
            throw new InvalidDataException("The command signing material is invalid.");
    }

    private static void Write(ArrayBufferWriter<byte> writer, string value)
    {
        if (value.Length > MaximumIdentifierCharacters)
            throw new InvalidDataException("A command signing identity exceeded its bound.");
        int count;
        try
        {
            count = Utf8.GetByteCount(value);
        }
        catch (EncoderFallbackException exception)
        {
            throw new InvalidDataException("A command signing identity is not valid UTF-8.", exception);
        }
        if (count > MaximumIdentifierBytes)
            throw new InvalidDataException("A command signing identity exceeded its bound.");
        WriteLength(writer, count);
        try
        {
            var destination = writer.GetSpan(count);
            var written = Utf8.GetBytes(value, destination);
            writer.Advance(written);
        }
        catch (EncoderFallbackException exception)
        {
            throw new InvalidDataException("A command signing identity is not valid UTF-8.", exception);
        }
    }

    private static void Write(ArrayBufferWriter<byte> writer, long value)
    {
        var destination = writer.GetSpan(sizeof(long));
        BinaryPrimitives.WriteInt64BigEndian(destination, value);
        writer.Advance(sizeof(long));
    }

    private static void Write(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        WriteLength(writer, value.Length);
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private static void WriteLength(ArrayBufferWriter<byte> writer, int value)
    {
        var destination = writer.GetSpan(sizeof(int));
        BinaryPrimitives.WriteInt32BigEndian(destination, value);
        writer.Advance(sizeof(int));
    }
}

