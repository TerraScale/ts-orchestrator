using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace TsOrch.Edge;

internal enum ClientHelloStatus
{
    NeedMoreData,
    Invalid,
    Complete,
}

internal static class TlsClientHello
{
    private const byte HandshakeRecord = 0x16;
    private const byte TlsMajorVersion = 0x03;
    private const byte ClientHelloMessage = 0x01;
    private const int RecordHeaderLength = 5;
    private const int HandshakeHeaderLength = 4;
    private const int MaxRecordLength = 16 * 1024;
    private const int MaxHandshakeLength = 64 * 1024;
    private const int ServerNameExtension = 0x0000;
    private const int HostNameType = 0x00;
    private const int MaxHostNameLength = 255;

    public static ClientHelloStatus TryReadServerName(ReadOnlySequence<byte> buffer, out string? serverName)
    {
        serverName = null;
        ReadOnlySpan<byte> data = buffer.IsSingleSegment ? buffer.FirstSpan : buffer.ToArray();
        var assembled = new ArrayBufferWriter<byte>();
        var offset = 0;
        while (true)
        {
            if (data.Length - offset < RecordHeaderLength)
            {
                return ClientHelloStatus.NeedMoreData;
            }

            var header = data.Slice(offset, RecordHeaderLength);
            if (header[0] != HandshakeRecord || header[1] != TlsMajorVersion)
            {
                return ClientHelloStatus.Invalid;
            }

            var recordLength = BinaryPrimitives.ReadUInt16BigEndian(header[3..]);
            if (recordLength is 0 or > MaxRecordLength)
            {
                return ClientHelloStatus.Invalid;
            }

            if (data.Length - offset - RecordHeaderLength < recordLength)
            {
                return ClientHelloStatus.NeedMoreData;
            }

            assembled.Write(data.Slice(offset + RecordHeaderLength, recordLength));
            offset += RecordHeaderLength + recordLength;
            var handshake = assembled.WrittenSpan;
            if (handshake.Length < HandshakeHeaderLength)
            {
                continue;
            }

            if (handshake[0] != ClientHelloMessage)
            {
                return ClientHelloStatus.Invalid;
            }

            var messageLength = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
            if (messageLength > MaxHandshakeLength)
            {
                return ClientHelloStatus.Invalid;
            }

            if (handshake.Length - HandshakeHeaderLength >= messageLength)
            {
                return ParseClientHello(handshake.Slice(HandshakeHeaderLength, messageLength), out serverName);
            }
        }
    }

    private static ClientHelloStatus ParseClientHello(ReadOnlySpan<byte> hello, out string? serverName)
    {
        serverName = null;
        var cursor = new Cursor(hello);
        if (!cursor.TrySkip(2 + 32)
            || !cursor.TryReadUInt8(out var sessionIdLength) || !cursor.TrySkip(sessionIdLength)
            || !cursor.TryReadUInt16(out var cipherSuitesLength) || !cursor.TrySkip(cipherSuitesLength)
            || !cursor.TryReadUInt8(out var compressionLength) || !cursor.TrySkip(compressionLength))
        {
            return ClientHelloStatus.Invalid;
        }

        if (cursor.IsEmpty)
        {
            return ClientHelloStatus.Complete;
        }

        if (!cursor.TryReadUInt16(out var extensionsLength) || !cursor.TryReadSlice(extensionsLength, out var extensionBytes))
        {
            return ClientHelloStatus.Invalid;
        }

        var extensions = new Cursor(extensionBytes);
        while (!extensions.IsEmpty)
        {
            if (!extensions.TryReadUInt16(out var type)
                || !extensions.TryReadUInt16(out var length)
                || !extensions.TryReadSlice(length, out var body))
            {
                return ClientHelloStatus.Invalid;
            }

            if (type == ServerNameExtension)
            {
                return ReadServerName(body, out serverName);
            }
        }

        return ClientHelloStatus.Complete;
    }

    private static ClientHelloStatus ReadServerName(ReadOnlySpan<byte> extension, out string? serverName)
    {
        serverName = null;
        var cursor = new Cursor(extension);
        if (!cursor.TryReadUInt16(out var listLength) || !cursor.TryReadSlice(listLength, out var listBytes))
        {
            return ClientHelloStatus.Invalid;
        }

        var names = new Cursor(listBytes);
        while (!names.IsEmpty)
        {
            if (!names.TryReadUInt8(out var nameType)
                || !names.TryReadUInt16(out var nameLength)
                || !names.TryReadSlice(nameLength, out var name))
            {
                return ClientHelloStatus.Invalid;
            }

            if (nameType != HostNameType)
            {
                continue;
            }

            if (name.IsEmpty || name.Length > MaxHostNameLength || !Ascii.IsValid(name))
            {
                return ClientHelloStatus.Invalid;
            }

            serverName = Encoding.ASCII.GetString(name);
            return ClientHelloStatus.Complete;
        }

        return ClientHelloStatus.Complete;
    }

    private ref struct Cursor(ReadOnlySpan<byte> data)
    {
        private ReadOnlySpan<byte> _remaining = data;

        public readonly bool IsEmpty => _remaining.IsEmpty;

        public bool TrySkip(int count) => TryReadSlice(count, out _);

        public bool TryReadUInt8(out int value)
        {
            if (_remaining.IsEmpty)
            {
                value = 0;
                return false;
            }

            value = _remaining[0];
            _remaining = _remaining[1..];
            return true;
        }

        public bool TryReadUInt16(out int value)
        {
            if (_remaining.Length < 2)
            {
                value = 0;
                return false;
            }

            value = BinaryPrimitives.ReadUInt16BigEndian(_remaining);
            _remaining = _remaining[2..];
            return true;
        }

        public bool TryReadSlice(int length, out ReadOnlySpan<byte> slice)
        {
            if (_remaining.Length < length)
            {
                slice = default;
                return false;
            }

            slice = _remaining[..length];
            _remaining = _remaining[length..];
            return true;
        }
    }
}
