using System.Buffers;
using System.Buffers.Binary;
using System.Text;

namespace TsOrch.Agent;

internal static class DockerStreamDemultiplexer
{
    private const int HeaderSize = 8;

    public static async Task ReadFramesAsync(
        Stream stream,
        Func<LogChannel, ReadOnlyMemory<byte>, CancellationToken, ValueTask> onFrame,
        CancellationToken cancellationToken)
    {
        var header = new byte[HeaderSize];
        while (true)
        {
            var read = await stream.ReadAtLeastAsync(header, HeaderSize, throwOnEndOfStream: false, cancellationToken);
            if (read < HeaderSize)
            {
                return;
            }

            var channel = header[0] == 2 ? LogChannel.Stderr : LogChannel.Stdout;
            var size = (int)BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(4));
            if (size == 0)
            {
                continue;
            }

            var buffer = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                await stream.ReadExactlyAsync(buffer.AsMemory(0, size), cancellationToken);
                await onFrame(channel, buffer.AsMemory(0, size), cancellationToken);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }
}

internal sealed class LineAssembler(int maxLineChars)
{
    private readonly Decoder _decoder = Encoding.UTF8.GetDecoder();
    private readonly StringBuilder _pending = new();

    public async ValueTask AppendAsync(ReadOnlyMemory<byte> bytes, Func<string, CancellationToken, ValueTask> onLine, CancellationToken cancellationToken)
    {
        var chars = ArrayPool<char>.Shared.Rent(Encoding.UTF8.GetMaxCharCount(bytes.Length));
        try
        {
            var count = _decoder.GetChars(bytes.Span, chars, flush: false);
            var start = 0;
            for (var index = 0; index < count; index++)
            {
                if (chars[index] != '\n')
                {
                    continue;
                }

                _pending.Append(chars, start, index - start);
                await EmitAsync(onLine, cancellationToken);
                start = index + 1;
            }

            _pending.Append(chars, start, count - start);
            while (_pending.Length > maxLineChars)
            {
                var chunk = _pending.ToString(0, maxLineChars);
                _pending.Remove(0, maxLineChars);
                await onLine(chunk, cancellationToken);
            }
        }
        finally
        {
            ArrayPool<char>.Shared.Return(chars);
        }
    }

    public async ValueTask FlushAsync(Func<string, CancellationToken, ValueTask> onLine, CancellationToken cancellationToken)
    {
        if (_pending.Length > 0)
        {
            await EmitAsync(onLine, cancellationToken);
        }
    }

    private async ValueTask EmitAsync(Func<string, CancellationToken, ValueTask> onLine, CancellationToken cancellationToken)
    {
        if (_pending.Length > 0 && _pending[^1] == '\r')
        {
            _pending.Length--;
        }

        var line = _pending.ToString();
        _pending.Clear();
        await onLine(line, cancellationToken);
    }
}

internal sealed class BoundedTextCapture(int maxChars)
{
    private readonly Decoder _decoder = Encoding.UTF8.GetDecoder();
    private readonly StringBuilder _text = new();

    public bool Truncated { get; private set; }

    public void Append(ReadOnlySpan<byte> bytes)
    {
        if (Truncated)
        {
            return;
        }

        var chars = ArrayPool<char>.Shared.Rent(Encoding.UTF8.GetMaxCharCount(bytes.Length));
        try
        {
            var count = _decoder.GetChars(bytes, chars, flush: false);
            var room = maxChars - _text.Length;
            if (count > room)
            {
                _text.Append(chars, 0, room);
                Truncated = true;
                return;
            }

            _text.Append(chars, 0, count);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(chars);
        }
    }

    public override string ToString() => _text.ToString();
}
