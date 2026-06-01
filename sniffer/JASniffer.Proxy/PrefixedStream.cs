namespace JASniffer.Proxy;

/// <summary>
/// A read-through stream that first replays a fixed byte prefix and then defers to
/// an inner stream. Used to hand bytes that were already buffered out of the raw
/// socket (e.g. the first bytes of a TLS ClientHello pipelined right after a
/// <c>CONNECT</c>) to <see cref="System.Net.Security.SslStream"/> without losing
/// them. Writes/flush pass straight through to the inner stream.
/// </summary>
internal sealed class PrefixedStream(byte[] prefix, Stream inner) : Stream
{
    private int _prefixPos;

    public override bool CanRead => true;
    public override bool CanWrite => inner.CanWrite;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_prefixPos < prefix.Length)
        {
            var n = Math.Min(count, prefix.Length - _prefixPos);
            Array.Copy(prefix, _prefixPos, buffer, offset, n);
            _prefixPos += n;
            return n;
        }

        return inner.Read(buffer, offset, count);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_prefixPos < prefix.Length)
        {
            var n = Math.Min(buffer.Length, prefix.Length - _prefixPos);
            prefix.AsMemory(_prefixPos, n).CopyTo(buffer);
            _prefixPos += n;
            return n;
        }

        return await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => inner.WriteAsync(buffer, cancellationToken);

    public override void Flush() => inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
