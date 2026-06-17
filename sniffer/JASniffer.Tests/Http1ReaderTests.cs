using System.Text;
using JASniffer.Proxy;

namespace JASniffer.Tests;

public class Http1ReaderTests
{
    private static Http1Reader Reader(string data) => new(new MemoryStream(Encoding.Latin1.GetBytes(data)));

    /// <summary>A stream that hands out its content one fixed-size slice per read,
    /// to exercise the reader's buffering across multiple fills.</summary>
    private sealed class DripStream(byte[] data, int dripSize) : Stream
    {
        private int _pos;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _pos; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_pos >= data.Length) return 0;
            var n = Math.Min(Math.Min(dripSize, count), data.Length - _pos);
            Array.Copy(data, _pos, buffer, offset, n);
            _pos += n;
            return n;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (_pos >= data.Length) return ValueTask.FromResult(0);
            var n = Math.Min(Math.Min(dripSize, buffer.Length), data.Length - _pos);
            data.AsMemory(_pos, n).CopyTo(buffer);
            _pos += n;
            return ValueTask.FromResult(n);
        }
        public override long Seek(long o, SeekOrigin g) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException();
        public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
    }

    [Fact]
    public async Task ReadHeaderBlock_ReturnsBlockWithoutTerminator()
    {
        var reader = Reader("GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY");
        var block = await reader.ReadHeaderBlockAsync(default);
        Assert.Equal("GET / HTTP/1.1\r\nHost: x", block);
    }

    [Fact]
    public async Task ReadHeaderBlock_EofReturnsNull()
    {
        var reader = Reader("");
        Assert.Null(await reader.ReadHeaderBlockAsync(default));
    }

    [Fact]
    public async Task ReadHeaderBlock_SplitAcrossManyReads()
    {
        var bytes = Encoding.Latin1.GetBytes("POST /a HTTP/1.1\r\nHost: y\r\nX: 1\r\n\r\n");
        var reader = new Http1Reader(new DripStream(bytes, dripSize: 3));
        var block = await reader.ReadHeaderBlockAsync(default);
        Assert.Equal("POST /a HTTP/1.1\r\nHost: y\r\nX: 1", block);
    }

    [Fact]
    public async Task ReadExactly_PullsExactCountAcrossBufferAndStream()
    {
        var reader = Reader("HEADERLINE\r\n\r\n0123456789");
        await reader.ReadHeaderBlockAsync(default);
        var body = await reader.ReadExactlyAsync(10, default);
        Assert.Equal("0123456789", Encoding.Latin1.GetString(body));
    }

    [Fact]
    public async Task ReadExactly_ThrowsOnShortStream()
    {
        var reader = Reader("H\r\n\r\nshort");
        await reader.ReadHeaderBlockAsync(default);
        await Assert.ThrowsAsync<EndOfStreamException>(() => reader.ReadExactlyAsync(100, default));
    }

    [Fact]
    public async Task ReadChunked_DecodesBodyAndConsumesTrailers()
    {
        // "Wikipedia" classic chunked example, plus a trailer line.
        var chunked = "H\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nTrailer: v\r\n\r\n";
        var reader = Reader(chunked);
        await reader.ReadHeaderBlockAsync(default);
        var body = await reader.ReadChunkedAsync(default);
        Assert.Equal("Wikipedia in\r\n\r\nchunks.", Encoding.Latin1.GetString(body));
    }

    [Fact]
    public async Task ReadChunked_MalformedSize_Throws()
    {
        var reader = Reader("H\r\n\r\nZZZ\r\ndata\r\n");
        await reader.ReadHeaderBlockAsync(default);
        await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadChunkedAsync(default));
    }

    [Fact]
    public async Task DrainBuffered_ReturnsLeftoverAfterHeader()
    {
        var reader = Reader("H\r\n\r\nleftover-bytes");
        await reader.ReadHeaderBlockAsync(default);
        var leftover = reader.DrainBuffered();
        Assert.Equal("leftover-bytes", Encoding.Latin1.GetString(leftover));
        Assert.Empty(reader.DrainBuffered()); // idempotent: nothing left
    }

    [Fact]
    public async Task ReadLine_ReturnsLinesWithoutTerminator()
    {
        var reader = Reader("first\r\nsecond\r\n");
        Assert.Equal("first", await reader.ReadLineAsync(default));
        Assert.Equal("second", await reader.ReadLineAsync(default));
    }

    [Fact]
    public async Task ReadHeaderBlock_OverLimit_Throws()
    {
        // 300 KB with no blank line trips the 256 KB header guard.
        var huge = new string('a', 300 * 1024);
        var reader = Reader(huge);
        await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadHeaderBlockAsync(default));
    }
}
