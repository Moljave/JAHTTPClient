using System.Text;

namespace JASniffer.Proxy;

/// <summary>
/// A minimal, allocation-conscious HTTP/1.1 reader over a byte stream. It buffers
/// from the underlying stream and hands back the header block, then the body
/// (sized by <c>Content-Length</c> or decoded from <c>chunked</c> framing). Any
/// bytes read past what was consumed can be reclaimed via <see cref="DrainBuffered"/>
/// when switching a connection over to a raw tunnel.
/// </summary>
internal sealed class Http1Reader(Stream stream)
{
    private const int MaxHeaderBytes = 256 * 1024;

    private byte[] _buf = new byte[16 * 1024];
    private int _pos;
    private int _len;

    /// <summary>
    /// Reads up to the next blank line and returns the header block (request/status
    /// line + headers, terminator stripped), or <c>null</c> at a clean end of
    /// stream. The body, if any, remains buffered for a subsequent body read.
    /// </summary>
    public async Task<string?> ReadHeaderBlockAsync(CancellationToken ct)
    {
        while (true)
        {
            var idx = IndexOfDoubleCrlf();
            if (idx >= 0)
            {
                var block = Encoding.Latin1.GetString(_buf, _pos, idx - _pos);
                _pos = idx + 4;
                return block;
            }

            if (_len - _pos > MaxHeaderBytes)
            {
                throw new InvalidDataException("HTTP header block exceeds the maximum allowed size.");
            }

            if (!await FillAsync(ct).ConfigureAwait(false))
            {
                return null; // EOF (clean if nothing buffered, otherwise a truncated head we can't use)
            }
        }
    }

    /// <summary>Reads exactly <paramref name="count"/> body bytes (from buffer first, then the stream).</summary>
    public async Task<byte[]> ReadExactlyAsync(int count, CancellationToken ct)
    {
        var result = new byte[count];
        var got = 0;
        while (got < count)
        {
            if (_pos < _len)
            {
                var take = Math.Min(_len - _pos, count - got);
                Array.Copy(_buf, _pos, result, got, take);
                _pos += take;
                got += take;
            }
            else if (!await FillAsync(ct).ConfigureAwait(false))
            {
                throw new EndOfStreamException("Connection closed before the full body was received.");
            }
        }

        return result;
    }

    /// <summary>Reads and de-chunks a <c>Transfer-Encoding: chunked</c> body.</summary>
    public async Task<byte[]> ReadChunkedAsync(CancellationToken ct)
    {
        using var body = new MemoryStream();
        while (true)
        {
            var sizeLine = await ReadLineAsync(ct).ConfigureAwait(false);
            var semi = sizeLine.IndexOf(';');
            if (semi >= 0)
            {
                sizeLine = sizeLine[..semi];
            }

            if (!int.TryParse(sizeLine.Trim(), System.Globalization.NumberStyles.HexNumber, null, out var size) || size < 0)
            {
                throw new InvalidDataException($"Malformed chunk size: '{sizeLine}'.");
            }

            if (size == 0)
            {
                // Consume optional trailers up to the final blank line.
                while ((await ReadLineAsync(ct).ConfigureAwait(false)).Length > 0)
                {
                }

                break;
            }

            var chunk = await ReadExactlyAsync(size, ct).ConfigureAwait(false);
            body.Write(chunk, 0, chunk.Length);
            await ReadLineAsync(ct).ConfigureAwait(false); // trailing CRLF after the chunk data
        }

        return body.ToArray();
    }

    /// <summary>Reads a single CRLF-terminated line (terminator stripped).</summary>
    public async Task<string> ReadLineAsync(CancellationToken ct)
    {
        while (true)
        {
            var idx = IndexOfCrlf();
            if (idx >= 0)
            {
                var line = Encoding.Latin1.GetString(_buf, _pos, idx - _pos);
                _pos = idx + 2;
                return line;
            }

            if (!await FillAsync(ct).ConfigureAwait(false))
            {
                var tail = Encoding.Latin1.GetString(_buf, _pos, _len - _pos);
                _pos = _len;
                return tail;
            }
        }
    }

    /// <summary>Returns and clears any bytes already buffered but not yet consumed.</summary>
    public byte[] DrainBuffered()
    {
        if (_pos >= _len)
        {
            return [];
        }

        var leftover = new byte[_len - _pos];
        Array.Copy(_buf, _pos, leftover, 0, leftover.Length);
        _pos = _len = 0;
        return leftover;
    }

    private int IndexOfDoubleCrlf()
    {
        for (var i = _pos; i + 3 < _len; i++)
        {
            if (_buf[i] == '\r' && _buf[i + 1] == '\n' && _buf[i + 2] == '\r' && _buf[i + 3] == '\n')
            {
                return i;
            }
        }

        return -1;
    }

    private int IndexOfCrlf()
    {
        for (var i = _pos; i + 1 < _len; i++)
        {
            if (_buf[i] == '\r' && _buf[i + 1] == '\n')
            {
                return i;
            }
        }

        return -1;
    }

    private async Task<bool> FillAsync(CancellationToken ct)
    {
        if (_pos > 0)
        {
            // Compact unread bytes to the front before pulling more.
            Array.Copy(_buf, _pos, _buf, 0, _len - _pos);
            _len -= _pos;
            _pos = 0;
        }

        if (_len == _buf.Length)
        {
            Array.Resize(ref _buf, _buf.Length * 2);
        }

        var n = await stream.ReadAsync(_buf.AsMemory(_len), ct).ConfigureAwait(false);
        if (n == 0)
        {
            return false;
        }

        _len += n;
        return true;
    }
}
