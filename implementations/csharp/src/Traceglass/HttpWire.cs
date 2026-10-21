using System.Globalization;
using System.Text;

namespace Traceglass;

internal sealed record WireRequest(string Method, string Target, Dictionary<string, string> Headers)
{
    public static async Task<WireRequest> Read(Stream stream, CancellationToken token)
    {
        var size = 0;
        async Task<string> Line()
        {
            var line = await HttpWire.Line(stream, 8192, token);
            size += line.Length + 2;
            if (size > 65536) throw new InvalidDataException("Headers too large");
            return line;
        }
        var start = (await Line()).Split(' ');
        if (start.Length != 3 || start[0].Length is < 1 or > 32 || !start[0].All(HttpWire.TokenChar) ||
            start[2] is not ("HTTP/1.0" or "HTTP/1.1") || start[1].Length == 0)
            throw new InvalidDataException("Invalid request line");
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await Line();
            if (line.Length == 0) break;
            var colon = line.IndexOf(':');
            if (colon <= 0 || !line[..colon].All(HttpWire.TokenChar) ||
                line[(colon + 1)..].Any(c => c < 32 && c != '\t' || c > 126))
                throw new InvalidDataException("Invalid header");
            var name = line[..colon];
            var value = line[(colon + 1)..].Trim();
            if (headers.TryGetValue(name, out var previous))
            {
                if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Duplicate framing/host header");
                headers[name] = previous + ", " + value;
            }
            else headers.Add(name, value);
        }
        if (!headers.ContainsKey("Host") || headers.ContainsKey("Content-Length") && headers.ContainsKey("Transfer-Encoding"))
            throw new InvalidDataException("Invalid framing or missing host");
        if (headers.TryGetValue("Content-Length", out var length) &&
            (!long.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n < 0))
            throw new InvalidDataException("Invalid length");
        if (headers.TryGetValue("Transfer-Encoding", out var encoding) && !encoding.Equals("chunked", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Unsupported transfer encoding");
        return new WireRequest(start[0], start[1], headers);
    }
}

internal static class HttpWire
{
    public static bool TokenChar(char c) => char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c);
    public static async Task<string> Line(Stream stream, int limit, CancellationToken token)
    {
        var data = new byte[limit];
        var single = new byte[1];
        var count = 0;
        while (count < limit)
        {
            if (await stream.ReadAsync(single, token) == 0) throw new EndOfStreamException();
            if (single[0] == '\n')
            {
                if (count == 0 || data[count - 1] != '\r') throw new InvalidDataException("Expected CRLF");
                return Encoding.ASCII.GetString(data, 0, count - 1);
            }
            if (single[0] > 127) throw new InvalidDataException("Non-ASCII header");
            data[count++] = single[0];
        }
        throw new InvalidDataException("Line too large");
    }
    public static ValueTask Write(Stream stream, string text, CancellationToken token) =>
        stream.WriteAsync(Encoding.ASCII.GetBytes(text), token);
    public static Task Error(Stream stream, int status, CancellationToken token) =>
        Write(stream, $"HTTP/1.1 {status} Proxy Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", token).AsTask();

    public static HashSet<string> HopHeaders(IEnumerable<KeyValuePair<string, string>> headers)
    {
        HashSet<string> result = new(StringComparer.OrdinalIgnoreCase)
        { "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length" };
        foreach (var header in headers)
            if (header.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase))
                foreach (var name in header.Value.Split(',')) result.Add(name.Trim());
        return result;
    }
}

internal sealed record WireResponse(int Status, List<KeyValuePair<string, string>> Headers)
{
    public static async Task<WireResponse> Read(Stream stream, CancellationToken token)
    {
        var start = await HttpWire.Line(stream, 8192, token);
        var parts = start.Split(' ', 3);
        if (parts.Length < 2 || parts[0] is not ("HTTP/1.0" or "HTTP/1.1") ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var status) || status is < 100 or > 599)
            throw new InvalidDataException("Invalid response line");
        List<KeyValuePair<string, string>> headers = [];
        var size = start.Length + 2;
        while (true)
        {
            var line = await HttpWire.Line(stream, 8192, token);
            size += line.Length + 2;
            if (size > 65536) throw new InvalidDataException("Response headers too large");
            if (line.Length == 0) break;
            var colon = line.IndexOf(':');
            if (colon <= 0 || !line[..colon].All(HttpWire.TokenChar) ||
                line[(colon + 1)..].Any(c => c < 32 && c != '\t' || c > 126))
                throw new InvalidDataException("Invalid response header");
            headers.Add(new(line[..colon], line[(colon + 1)..].Trim()));
        }
        var lengths = headers.Where(h => h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).ToArray();
        var encodings = headers.Where(h => h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (lengths.Length > 1 || encodings.Length > 1 || lengths.Length + encodings.Length > 1 ||
            lengths.Length == 1 && (!long.TryParse(lengths[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var length) || length < 0) ||
            encodings.Length == 1 && !encodings[0].Value.Equals("chunked", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Invalid response framing");
        return new(status, headers);
    }
}

internal sealed class RequestBody(Stream source, long length, bool chunked) : Stream
{
    private long remaining = length;
    private long chunkRemaining;
    private bool needChunkEnd;
    public long Count { get; private set; }
    public bool Complete { get; private set; } = !chunked && length == 0;
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.Length == 0 || Complete) return 0;
        if (chunked && chunkRemaining == 0)
        {
            if (needChunkEnd && await HttpWire.Line(source, 2, cancellationToken) != "")
                throw new InvalidDataException("Invalid chunk terminator");
            var line = await HttpWire.Line(source, 1024, cancellationToken);
            var number = line.Split(';')[0];
            if (!long.TryParse(number, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out chunkRemaining) || chunkRemaining < 0)
                throw new InvalidDataException("Invalid chunk size");
            if (chunkRemaining == 0)
            {
                var total = 0;
                while ((line = await HttpWire.Line(source, 8192, cancellationToken)).Length != 0)
                    if ((total += line.Length + 2) > 65536) throw new InvalidDataException("Trailers too large");
                Complete = true;
                return 0;
            }
            needChunkEnd = true;
        }
        var wanted = (int)Math.Min(buffer.Length, chunked ? chunkRemaining : remaining);
        var n = await source.ReadAsync(buffer[..wanted], cancellationToken);
        if (n == 0) throw new EndOfStreamException("Incomplete upload");
        Count += n;
        if (chunked) chunkRemaining -= n;
        else { remaining -= n; Complete = remaining == 0; }
        return n;
    }
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => Count; set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
