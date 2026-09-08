using CodeSignAuto.Service.Jobs;

namespace CodeSignAuto.Service.Api;

internal sealed class MultipartFileSectionStream : Stream
{
    private readonly Stream _inner;
    private readonly long _maxBytes;
    private readonly byte[] _probe = new byte[1];
    private long _bytesRead;
    private bool _completed;

    public MultipartFileSectionStream(Stream inner, long maxBytes)
    {
        ArgumentNullException.ThrowIfNull(inner);
        if (maxBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxBytes));
        }

        _inner = inner;
        _maxBytes = maxBytes;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => _bytesRead;
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.Length == 0 || _completed)
        {
            return 0;
        }

        if (_bytesRead < _maxBytes)
        {
            var allowed = (int)Math.Min(buffer.Length, _maxBytes - _bytesRead);
            var read = _inner.Read(buffer[..allowed]);
            _bytesRead += read;
            _completed = read == 0;
            return read;
        }

        if (_inner.Read(_probe, 0, 1) == 0)
        {
            _completed = true;
            return 0;
        }

        throw new SpoolException("file_too_large");
    }

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        if (buffer.Length == 0 || _completed)
        {
            return 0;
        }

        if (_bytesRead < _maxBytes)
        {
            var allowed = (int)Math.Min(buffer.Length, _maxBytes - _bytesRead);
            var read = await _inner.ReadAsync(buffer[..allowed], cancellationToken).ConfigureAwait(false);
            _bytesRead += read;
            _completed = read == 0;
            return read;
        }

        if (await _inner.ReadAsync(_probe.AsMemory(0, 1), cancellationToken).ConfigureAwait(false) == 0)
        {
            _completed = true;
            return 0;
        }

        throw new SpoolException("file_too_large");
    }

    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
