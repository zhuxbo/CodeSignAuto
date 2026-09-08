using System.Net;
using CodeSignAuto.Service.Api;
using CodeSignAuto.Service.Jobs;
using Xunit;

namespace CodeSignAuto.Service.Tests;

public sealed class MultipartLimitContractTests
{
    [Fact]
    public void Exact_max_file_with_real_multipart_framing_fits_the_bounded_request_contract()
    {
        using var multipart = new MultipartFormDataContent(new string('b', JobEndpoints.MaxBoundaryBytes));
        multipart.Add(new StringContent(
            "{\"kind\":\"pdf\",\"certificateSerialNumber\":\"6F09D233\",\"digestAlgorithm\":\"sha256\",\"page\":1,\"box\":[10,10,100,50],\"fieldName\":\"Signature1\"}"),
            "parameters");
        multipart.Add(new LengthOnlyContent(JobEndpoints.MaxFileBytes), "file", "document.pdf");

        var contentLength = Assert.IsType<long>(multipart.Headers.ContentLength);

        Assert.True(contentLength > JobEndpoints.MaxFileBytes);
        Assert.True(contentLength <= JobEndpoints.MaxRequestBodyBytes);
        Assert.Equal(
            JobEndpoints.MaxFileBytes + JobEndpoints.MaxMultipartOverheadBytes,
            JobEndpoints.MaxRequestBodyBytes);
    }

    [Fact]
    public async Task File_section_limiter_accepts_exact_max_and_reads_only_one_byte_past_limit()
    {
        var exactSource = new GeneratedLengthStream(JobEndpoints.MaxFileBytes);
        await using (var exact = new MultipartFileSectionStream(exactSource, JobEndpoints.MaxFileBytes))
        {
            Assert.Equal(JobEndpoints.MaxFileBytes, await DrainAsync(exact));
        }

        Assert.Equal(JobEndpoints.MaxFileBytes, exactSource.BytesRead);

        var oversizedSource = new GeneratedLengthStream(JobEndpoints.MaxFileBytes + 1024 * 1024);
        await using var oversized = new MultipartFileSectionStream(oversizedSource, JobEndpoints.MaxFileBytes);
        var error = await Assert.ThrowsAsync<SpoolException>(() => DrainAsync(oversized));

        Assert.Equal("file_too_large", error.Code);
        Assert.Equal(JobEndpoints.MaxFileBytes + 1, oversizedSource.BytesRead);
    }

    [Fact]
    public void Synchronous_file_section_limiter_accepts_exact_limit_and_probes_only_one_extra_byte()
    {
        var exactSource = new GeneratedLengthStream(3);
        using (var exact = new MultipartFileSectionStream(exactSource, 3))
        {
            var buffer = new byte[8];
            Assert.Equal(3, exact.Read(buffer, 0, buffer.Length));
            Assert.Equal(0, exact.Read(buffer.AsSpan()));
            Assert.Equal(3, exact.Position);
        }

        var oversizedSource = new GeneratedLengthStream(5);
        using var oversized = new MultipartFileSectionStream(oversizedSource, 3);
        Assert.Equal(3, oversized.Read(new byte[3], 0, 3));
        var error = Assert.Throws<SpoolException>(() => oversized.Read(new byte[1], 0, 1));

        Assert.Equal("file_too_large", error.Code);
        Assert.Equal(4, oversizedSource.BytesRead);
    }

    [Fact]
    public async Task Empty_reads_completion_and_unsupported_stream_operations_are_fail_closed()
    {
        Assert.Throws<ArgumentNullException>(() => new MultipartFileSectionStream(null!, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new MultipartFileSectionStream(Stream.Null, -1));
        using var stream = new MultipartFileSectionStream(new MemoryStream([]), 0);
        var empty = Array.Empty<byte>();

        Assert.Equal(0, stream.Read(empty, 0, 0));
        Assert.Equal(0, await stream.ReadAsync(empty));
        Assert.True(stream.CanRead);
        Assert.False(stream.CanSeek);
        Assert.False(stream.CanWrite);
        Assert.Throws<NotSupportedException>(() => _ = stream.Length);
        Assert.Throws<NotSupportedException>(() => stream.Position = 0);
        Assert.Throws<NotSupportedException>(() => stream.Flush());
        Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
        Assert.Throws<NotSupportedException>(() => stream.SetLength(0));
        Assert.Throws<NotSupportedException>(() => stream.Write(empty, 0, 0));
    }

    private static async Task<long> DrainAsync(Stream stream)
    {
        var buffer = new byte[1024 * 1024];
        long total = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer);
            if (read == 0)
            {
                return total;
            }

            total += read;
        }
    }

    private sealed class LengthOnlyContent(long length) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            throw new NotSupportedException("Length-only multipart evidence must not serialize the 512 MiB fixture.");

        protected override bool TryComputeLength(out long computedLength)
        {
            computedLength = length;
            return true;
        }
    }

    private sealed class GeneratedLengthStream : Stream
    {
        private readonly long _length;
        private long _remaining;

        public GeneratedLengthStream(long length)
        {
            _length = length;
            _remaining = length;
        }

        public long BytesRead { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _length;
        public override long Position { get => BytesRead; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            var read = (int)Math.Min(buffer.Length, _remaining);
            _remaining -= read;
            BytesRead += read;
            return read;
        }

        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
