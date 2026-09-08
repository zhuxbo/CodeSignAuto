using System.Net.Http.Headers;
using System.Text;
using CodeSignAuto.Core.Jobs;
using UglyToad.PdfPig;

namespace CodeSignAuto.EndToEnd.Tests;

internal static class EndToEndFixtures
{
    private static readonly byte[] PdfBytes = CreateTwoPagePdf();

    public static byte[] TwoPagePdf => PdfBytes.ToArray();

    public static byte[] UnsignedPortableExecutable
    {
        get
        {
            var projectDirectory = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Parent!.Parent!;
            var repositoryRoot = projectDirectory.Parent!.Parent!.FullName;
            var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
            var path = Path.Combine(
                repositoryRoot,
                "tests",
                "CodeSignAuto.Agent.Tests",
                "Fixtures",
                "UnsignedHello",
                "bin",
                configuration,
                "net10.0-windows",
                "UnsignedHello.dll");
            var bytes = File.ReadAllBytes(path);
            if (!bytes.AsSpan().StartsWith("MZ"u8))
            {
                throw new InvalidOperationException("test_pe_fixture_invalid");
            }

            return bytes;
        }
    }

    public static HttpRequestMessage PdfRequest(
        string uri,
        byte[]? content = null,
        string? idempotencyKey = null,
        string fileName = "document.pdf",
        string? parametersJson = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, uri);
        if (idempotencyKey is not null)
        {
            request.Headers.TryAddWithoutValidation("Idempotency-Key", idempotencyKey);
        }

        var multipart = new MultipartFormDataContent("ssa-e2e-boundary-" + Guid.NewGuid().ToString("N"));
        var parameters = new StringContent(
            parametersJson ?? SigningParameters.SerializeCanonical(PdfParameters()),
            Encoding.UTF8,
            "application/json");
        multipart.Add(parameters, "parameters");
        var file = new ByteArrayContent(content ?? PdfBytes);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        multipart.Add(file, "file", fileName);
        request.Content = multipart;
        return request;
    }

    public static PdfParameters PdfParameters() => new(
        "CC00",
        "sha256",
        1,
        new PdfBox(10, 10, 100, 50),
        "Signature1",
        null,
        null);

    private static byte[] CreateTwoPagePdf()
    {
        var objects = new[]
        {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>",
        };
        using var stream = new MemoryStream();
        using var writer = new StreamWriter(stream, Encoding.ASCII, leaveOpen: true)
        {
            NewLine = "\n",
        };
        writer.WriteLine("%PDF-1.4");
        writer.Flush();
        var offsets = new List<long> { 0 };
        for (var index = 0; index < objects.Length; index++)
        {
            offsets.Add(stream.Position);
            writer.WriteLine($"{index + 1} 0 obj");
            writer.WriteLine(objects[index]);
            writer.WriteLine("endobj");
            writer.Flush();
        }

        var xref = stream.Position;
        writer.WriteLine("xref");
        writer.WriteLine($"0 {objects.Length + 1}");
        writer.WriteLine("0000000000 65535 f ");
        foreach (var offset in offsets.Skip(1))
        {
            writer.WriteLine($"{offset:0000000000} 00000 n ");
        }

        writer.WriteLine("trailer");
        writer.WriteLine($"<< /Size {objects.Length + 1} /Root 1 0 R >>");
        writer.WriteLine("startxref");
        writer.WriteLine(xref);
        writer.WriteLine("%%EOF");
        writer.Flush();
        var bytes = stream.ToArray();
        using var document = PdfDocument.Open(bytes);
        if (document.NumberOfPages != 2)
        {
            throw new InvalidOperationException("test_pdf_fixture_invalid");
        }

        return bytes;
    }
}
