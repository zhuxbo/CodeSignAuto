using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SimplySignAuto.Setup;

internal sealed class SetupBootstrapperException : Exception
{
    public SetupBootstrapperException(string code)
        : base(Describe(code)) => Code = ReadPrimaryCode(code);

    public string Code { get; }

    private static string Describe(string code)
    {
        var description = ReadPrimaryCode(code) switch
        {
            "required_runtime_missing" =>
                "缺少 SimplySignAuto 所需的 .NET 10 Windows x64 运行环境。请安装 " +
                "ASP.NET Core Runtime 和 .NET Desktop Runtime 后重新运行安装程序。\n" +
                "ASP.NET Core Runtime：https://dotnet.microsoft.com/en-us/download/dotnet/10.0\n" +
                ".NET Desktop Runtime：https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime",
            "simplysign_desktop_missing" =>
                "Certum SimplySign Desktop（Windows 64 位）未安装。请安装后重新运行安装程序。\n" +
                "下载：https://support.certum.eu/en/software/procertum-smartsign/",
            "simplysign_pkcs11_missing" =>
                "未找到 C:\\Windows\\System32\\SimplySignPKCS.dll。请修复或重新安装 " +
                "Certum SimplySign Desktop（Windows 64 位）。\n" +
                "下载：https://support.certum.eu/en/software/procertum-smartsign/",
            "os_unsupported" =>
                "不支持当前 Windows 版本或版本组合。支持 x64 Windows 10 22H2、受支持的 " +
                "Windows 10 LTSC/Windows 11，以及 Windows Server 2019/2022/2025 Desktop Experience。",
            "desktop_experience_required" =>
                "自动签名服务需要 Windows Server Desktop Experience，不支持 Server Core。",
            "architecture_unsupported" =>
                "SimplySignAuto 只支持 x64 Windows。请在 64 位操作系统中运行 64 位安装程序。",
            "elevation_required" or "administrator_required" =>
                "安装需要管理员权限。请右键安装程序并选择“以管理员身份运行”，然后重新运行。",
            "domain_controller_unsupported" =>
                "不支持在域控制器上安装。请改用工作组计算机、域成员客户端或成员服务器。",
            "autologon_conflict" =>
                "检测到已有自动登录配置。自动签名服务需要独占该配置，安装程序不会覆盖现有设置。" +
                "请先安全关闭原自动登录配置，再重新运行安装程序。",
            "autologon_plaintext_password_present" =>
                "检测到注册表中的旧式明文自动登录密码。请使用原配置工具安全移除后再安装；" +
                "安装程序不会读取或覆盖该密码。",
            _ => "安装未完成。请检查系统要求并修正问题后重新运行安装程序。",
        };

        return $"{description}\n\n错误代码：{code}";
    }

    private static string ReadPrimaryCode(string code)
    {
        var separator = code.IndexOf(' ', StringComparison.Ordinal);
        return separator > 0 ? code[..separator] : code;
    }
}

internal enum SetupProductKind
{
    Main,
    PdfExtension,
}

internal sealed record SetupProgress(int Percent, string Message);

internal sealed record SetupPayloadMetadata(
    int SchemaVersion,
    SetupProductKind ProductKind,
    string ProductVersion,
    long PayloadLength,
    string PayloadSha256,
    string PublisherCertificateSha256);

internal static partial class SetupPayloadMetadataCodec
{
    private static readonly HashSet<string> ExpectedProperties =
    [
        "schemaVersion",
        "productKind",
        "productVersion",
        "payloadLength",
        "payloadSha256",
        "publisherCertificateSha256",
    ];

    public static SetupPayloadMetadata Decode(ReadOnlySpan<byte> json)
    {
        try
        {
            using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4,
            });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw Invalid();
            }

            var properties = document.RootElement.EnumerateObject().ToArray();
            if (properties.Length != ExpectedProperties.Count ||
                properties.Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() !=
                ExpectedProperties.Count ||
                properties.Any(property => !ExpectedProperties.Contains(property.Name)))
            {
                throw Invalid();
            }

            var schemaVersion = ReadInt32(document.RootElement, "schemaVersion");
            var productKind = ReadProductKind(document.RootElement);
            var productVersion = ReadString(document.RootElement, "productVersion");
            var payloadLength = ReadInt64(document.RootElement, "payloadLength");
            var payloadSha256 = ReadString(document.RootElement, "payloadSha256");
            var publisher = ReadString(document.RootElement, "publisherCertificateSha256");
            if (schemaVersion != 1 ||
                payloadLength <= 0 ||
                payloadLength > 512L * 1024 * 1024 ||
                !SemVerPattern().IsMatch(productVersion) ||
                !IsLowerHex64(payloadSha256) ||
                !IsLowerHex64(publisher))
            {
                throw Invalid();
            }

            return new SetupPayloadMetadata(
                schemaVersion,
                productKind,
                productVersion,
                payloadLength,
                payloadSha256,
                publisher);
        }
        catch (SetupBootstrapperException)
        {
            throw;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or OverflowException)
        {
            throw Invalid();
        }
    }

    private static int ReadInt32(JsonElement root, string name)
    {
        var value = root.GetProperty(name);
        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var result)
            ? result
            : throw Invalid();
    }

    private static long ReadInt64(JsonElement root, string name)
    {
        var value = root.GetProperty(name);
        return value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var result)
            ? result
            : throw Invalid();
    }

    private static string ReadString(JsonElement root, string name)
    {
        var value = root.GetProperty(name);
        return value.ValueKind == JsonValueKind.String && value.GetString() is { } result
            ? result
            : throw Invalid();
    }

    private static SetupProductKind ReadProductKind(JsonElement root) =>
        ReadString(root, "productKind") switch
        {
            "main" => SetupProductKind.Main,
            "pdf-extension" => SetupProductKind.PdfExtension,
            _ => throw Invalid(),
        };

    private static bool IsLowerHex64(string value) =>
        value.Length == 64 && value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static SetupBootstrapperException Invalid() => new("setup_payload_invalid");

    [GeneratedRegex(
        "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex SemVerPattern();
}

internal static class SetupPayloadArchive
{
    private const long MaximumExpandedBytes = 512L * 1024 * 1024;

    public static async Task ExtractAsync(
        Stream payload,
        string destination,
        CancellationToken cancellationToken) => await ExtractCoreAsync(
        payload,
        destination,
        destinationMustExist: false,
        cleanupDestinationOnFailure: true,
        cancellationToken).ConfigureAwait(false);

    public static async Task ExtractIntoExistingAsync(
        Stream payload,
        string destination,
        CancellationToken cancellationToken) => await ExtractCoreAsync(
        payload,
        destination,
        destinationMustExist: true,
        cleanupDestinationOnFailure: false,
        cancellationToken).ConfigureAwait(false);

    private static async Task ExtractCoreAsync(
        Stream payload,
        string destination,
        bool destinationMustExist,
        bool cleanupDestinationOnFailure,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);
        if (string.IsNullOrWhiteSpace(destination) || File.Exists(destination))
        {
            throw new SetupBootstrapperException("setup_payload_invalid");
        }

        var canonicalDestination = Path.GetFullPath(destination);
        if (destinationMustExist)
        {
            if (!Directory.Exists(canonicalDestination) ||
                (File.GetAttributes(canonicalDestination) & FileAttributes.ReparsePoint) != 0 ||
                Directory.EnumerateFileSystemEntries(canonicalDestination).Any())
            {
                throw new SetupBootstrapperException("setup_payload_invalid");
            }
        }
        else if (Directory.Exists(canonicalDestination))
        {
            throw new SetupBootstrapperException("setup_payload_invalid");
        }

        try
        {
            using var archive = new ZipArchive(payload, ZipArchiveMode.Read, leaveOpen: true);
            var entries = archive.Entries.Where(entry => !string.IsNullOrEmpty(entry.Name)).ToArray();
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            long expandedBytes = 0;
            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relative = ValidateEntryName(entry.FullName);
                if (!names.Add(relative) || entry.Length < 0)
                {
                    throw new SetupBootstrapperException("setup_payload_invalid");
                }

                expandedBytes = checked(expandedBytes + entry.Length);
                if (expandedBytes > MaximumExpandedBytes)
                {
                    throw new SetupBootstrapperException("setup_payload_invalid");
                }
            }

            if (!destinationMustExist)
            {
                Directory.CreateDirectory(canonicalDestination);
            }

            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var relative = ValidateEntryName(entry.FullName);
                var target = Path.GetFullPath(Path.Combine(
                    canonicalDestination,
                    relative.Replace('/', Path.DirectorySeparatorChar)));
                if (!target.StartsWith(canonicalDestination + Path.DirectorySeparatorChar, PathComparison()))
                {
                    throw new SetupBootstrapperException("setup_payload_invalid");
                }

                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                await using var output = new FileStream(
                    target,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    64 * 1024,
                    FileOptions.Asynchronous | FileOptions.WriteThrough);
                await using var input = entry.Open();
                await input.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
            }
        }
        catch
        {
            if (cleanupDestinationOnFailure && Directory.Exists(canonicalDestination))
            {
                Directory.Delete(canonicalDestination, recursive: true);
            }

            throw;
        }
    }

    private static string ValidateEntryName(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Contains('\\', StringComparison.Ordinal) ||
            value.StartsWith("/", StringComparison.Ordinal) ||
            value.Contains(':', StringComparison.Ordinal))
        {
            throw new SetupBootstrapperException("setup_payload_invalid");
        }

        var segments = value.Split('/');
        if (segments.Any(segment =>
                string.IsNullOrEmpty(segment) || segment is "." or ".." ||
                segment.EndsWith(' ') || segment.EndsWith('.')))
        {
            throw new SetupBootstrapperException("setup_payload_invalid");
        }

        return string.Join('/', segments);
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
}

internal interface ISetupPayloadSource
{
    string ExecutablePath { get; }

    byte[] ReadMetadata();

    Stream OpenPayload();
}

internal interface ISetupPublisherVerifier
{
    Task VerifyAsync(
        string executablePath,
        string expectedPublisherCertificateSha256,
        CancellationToken cancellationToken);
}

internal interface ISetupWorkspace
{
    string Create();

    Task CleanupAsync(string mediaRoot);
}

internal interface ISetupProcessRunner
{
    Task<int> RunAsync(
        SetupProductKind productKind,
        string mediaRoot,
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken);
}

internal interface ISetupProcessInvoker
{
    Task<int> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        IProgress<string>? progress,
        CancellationToken cancellationToken);
}

internal sealed record StagedSetupPayload(
    string MediaRoot,
    SetupPayloadMetadata Metadata);

internal sealed class SetupBootstrapperOperations(
    ISetupPayloadSource payloadSource,
    ISetupPublisherVerifier publisherVerifier,
    ISetupWorkspace workspace,
    ISetupProcessRunner processRunner) : ISetupBootstrapperOperations
{
    public async Task<StagedSetupPayload> StageAsync(CancellationToken cancellationToken)
    {
        var metadata = SetupPayloadMetadataCodec.Decode(payloadSource.ReadMetadata());
        await publisherVerifier.VerifyAsync(
                payloadSource.ExecutablePath,
                metadata.PublisherCertificateSha256,
                cancellationToken)
            .ConfigureAwait(false);

        await using var payload = payloadSource.OpenPayload();
        if (!payload.CanSeek || payload.Length != metadata.PayloadLength)
        {
            throw new SetupBootstrapperException("setup_payload_invalid");
        }

        var digest = await SHA256.HashDataAsync(payload, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(
                Convert.ToHexString(digest).ToLowerInvariant(),
                metadata.PayloadSha256,
                StringComparison.Ordinal))
        {
            throw new SetupBootstrapperException("setup_payload_invalid");
        }

        payload.Position = 0;
        var mediaRoot = workspace.Create();
        try
        {
            await SetupPayloadArchive.ExtractIntoExistingAsync(payload, mediaRoot, cancellationToken)
                .ConfigureAwait(false);
            return new StagedSetupPayload(mediaRoot, metadata);
        }
        catch
        {
            await workspace.CleanupAsync(mediaRoot).ConfigureAwait(false);
            throw;
        }
    }

    public Task<int> InstallAsync(
        StagedSetupPayload staged,
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken) =>
        processRunner.RunAsync(
            staged.Metadata.ProductKind,
            staged.MediaRoot,
            progress,
            cancellationToken);

    public Task CleanupAsync(string mediaRoot) => workspace.CleanupAsync(mediaRoot);
}

internal interface ISetupBootstrapperOperations
{
    Task<StagedSetupPayload> StageAsync(CancellationToken cancellationToken);

    Task<int> InstallAsync(
        StagedSetupPayload staged,
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken);

    Task CleanupAsync(string mediaRoot);
}

internal sealed class SetupBootstrapper(ISetupBootstrapperOperations operations)
{
    public async Task<int> RunAsync(
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operations);
        StagedSetupPayload? staged = null;
        var tracker = new MonotonicSetupProgress(progress);
        var installSucceeded = false;
        try
        {
            staged = await operations.StageAsync(cancellationToken).ConfigureAwait(false);
            tracker.Report(new SetupProgress(25, "安装介质已验证"));
            var exitCode = await operations.InstallAsync(staged, tracker, cancellationToken)
                .ConfigureAwait(false);
            installSucceeded = exitCode == 0;
            if (installSucceeded)
            {
                tracker.Report(new SetupProgress(95, "产品安装完成"));
            }

            return exitCode;
        }
        finally
        {
            if (staged is not null)
            {
                await operations.CleanupAsync(staged.MediaRoot).ConfigureAwait(false);
                if (installSucceeded)
                {
                    tracker.Report(new SetupProgress(100, "安装完成"));
                }
            }
        }
    }

    private sealed class MonotonicSetupProgress(IProgress<SetupProgress>? inner)
        : IProgress<SetupProgress>
    {
        private int _lastPercent;

        public void Report(SetupProgress value)
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Percent is < 0 or > 100 || string.IsNullOrWhiteSpace(value.Message))
            {
                throw new SetupBootstrapperException("setup_progress_invalid");
            }

            if (value.Percent <= _lastPercent)
            {
                return;
            }

            _lastPercent = value.Percent;
            inner?.Report(value);
        }
    }
}
