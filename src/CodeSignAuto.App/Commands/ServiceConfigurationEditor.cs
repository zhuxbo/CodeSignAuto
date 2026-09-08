using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CodeSignAuto.Protocol;
using CodeSignAuto.Service;

namespace CodeSignAuto.App.Commands;

internal sealed record ServiceConfigurationEditRequest(
    int ListenPort,
    int RetentionHours,
    bool RotateToken);

internal sealed record ServiceConfigurationEditResult(
    ServiceSettingsSummary Summary,
    string? OneTimeApiToken)
{
    public override string ToString() =>
        $"ServiceConfigurationEditResult {{ Summary = {Summary}, " +
        $"OneTimeApiToken = {(OneTimeApiToken is null ? "[ABSENT]" : "[PRESENT]")} }}";
}

internal sealed class SensitiveOneTimeApiToken : IDisposable
{
    private const int TokenCharacters = 43;
    private char[]? _value;
    private int _materializationCount;

    internal SensitiveOneTimeApiToken(char[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        _value = value;
        if (value.Length != TokenCharacters ||
            value.Any(static character => character is not (
                >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_')))
        {
            Dispose();
            throw new ConfigureServiceException("configure_service_failed");
        }
    }

    internal bool WasMaterialized => Volatile.Read(ref _materializationCount) != 0;
    internal int MaterializationCount => Volatile.Read(ref _materializationCount);

    internal string ComputeHash()
    {
        var value = AsSpan();
        var utf8 = new byte[Encoding.UTF8.GetByteCount(value)];
        try
        {
            _ = Encoding.UTF8.GetBytes(value, utf8);
            return ConfigureServiceTokenSecret.HashAndZero(utf8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    internal string Materialize()
    {
        if (Interlocked.CompareExchange(ref _materializationCount, 1, 0) != 0)
        {
            throw new InvalidOperationException("one_time_token_already_materialized");
        }

        return new string(AsSpan());
    }

    public void Dispose()
    {
        var value = Interlocked.Exchange(ref _value, null);
        if (value is not null)
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(value.AsSpan()));
        }
    }

    public override string ToString() => string.Empty;

    private ReadOnlySpan<char> AsSpan() =>
        _value ?? throw new ObjectDisposedException(nameof(SensitiveOneTimeApiToken));
}

internal interface IServiceConfigurationTokenFactory
{
    SensitiveOneTimeApiToken Create();
}

internal sealed class RandomServiceConfigurationTokenFactory : IServiceConfigurationTokenFactory
{
    public static RandomServiceConfigurationTokenFactory Instance { get; } = new();

    public SensitiveOneTimeApiToken Create()
    {
        var random = RandomNumberGenerator.GetBytes(32);
        char[]? encoded = null;
        char[]? token = null;
        try
        {
            encoded = new char[44];
            if (!Convert.TryToBase64Chars(random, encoded, out var written) ||
                written != encoded.Length || encoded[^1] != '=')
            {
                throw new ConfigureServiceException("configure_service_failed");
            }

            token = encoded.AsSpan(0, encoded.Length - 1).ToArray();
            for (var index = 0; index < token.Length; index++)
            {
                token[index] = token[index] switch
                {
                    '+' => '-',
                    '/' => '_',
                    var character => character,
                };
            }

            var result = new SensitiveOneTimeApiToken(token);
            token = null;
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(random);
            if (encoded is not null)
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(encoded.AsSpan()));
            }

            if (token is not null)
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(token.AsSpan()));
            }
        }
    }
}

internal interface IServiceConfigurationEditor
{
    Task<ServiceConfigurationEditResult> ApplyAsync(
        ServiceConfigurationEditRequest request,
        CancellationToken cancellationToken);
}

internal sealed class ServiceConfigurationEditor : IServiceConfigurationEditor
{
    private readonly IConfigureServicePlatform _platform;
    private readonly IServiceConfigurationTokenFactory _tokenFactory;
    private ConfigureServiceLoadResult? _preloaded;
    private IDisposable? _preacquiredLease;

    public ServiceConfigurationEditor(IConfigureServicePlatform platform)
        : this(platform, RandomServiceConfigurationTokenFactory.Instance)
    {
    }

    internal ServiceConfigurationEditor(
        IConfigureServicePlatform platform,
        IServiceConfigurationTokenFactory tokenFactory)
    {
        _platform = platform ?? throw new ArgumentNullException(nameof(platform));
        _tokenFactory = tokenFactory ?? throw new ArgumentNullException(nameof(tokenFactory));
    }

    internal ServiceConfigurationEditor(
        IConfigureServicePlatform platform,
        ConfigureServiceLoadResult preloaded,
        IDisposable preacquiredLease)
        : this(platform)
    {
        _preloaded = preloaded ?? throw new ArgumentNullException(nameof(preloaded));
        _preacquiredLease = preacquiredLease ?? throw new ArgumentNullException(nameof(preacquiredLease));
    }

    public async Task<ServiceConfigurationEditResult> ApplyAsync(
        ServiceConfigurationEditRequest request,
        CancellationToken cancellationToken)
    {
        IDisposable? lease = Interlocked.Exchange(ref _preacquiredLease, null);
        SensitiveOneTimeApiToken? oneTimeToken = null;
        try
        {
            ArgumentNullException.ThrowIfNull(request);
            ValidateRequest(request);
            cancellationToken.ThrowIfCancellationRequested();
            if (!_platform.IsAdministratorElevated())
            {
                throw new ConfigureServiceException("administrator_required");
            }

            lease ??= _platform.TryAcquireInstanceLease();
            if (lease is null)
            {
                throw new ConfigureServiceException("configure_service_busy");
            }

            var loaded = Interlocked.Exchange(ref _preloaded, null) ??
                await _platform.LoadProtectedAsync(cancellationToken).ConfigureAwait(false);
            var original = ServiceConfigurationLoader.Validate(loaded.Configuration);
            var validatedLoad = new ConfigureServiceLoadResult(original, loaded.Revision);
            var updated = ServiceConfigurationLoader.Validate(original with
            {
                ListenPort = request.ListenPort,
                RetentionHours = request.RetentionHours,
            });

            var summary = _platform.CreateSettingsSummary(updated);
            if (request.RotateToken)
            {
                oneTimeToken = _tokenFactory.Create();
                updated = ServiceConfigurationLoader.Validate(updated with
                {
                    TokenHash = oneTimeToken.ComputeHash(),
                });
            }

            await _platform.ApplyAndRestartAsync(validatedLoad, updated, cancellationToken)
                .ConfigureAwait(false);
            return new ServiceConfigurationEditResult(summary, oneTimeToken?.Materialize());
        }
        finally
        {
            oneTimeToken?.Dispose();
            lease?.Dispose();
        }
    }

    private static void ValidateRequest(ServiceConfigurationEditRequest request)
    {
        if (request.ListenPort is < 1 or > 65535 ||
            request.RetentionHours is < 0 or > 168)
        {
            throw new ConfigureServiceException("configure_service_input_invalid");
        }
    }

}
