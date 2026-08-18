using System.Net;
using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Core.Versioning;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.Service;

public sealed record ProductComponentVersions(string AgentIdentity, string AppIdentity);

public sealed record ServiceHostOptions(byte[] TokenHash, string DatabasePath, string SpoolPath)
{
    public int RetentionHours { get; init; } = 24;

    public string? SigningUserSid { get; init; }

    public ISpoolAclPolicy? SpoolAclPolicy { get; init; }

    public ServiceSettingsSummary? ManagementSettings { get; init; }

    public required string ProductVersionIdentity { get; init; }
}

internal sealed record ServiceRuntimeSettings(
    ServiceConfiguration Configuration,
    byte[] TokenHash,
    bool Console,
    bool AllowHttpLoopback);

public sealed class SigningRuntimeHostedService : BackgroundService
{
    private static readonly EventId RuntimeFailureEvent = new(2001, "SigningRuntimeFailed");
    private static readonly EventId RuntimeJoinFailureEvent = new(2002, "SigningRuntimeJoinFailed");
    private readonly IAgentPipeRuntime _pipe;
    private readonly IJobDispatcherRuntime _dispatcher;
    private readonly IAgentStartupPreparationRuntime? _startupPreparation;
    private readonly ILogger<SigningRuntimeHostedService> _logger;

    public SigningRuntimeHostedService(
        IAgentPipeRuntime pipe,
        IJobDispatcherRuntime dispatcher,
        ILocalJobRequestHandler? localJobs = null,
        IAgentStartupPreparationRuntime? startupPreparation = null,
        ILogger<SigningRuntimeHostedService>? logger = null)
    {
        _pipe = pipe ?? throw new ArgumentNullException(nameof(pipe));
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _startupPreparation = startupPreparation;
        _logger = logger ?? NullLogger<SigningRuntimeHostedService>.Instance;
        if (pipe is AgentPipeServer server && localJobs is not null)
        {
            server.ConfigureLocalJobs(localJobs);
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var runtimeCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var pipeTask = _pipe.RunAsync(runtimeCancellation.Token);
        var dispatcherTask = _dispatcher.RunAsync(runtimeCancellation.Token);
        var startupTask = _startupPreparation?.RunAsync(runtimeCancellation.Token);
        var runtimeTasks = startupTask is null
            ? new[] { pipeTask, dispatcherTask }
            : new[] { pipeTask, dispatcherTask, startupTask };
        var completed = await Task.WhenAny(runtimeTasks).ConfigureAwait(false);
        Exception? failure = null;
        try
        {
            await completed.ConfigureAwait(false);
            if (!stoppingToken.IsCancellationRequested)
            {
                failure = new InvalidOperationException("signing_runtime_stopped");
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception error)
        {
            failure = error;
        }

        runtimeCancellation.Cancel();
        try
        {
            await Task.WhenAll(runtimeTasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (runtimeCancellation.IsCancellationRequested)
        {
        }
        catch (Exception error) when (failure is not null)
        {
            if (!ReferenceEquals(error, failure))
            {
                ServiceHost.TryLogError(
                    _logger,
                    RuntimeJoinFailureEvent,
                    "signing_runtime_join_failed",
                    "runtime_join",
                    error);
            }
        }
        catch (Exception error)
        {
            failure = error;
        }

        if (failure is not null)
        {
            ServiceHost.TryLogError(
                _logger,
                RuntimeFailureEvent,
                "signing_runtime_failed",
                "runtime_execute",
                failure);
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }
}

public sealed class AdminControlHostedService(IAdminControlRuntime runtime) : BackgroundService
{
    private readonly IAdminControlRuntime _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        _runtime.RunAsync(stoppingToken);
}

public static class ServiceHost
{
    internal static string FormatDiagnostic(Exception error, string stage, string stableCode)
    {
        ArgumentNullException.ThrowIfNull(error);
        var diagnostic = new System.Text.StringBuilder()
            .AppendLine("service_diagnostic_begin")
            .Append("stable_code=").AppendLine(stableCode)
            .Append("stage=").AppendLine(stage)
            .AppendLine("exception_begin");
        var depth = 0;
        for (var current = error; current is not null; current = current.InnerException, depth++)
        {
            if (depth > 0)
            {
                diagnostic.AppendLine("inner_exception");
            }

            diagnostic
                .Append("exception_depth=").AppendLine(depth.ToString(CultureInfo.InvariantCulture))
                .Append("exception_type=").AppendLine(current.GetType().FullName)
                .Append("message=").AppendLine(current.Message)
                .Append("hresult=0x").AppendLine(((uint)current.HResult).ToString("X8", CultureInfo.InvariantCulture))
                .Append("win32_error=").AppendLine(
                    current is Win32Exception native
                        ? native.NativeErrorCode.ToString(CultureInfo.InvariantCulture)
                        : string.Empty)
                .AppendLine("stack_begin")
                .AppendLine(current.StackTrace ?? string.Empty)
                .AppendLine("stack_end");
        }

        return SecretRedactor.Redact(diagnostic.AppendLine("exception_end").Append("service_diagnostic_end").ToString());
    }

    internal static void TryLogError(
        ILogger logger,
        EventId eventId,
        string stableCode,
        string stage,
        Exception error)
    {
        try
        {
            logger.LogError(
                eventId,
                "Failure. Code: {Code}{NewLine}{Diagnostic}",
                stableCode,
                Environment.NewLine,
                FormatDiagnostic(error, stage, stableCode));
        }
        catch (Exception)
        {
        }
    }

    public static void Configure(WebApplicationBuilder builder, ServiceHostOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.TokenHash.Length != SHA256.HashSizeInBytes)
        {
            throw new ArgumentException("Bearer token hash must be a SHA-256 value.", nameof(options));
        }

        if (options.RetentionHours is < 0 or > 168)
        {
            throw new ArgumentOutOfRangeException(nameof(options));
        }

        ConfigureSafeLogging(builder.Logging);

        builder.Services
            .AddAuthentication(BearerTokenAuthenticationHandler.SchemeName)
            .AddScheme<BearerTokenAuthenticationOptions, BearerTokenAuthenticationHandler>(
                BearerTokenAuthenticationHandler.SchemeName,
                configured => configured.TokenHash = options.TokenHash.ToArray());
        builder.Services.AddAuthorization();
        builder.Services.TryAddSingleton<IUploadedContentValidator, UploadedContentValidator>();
        builder.Services.AddSingleton<IJobStore>(_ => new SqliteJobStore(options.DatabasePath));
        builder.Services.TryAddSingleton<IJobCompletionNotifier, JobCompletionNotifier>();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton(new JobRetentionPolicy(options.RetentionHours));
        if (options.SigningUserSid is null)
        {
            builder.Services.AddSingleton<ISpoolStore>(_ => new SpoolStore(options.SpoolPath));
            AddCleanup(builder);
            builder.Services.TryAddSingleton<IJobDispatcher, NullJobDispatcher>();
            builder.Services.TryAddSingleton<IAgentHealthStatusSource, DisconnectedAgentHealthStatusSource>();
            return;
        }

        if (!CanonicalWindowsSid.IsValid(options.SigningUserSid))
        {
            throw new ArgumentException("Signing user SID is invalid.", nameof(options));
        }

        if (options.SpoolAclPolicy is null)
        {
            throw new InvalidOperationException("signing_security_policy_required");
        }

        builder.Services.AddSingleton<ISpoolStore>(_ => new SpoolStore(options.SpoolPath, options.SpoolAclPolicy));
        AddCleanup(builder);

        builder.Services.AddSingleton(services => new ServiceManagementSnapshotProvider(
            services.GetRequiredService<IJobStore>(),
            services.GetRequiredService<TimeProvider>(),
            options.ManagementSettings));
        builder.Services.AddSingleton<IServiceManagementSnapshotProvider>(services =>
            services.GetRequiredService<ServiceManagementSnapshotProvider>());
        builder.Services.AddSingleton(services => new AgentPipeServer(
            options.SigningUserSid,
            options.ProductVersionIdentity,
            managementProvider: services.GetRequiredService<IServiceManagementSnapshotProvider>()));
        builder.Services.AddSingleton<IAgentPipeRuntime>(services => services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<IAgentPipeTransport>(services => services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<IAgentControlTransport>(services =>
            services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<IAgentStartupPreparationTransport>(services =>
            services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<AgentStartupPreparationCoordinator>();
        builder.Services.AddSingleton<IAgentStartupPreparationRuntime>(services =>
            services.GetRequiredService<AgentStartupPreparationCoordinator>());
        builder.Services.AddSingleton<IAgentHealthStatusSource>(services => services.GetRequiredService<AgentPipeServer>());
        builder.Services.AddSingleton<JobDispatcher>();
        builder.Services.AddSingleton<IJobDispatcherRuntime>(services => services.GetRequiredService<JobDispatcher>());
        builder.Services.AddSingleton<IJobDispatcher>(services => services.GetRequiredService<JobDispatcher>());
        builder.Services.AddSingleton(services => new LocalJobUploadCoordinator(
            services.GetRequiredService<IJobStore>(),
            services.GetRequiredService<ISpoolStore>(),
            services.GetRequiredService<IJobDispatcher>(),
            services.GetRequiredService<TimeProvider>(),
            options.SigningUserSid,
            retentionHours: options.RetentionHours));
        builder.Services.AddSingleton<ILocalJobRequestHandler>(services =>
            services.GetRequiredService<LocalJobUploadCoordinator>());
        builder.Services.AddSingleton<IAdministratorLocalJobRequestHandler>(services =>
            services.GetRequiredService<LocalJobUploadCoordinator>());
        builder.Services.AddSingleton<ILocalUploadCleanup>(services =>
            services.GetRequiredService<LocalJobUploadCoordinator>());
        builder.Services.AddHostedService<SigningRuntimeHostedService>();
        builder.Services.AddSingleton<AdminControlPipeServer>();
        builder.Services.AddSingleton<IAdminControlRuntime>(services =>
            services.GetRequiredService<AdminControlPipeServer>());
        builder.Services.AddHostedService<AdminControlHostedService>();
    }

    internal static void ConfigureSafeLogging(ILoggingBuilder logging)
    {
        ArgumentNullException.ThrowIfNull(logging);
        logging.SetMinimumLevel(LogLevel.Information);
        logging.AddFilter(static (category, level) =>
            level >= LogLevel.Information &&
            !string.Equals(category, "Microsoft.Hosting.Lifetime", StringComparison.Ordinal) &&
            !string.Equals(category, "Microsoft.Extensions.Hosting.Internal.Host", StringComparison.Ordinal) &&
            !(category?.StartsWith("Microsoft.AspNetCore.DataProtection.", StringComparison.Ordinal) ?? false));
    }

    private static void AddCleanup(WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<JobCleanupService>();
        builder.Services.AddHostedService(services => services.GetRequiredService<JobCleanupService>());
    }

    public static void MapPipeline(WebApplication application)
    {
        application.Use(async (context, next) =>
        {
            try
            {
                await next(context);
            }
            catch (Exception error) when (!context.RequestAborted.IsCancellationRequested)
            {
                try
                {
                    var logger = context.RequestServices
                        .GetService<ILoggerFactory>()?
                        .CreateLogger("SimplySignAuto.Service.Api");
                    if (logger is not null)
                    {
                        TryLogError(
                            logger,
                            new EventId(2003, "ApiRequestFailed"),
                            "internal_error",
                            "api_request",
                            error);
                    }
                }
                catch (Exception)
                {
                }
                if (context.Response.HasStarted)
                {
                    throw;
                }

                context.Response.Clear();
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                context.Response.ContentType = "application/problem+json";
                await JsonSerializer.SerializeAsync(
                    context.Response.Body,
                    ApiProblem.Create(
                        "internal_error",
                        context.TraceIdentifier,
                        "The request could not be completed.",
                        StatusCodes.Status500InternalServerError),
                    JsonSerializerOptions.Web,
                    cancellationToken: context.RequestAborted);
            }
        });
        application.UseAuthentication();
        application.UseAuthorization();
        application.MapHealthEndpoints();
        var v1 = application.MapGroup("/v1").RequireAuthorization();
        v1.MapJobEndpoints();
        v1.MapReadinessEndpoint();
    }

    public static async Task RunAsync(
        string[] args,
        ProductComponentVersions componentVersions)
    {
        await RunAsync(
            args,
            componentVersions,
            new ServiceConfigurationLoader(),
            CancellationToken.None).ConfigureAwait(false);
    }

    internal static async Task RunAsync(
        string[] args,
        ProductComponentVersions componentVersions,
        IServiceConfigurationLoader configurationLoader,
        CancellationToken cancellationToken)
    {
        var runtime = await PrepareRuntimeAsync(
            args,
            configurationLoader,
            cancellationToken).ConfigureAwait(false);

        var builder = WebApplication.CreateBuilder();
        if (!runtime.Console)
        {
            builder.Host.UseWindowsService();
        }

        builder.WebHost.ConfigureKestrel(server => ConfigureListeners(server, runtime));
        Configure(builder, CreateOptions(runtime, componentVersions));
        var application = builder.Build();
        MapPipeline(application);
        await application.RunAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static ServiceHostOptions CreateOptions(
        ServiceRuntimeSettings runtime,
        ProductComponentVersions componentVersions,
        Func<string, ISpoolAclPolicy>? spoolAclPolicyFactory = null)
    {
        ArgumentNullException.ThrowIfNull(runtime);
        ArgumentNullException.ThrowIfNull(componentVersions);
        spoolAclPolicyFactory ??= static signingUserSid => new WindowsSpoolAclPolicy(signingUserSid);
        var productVersion = ComposeProductVersion(
            ReadInformationalIdentity(typeof(ServiceHost).Assembly),
            componentVersions);
        return new ServiceHostOptions(
            runtime.TokenHash,
            Path.Combine(runtime.Configuration.DataRoot, "jobs.db"),
            runtime.Configuration.SpoolRoot)
        {
            RetentionHours = runtime.Configuration.RetentionHours,
            SigningUserSid = runtime.Configuration.SigningUserSid,
            SpoolAclPolicy = spoolAclPolicyFactory(runtime.Configuration.SigningUserSid),
            ManagementSettings = CreateSettingsSummary(runtime, productVersion),
            ProductVersionIdentity = productVersion.Identity,
        };
    }

    internal static ProductVersion ComposeProductVersion(
        string? serviceIdentity,
        ProductComponentVersions componentVersions)
    {
        ArgumentNullException.ThrowIfNull(componentVersions);
        if (!ProductVersion.TryParse(serviceIdentity, out var serviceVersion) ||
            !ProductVersion.TryParse(componentVersions.AgentIdentity, out var agentVersion) ||
            !ProductVersion.TryParse(componentVersions.AppIdentity, out var appVersion) ||
            !string.Equals(serviceVersion!.Identity, agentVersion!.Identity, StringComparison.Ordinal) ||
            !string.Equals(serviceVersion.Identity, appVersion!.Identity, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("product_version_mismatch");
        }

        return serviceVersion!;
    }

    private static ServiceSettingsSummary CreateSettingsSummary(
        ServiceRuntimeSettings runtime,
        ProductVersion productVersion)
    {
        return new ServiceSettingsSummary(
            runtime.Configuration.ListenPort,
            ServiceSettingsSummary.FixedMaximumUploadBytes,
            runtime.Configuration.RetentionHours,
            productVersion.Identity);
    }

    private static string? ReadInformationalIdentity(Assembly assembly) =>
        assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

    internal static async Task<ServiceRuntimeSettings> PrepareRuntimeAsync(
        string[] args,
        IServiceConfigurationLoader configurationLoader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(configurationLoader);
        var console = args is ["--console"] or ["--console", "--allow-http-loopback"];
        var allowHttpLoopback = args is ["--console", "--allow-http-loopback"];
        if (args.Length != 0 && !console)
        {
            throw new ArgumentException("service_arguments_invalid", nameof(args));
        }

        var configuration = ServiceConfigurationLoader.Validate(
            await configurationLoader.LoadAsync(cancellationToken).ConfigureAwait(false));
        var tokenHash = Convert.FromHexString(configuration.TokenHash);
        return new ServiceRuntimeSettings(
            configuration,
            tokenHash,
            console,
            allowHttpLoopback);
    }

    private static void ConfigureListeners(KestrelServerOptions server, ServiceRuntimeSettings runtime)
    {
        server.Limits.MaxRequestBodySize = JobEndpoints.MaxRequestBodyBytes;
        if (runtime.AllowHttpLoopback)
        {
            server.Listen(IPAddress.Loopback, 5080);
            return;
        }

        server.ListenAnyIP(runtime.Configuration.ListenPort);
    }

}
