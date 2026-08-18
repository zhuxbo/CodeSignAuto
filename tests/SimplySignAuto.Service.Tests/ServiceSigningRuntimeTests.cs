using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SimplySignAuto.Protocol;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Ipc;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class ServiceSigningRuntimeTests
{
    private const string SigningUserSid = "S-1-5-21-1000-2000-3000-4000";

    [Fact]
    public void Signing_sid_composes_one_real_pipe_dispatcher_and_hosted_runtime()
    {
        using var fixture = new Fixture();
        var builder = WebApplication.CreateBuilder();

        ServiceHost.Configure(builder, new ServiceHostOptions(
            SHA256.HashData("token"u8),
            fixture.DatabasePath,
            fixture.SpoolPath)
        {
            ProductVersionIdentity = "1.0.0",
            SigningUserSid = SigningUserSid,
            SpoolAclPolicy = UnrestrictedSpoolAclPolicy.Instance,
        });

        using var provider = builder.Services.BuildServiceProvider();
        var pipe = Assert.IsType<AgentPipeServer>(provider.GetRequiredService<IAgentPipeTransport>());
        var dispatcher = Assert.IsType<JobDispatcher>(provider.GetRequiredService<IJobDispatcher>());
        var localJobs = Assert.IsType<LocalJobUploadCoordinator>(provider.GetRequiredService<ILocalJobRequestHandler>());
        Assert.Same(pipe, provider.GetRequiredService<IAgentPipeRuntime>());
        Assert.Same(pipe, provider.GetRequiredService<IAgentStartupPreparationTransport>());
        Assert.IsType<AgentStartupPreparationCoordinator>(
            provider.GetRequiredService<IAgentStartupPreparationRuntime>());
        Assert.Same(dispatcher, provider.GetRequiredService<IJobDispatcherRuntime>());
        Assert.Same(localJobs, provider.GetRequiredService<LocalJobUploadCoordinator>());
        Assert.Same(localJobs, provider.GetRequiredService<ILocalUploadCleanup>());
        Assert.Same(pipe, provider.GetRequiredService<IAgentHealthStatusSource>());
        Assert.Collection(
            provider.GetServices<IHostedService>().Where(service => service is JobCleanupService or SigningRuntimeHostedService),
            service => Assert.IsType<JobCleanupService>(service),
            service => Assert.IsType<SigningRuntimeHostedService>(service));
        Assert.Same(localJobs, pipe.LocalJobHandler);
    }

    [Fact]
    public void Signing_runtime_rejects_missing_security_policies_instead_of_falling_back()
    {
        using var fixture = new Fixture();
        var builder = WebApplication.CreateBuilder();

        var failure = Assert.Throws<InvalidOperationException>(() => ServiceHost.Configure(
            builder,
            new ServiceHostOptions(
                SHA256.HashData("token"u8),
                fixture.DatabasePath,
                fixture.SpoolPath)
            {
                ProductVersionIdentity = "1.0.0",
                SigningUserSid = SigningUserSid,
            }));

        Assert.Equal("signing_security_policy_required", failure.Message);
    }

    [Fact]
    public void Missing_signing_sid_still_composes_cleanup_and_disconnected_health_without_windows_pipe()
    {
        using var fixture = new Fixture();
        var builder = WebApplication.CreateBuilder();

        ServiceHost.Configure(builder, new ServiceHostOptions(
            SHA256.HashData("token"u8),
            fixture.DatabasePath,
            fixture.SpoolPath)
        {
            ProductVersionIdentity = "1.0.0",
        });

        using var provider = builder.Services.BuildServiceProvider();
        Assert.IsType<DisconnectedAgentHealthStatusSource>(provider.GetRequiredService<IAgentHealthStatusSource>());
        Assert.IsType<NullJobDispatcher>(provider.GetRequiredService<IJobDispatcher>());
        Assert.IsType<JobCleanupService>(Assert.Single(provider.GetServices<IHostedService>(), service => service is JobCleanupService));
        Assert.Null(provider.GetService<AgentPipeServer>());
    }

    [Fact]
    public void Signing_sid_must_be_strictly_normalized()
    {
        string[] invalidSids =
        [
            "S-1-5-21-+1",
            "S-1-5-21- 1",
            "S-2-5-21-1",
            "S-1-05-21-1",
            "S-1-5-021-1",
            "S-1-5-21-01",
        ];
        foreach (var signingUserSid in invalidSids)
        {
            using var fixture = new Fixture();
            var builder = WebApplication.CreateBuilder();

            Assert.Throws<ArgumentException>(() => ServiceHost.Configure(builder, new ServiceHostOptions(
                SHA256.HashData("token"u8),
                fixture.DatabasePath,
                fixture.SpoolPath)
            {
                ProductVersionIdentity = "1.0.0",
                SigningUserSid = signingUserSid,
            }));
        }
    }

    [Fact]
    public async Task Hosted_runtime_cancels_and_awaits_all_loops_on_stop()
    {
        var pipe = new RecordingPipeRuntime();
        var dispatcher = new RecordingDispatcherRuntime();
        var startup = new RecordingStartupRuntime();
        using var runtime = new SigningRuntimeHostedService(
            pipe,
            dispatcher,
            startupPreparation: startup);

        await runtime.StartAsync(CancellationToken.None);
        await Task.WhenAll(pipe.Started.Task, dispatcher.Started.Task, startup.Started.Task)
            .WaitAsync(TimeSpan.FromSeconds(2));
        await runtime.StopAsync(CancellationToken.None);

        Assert.True(pipe.Stopped.Task.IsCompletedSuccessfully);
        Assert.True(dispatcher.Stopped.Task.IsCompletedSuccessfully);
        Assert.True(startup.Stopped.Task.IsCompletedSuccessfully);
        Assert.True(runtime.ExecuteTask?.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task Hosted_runtime_propagates_loop_failure_after_joining_the_other_loop()
    {
        var native = new System.ComponentModel.Win32Exception(5, "access denied path=C:\\pipe");
        var expected = new InvalidOperationException("pipe_loop_failed", native);
        var pipe = new RecordingPipeRuntime(expected);
        var dispatcher = new RecordingDispatcherRuntime();
        var logger = new CapturingLogger<SigningRuntimeHostedService>();
        using var runtime = new SigningRuntimeHostedService(pipe, dispatcher, logger: logger);

        await runtime.StartAsync(CancellationToken.None);
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await runtime.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(2)));

        Assert.Same(expected, failure);
        Assert.True(dispatcher.Stopped.Task.IsCompletedSuccessfully);
        var message = Assert.Single(logger.Messages);
        Assert.Contains("signing_runtime_failed", message, StringComparison.Ordinal);
        Assert.Contains("pipe_loop_failed", message, StringComparison.Ordinal);
        Assert.Contains("InvalidOperationException", message, StringComparison.Ordinal);
        Assert.Contains("stage=runtime_execute", message, StringComparison.Ordinal);
        Assert.Contains("exception_depth=1", message, StringComparison.Ordinal);
        Assert.Contains("Win32Exception", message, StringComparison.Ordinal);
        Assert.Contains("win32_error=5", message, StringComparison.Ordinal);
        Assert.Contains("hresult=0x", message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Throwing_logger_does_not_replace_the_runtime_failure()
    {
        var expected = new InvalidOperationException("pipe_loop_failed");
        var pipe = new RecordingPipeRuntime(expected);
        var dispatcher = new RecordingDispatcherRuntime();
        using var runtime = new SigningRuntimeHostedService(
            pipe,
            dispatcher,
            logger: new ThrowingLogger<SigningRuntimeHostedService>());

        await runtime.StartAsync(CancellationToken.None);
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await runtime.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(2)));

        Assert.Same(expected, failure);
        Assert.True(dispatcher.Stopped.Task.IsCompletedSuccessfully);
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Messages.Add(formatter(state, exception) + (exception is null ? string.Empty : "\n" + exception));
    }

    private sealed class ThrowingLogger<T> : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            throw new InvalidOperationException("logger_failed");
    }

    private sealed class RecordingPipeRuntime(Exception? failure = null) : IAgentPipeRuntime
    {
        public event EventHandler<AgentConnectionStateChangedEventArgs>? ConnectionStateChanged
        {
            add { }
            remove { }
        }

        public event EventHandler<AgentMessageReceivedEventArgs>? MessageReceived
        {
            add { }
            remove { }
        }
        public AgentConnectionSnapshot? CurrentConnection => null;
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Stopped { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            if (failure is not null)
            {
                throw failure;
            }

            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            finally
            {
                Stopped.TrySetResult();
            }
        }

        public Task SendAsync(Guid connectionId, SignJobCommand command, CancellationToken cancellationToken) =>
            Task.FromException(new NotSupportedException());
    }

    private sealed class RecordingDispatcherRuntime : IJobDispatcherRuntime
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Stopped { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Enqueue(Guid jobId)
        {
        }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            finally
            {
                Stopped.TrySetResult();
            }
        }
    }

    private sealed class RecordingStartupRuntime : IAgentStartupPreparationRuntime
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Stopped { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public AgentStartupPreparationSnapshot Current { get; } = new(
            AgentStartupPreparationStatus.Pending,
            null,
            null);

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            finally
            {
                Stopped.TrySetResult();
            }
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string _root = Path.Combine(
            Path.GetTempPath(),
            "SimplySignAuto.Tests",
            Guid.NewGuid().ToString("N"));

        public string DatabasePath => Path.Combine(_root, "jobs.db");

        public string SpoolPath => Path.Combine(_root, "spool");

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }
}
