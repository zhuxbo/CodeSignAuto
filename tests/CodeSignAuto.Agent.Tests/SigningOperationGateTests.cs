using CodeSignAuto.Agent.Signing;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class SigningOperationGateTests
{
    [Fact]
    public async Task Codesign_document_and_probe_operations_share_one_process_wide_slot()
    {
        await using var gate = new SigningOperationGate();
        var concurrent = 0;
        var maximum = 0;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var operations = Enumerable.Range(0, 20).Select(_ => gate.RunAsync(async cancellationToken =>
        {
            var entered = Interlocked.Increment(ref concurrent);
            maximum = Math.Max(maximum, entered);
            try
            {
                await release.Task.WaitAsync(cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref concurrent);
            }
        }, CancellationToken.None)).ToArray();

        await Task.Yield();
        Assert.Equal(1, Volatile.Read(ref concurrent));
        release.TrySetResult();
        await Task.WhenAll(operations);
        Assert.Equal(1, maximum);
    }

    [Fact]
    public async Task Background_health_check_skips_instead_of_queueing_behind_signing()
    {
        await using var gate = new SigningOperationGate();
        var signingEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var signing = gate.RunAsync(async cancellationToken =>
        {
            signingEntered.TrySetResult();
            await release.Task.WaitAsync(cancellationToken);
        }, CancellationToken.None);
        await signingEntered.Task;
        var healthCalls = 0;

        var ran = await gate.TryRunHealthCheckAsync(_ =>
        {
            healthCalls++;
            return Task.CompletedTask;
        }, CancellationToken.None);

        Assert.False(ran);
        Assert.Equal(0, healthCalls);
        release.TrySetResult();
        await signing;
    }
}
