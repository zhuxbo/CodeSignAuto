using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.Service.Tests;

public sealed class UpgradeAdmissionGateTests
{
    [Fact]
    public async Task Drain_rejects_new_admissions_and_waits_for_the_current_admission()
    {
        var gate = new UpgradeAdmissionGate();
        var admission = await gate.TryEnterAsync(CancellationToken.None);
        Assert.NotNull(admission);
        await using var admissionLease = admission;

        var drain = gate.DrainAsync(TimeSpan.FromSeconds(1), CancellationToken.None);
        await WaitUntilAsync(() => gate.IsDraining);

        Assert.Null(await gate.TryEnterAsync(CancellationToken.None));
        Assert.False(drain.IsCompleted);

        await admissionLease.DisposeAsync();

        Assert.True(await drain);
        Assert.Null(await gate.TryEnterAsync(CancellationToken.None));
    }

    [Fact]
    public async Task Timed_out_drain_reopens_admission_without_leaking_the_active_count()
    {
        var gate = new UpgradeAdmissionGate();
        var admission = await gate.TryEnterAsync(CancellationToken.None);
        Assert.NotNull(admission);
        await using var admissionLease = admission;

        Assert.False(await gate.DrainAsync(TimeSpan.FromMilliseconds(20), CancellationToken.None));
        Assert.False(gate.IsDraining);

        var accepted = await gate.TryEnterAsync(CancellationToken.None);
        Assert.NotNull(accepted);
        await using var acceptedLease = accepted;
    }

    [Fact]
    public async Task Resume_is_idempotent_after_a_completed_drain()
    {
        var gate = new UpgradeAdmissionGate();
        Assert.True(await gate.DrainAsync(TimeSpan.FromSeconds(1), CancellationToken.None));

        gate.Resume();
        gate.Resume();

        var accepted = await gate.TryEnterAsync(CancellationToken.None);
        Assert.NotNull(accepted);
        await using var acceptedLease = accepted;
    }

    [Fact]
    public async Task Drain_waits_for_unaccepted_local_upload_and_seals_existing_admissions_after_completion()
    {
        var root = Directory.CreateTempSubdirectory("ssa-upgrade-drain-").FullName;
        var database = Path.Combine(root, "jobs.db");
        try
        {
            using var jobs = new SqliteJobStore(database);
            var now = DateTimeOffset.UtcNow;
            var pending = new LocalUploadLeaseRecord(
                Guid.NewGuid(),
                new string('a', 64),
                Guid.NewGuid(),
                new string('b', 64),
                [1],
                "S-1-5-21-1-2-3-1001",
                7,
                "0123456789abcdef0123456789abcdef/input.exe.part",
                "input.exe",
                ".exe",
                16,
                "{}",
                now,
                now.AddMinutes(5),
                null);
            await jobs.CreateOrGetLocalLeaseAsync(pending);

            var gate = new UpgradeAdmissionGate();
            var coordinator = new UpgradeDrainCoordinator(gate, jobs, TimeProvider.System);
            var drain = coordinator.DrainAsync(TimeSpan.FromSeconds(2), CancellationToken.None);
            await WaitUntilAsync(() => gate.IsDraining);
            await Task.Delay(120);

            Assert.False(drain.IsCompleted);
            Assert.Null(await gate.TryEnterAsync(CancellationToken.None));
            var completion = await gate.TryEnterExistingAsync(CancellationToken.None);
            Assert.NotNull(completion);
            await using var completionLease = completion;

            Assert.True(await jobs.DeleteLocalLeaseAsync(pending.RequestId, pending.JobId));
            await Task.Delay(120);
            Assert.False(drain.IsCompleted);

            await completionLease.DisposeAsync();
            Assert.True(await drain);
            Assert.Null(await gate.TryEnterExistingAsync(CancellationToken.None));

            coordinator.Resume();
            var resumed = await gate.TryEnterAsync(CancellationToken.None);
            Assert.NotNull(resumed);
            await using var resumedLease = resumed;
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(1);
        while (!condition())
        {
            if (DateTimeOffset.UtcNow >= deadline)
            {
                throw new TimeoutException();
            }

            await Task.Delay(5);
        }
    }
}
