using System.Net;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class EndToEndHarnessTests
{
    [Fact]
    public async Task Harness_uses_real_http_kestrel()
    {
        await using var harness = await EndToEndHarness.StartAsync();

        using var response = await harness.Client.GetAsync("/health/live");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("http", harness.Client.BaseAddress!.Scheme);
        Assert.False(harness.UsesTestServer);
    }

    [Fact]
    public async Task Dispose_cleanup_preserves_the_first_failure_and_runs_later_cleanup_best_effort()
    {
        var first = new InvalidOperationException("first_dispose_failure");
        var second = new IOException("second_dispose_failure");
        var order = new List<string>();

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await EndToEndHarness.RunCleanupPreservingFirstAsync(
                null,
                () => Fail("first", first),
                () => Fail("second", second),
                () => Complete("third")));

        Assert.Same(first, thrown);
        Assert.Equal(["first", "second", "third"], order);

        ValueTask Fail(string step, Exception error)
        {
            order.Add(step);
            return ValueTask.FromException(error);
        }

        ValueTask Complete(string step)
        {
            order.Add(step);
            return ValueTask.CompletedTask;
        }
    }

    [Fact]
    public async Task Start_cleanup_preserves_the_start_failure_ahead_of_multiple_cleanup_failures()
    {
        var start = new InvalidOperationException("start_failure");
        var order = new List<string>();

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await EndToEndHarness.RunCleanupPreservingFirstAsync(
                start,
                () => Fail("dispose_application"),
                () => Fail("delete_root")));

        Assert.Same(start, thrown);
        Assert.Equal(["dispose_application", "delete_root"], order);

        ValueTask Fail(string step)
        {
            order.Add(step);
            return ValueTask.FromException(new IOException(step));
        }
    }
}
