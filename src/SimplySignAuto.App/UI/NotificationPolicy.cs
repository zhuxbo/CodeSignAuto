using SimplySignAuto.App.UI.Status;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.App.UI;

public enum TrayNotificationKind
{
    ServiceUnavailable,
    LocalJobSucceeded,
    JobFailed,
}

public sealed record TrayNotification(
    TrayNotificationKind Kind,
    string Title,
    string Message);

public sealed class NotificationPolicy
{
    private static readonly TimeSpan UnavailableSuppression = TimeSpan.FromMinutes(30);
    private readonly TimeProvider _timeProvider;
    private readonly Dictionary<string, DateTimeOffset> _unavailableNotifiedAt = new(StringComparer.Ordinal);
    private long _terminalSequence;
    private bool _terminalBaselineEstablished;

    public NotificationPolicy(TimeProvider? timeProvider = null) =>
        _timeProvider = timeProvider ?? TimeProvider.System;

    internal int TrackedTerminalJobCount => 0;

    public IReadOnlyList<TrayNotification> Evaluate(
        OverallStatus? previous,
        OverallStatus current,
        IReadOnlyList<TerminalJobEventItem>? terminalJobs)
    {
        ArgumentNullException.ThrowIfNull(current);
        var notifications = new List<TrayNotification>();
        EvaluateAvailability(previous, current, notifications);
        if (terminalJobs is not null)
        {
            EvaluateTerminalJobs(terminalJobs, notifications);
        }

        return notifications.AsReadOnly();
    }

    private void EvaluateAvailability(
        OverallStatus? previous,
        OverallStatus current,
        ICollection<TrayNotification> notifications)
    {
        if (current.Overall == OverallReadiness.Ready)
        {
            _unavailableNotifiedAt.Clear();
            return;
        }

        if (previous?.Overall != OverallReadiness.Ready ||
            current.Overall != OverallReadiness.ActionRequired)
        {
            return;
        }

        var reason = current.Reasons.FirstOrDefault() ?? "service_unavailable";
        var now = _timeProvider.GetUtcNow();
        if (_unavailableNotifiedAt.TryGetValue(reason, out var notifiedAt))
        {
            var elapsed = now - notifiedAt;
            if (elapsed < TimeSpan.Zero || elapsed < UnavailableSuppression)
            {
                return;
            }
        }

        _unavailableNotifiedAt[reason] = now;
        notifications.Add(new TrayNotification(
            TrayNotificationKind.ServiceUnavailable,
            "SimplySignAuto 需要处理",
            "签名服务当前不可用，请打开管理控制台查看状态。"));
    }

    private void EvaluateTerminalJobs(
        IReadOnlyList<TerminalJobEventItem> terminalJobs,
        ICollection<TrayNotification> notifications)
    {
        if (!_terminalBaselineEstablished)
        {
            _terminalSequence = terminalJobs.Count == 0 ? 0 : terminalJobs.Max(static item => item.Sequence);
            _terminalBaselineEstablished = true;
            return;
        }

        foreach (var terminalEvent in terminalJobs.OrderBy(static item => item.Sequence))
        {
            if (terminalEvent.Sequence <= _terminalSequence)
            {
                continue;
            }

            var job = terminalEvent.Item;
            if (!IsTerminal(job))
            {
                throw new InvalidOperationException("terminal_event_is_not_terminal");
            }

            if (job.State == "succeeded" && job.Source == "local")
            {
                notifications.Add(new TrayNotification(
                    TrayNotificationKind.LocalJobSucceeded,
                    "本机签名已完成",
                    $"本机 {KindText(job.Kind)} 签名已完成（任务 {JobSuffix(job.JobId)}）。"));
            }
            else if (job.State == "failed")
            {
                notifications.Add(new TrayNotification(
                    TrayNotificationKind.JobFailed,
                    "签名任务失败",
                    $"{SourceText(job.Source)} {KindText(job.Kind)} 签名失败：{job.ErrorCode}（任务 {JobSuffix(job.JobId)}）。"));
            }

            _terminalSequence = terminalEvent.Sequence;
        }
    }

    private static bool IsTerminal(JobPageItem job) =>
        job.State is "succeeded" or "failed" or "expired" && job.CompletedAtUtc is not null;

    private static string SourceText(string source) => source == "local" ? "本机" : "CI/API";

    private static string KindText(string kind) => kind == "pdf" ? "PDF" : "软件";

    private static string JobSuffix(Guid jobId) => jobId.ToString("N")[^8..].ToUpperInvariant();

}
