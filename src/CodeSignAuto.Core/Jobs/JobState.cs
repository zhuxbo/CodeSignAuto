namespace CodeSignAuto.Core.Jobs;

public enum JobState
{
    Queued,
    WaitingForAgent,
    Signing,
    Verifying,
    Succeeded,
    Failed,
    Expired,
}
