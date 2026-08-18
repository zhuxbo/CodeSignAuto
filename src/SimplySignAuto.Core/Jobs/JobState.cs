namespace SimplySignAuto.Core.Jobs;

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
