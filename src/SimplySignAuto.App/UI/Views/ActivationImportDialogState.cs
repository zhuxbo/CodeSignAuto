namespace SimplySignAuto.App.UI.Views;

internal enum ActivationImportCloseDecision
{
    Allowed,
    SaveInProgress,
    AlreadyClosed,
}

internal sealed class ActivationImportDialogState
{
    private const int Idle = 0;
    private const int Saving = 1;
    private const int Closed = 2;
    private int _state;

    public bool IsSaving => Volatile.Read(ref _state) == Saving;

    public bool TryBeginSave() => Interlocked.CompareExchange(ref _state, Saving, Idle) == Idle;

    public ActivationImportCloseDecision RequestUserClose() => Volatile.Read(ref _state) switch
    {
        Saving => ActivationImportCloseDecision.SaveInProgress,
        Closed => ActivationImportCloseDecision.AlreadyClosed,
        _ => ActivationImportCloseDecision.Allowed,
    };

    public bool CompleteSave(bool succeeded) =>
        Interlocked.CompareExchange(ref _state, Idle, Saving) == Saving && succeeded;

    public void MarkClosed() => Interlocked.Exchange(ref _state, Closed);
}
