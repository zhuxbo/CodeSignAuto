using CodeSignAuto.App.UI.Views;

namespace CodeSignAuto.UI.Tests;

public sealed class ActivationImportDialogStateTests
{
    [Fact]
    public void Saving_rejects_user_close_then_success_requests_exactly_one_close()
    {
        var state = new ActivationImportDialogState();

        Assert.True(state.TryBeginSave());
        Assert.Equal(ActivationImportCloseDecision.SaveInProgress, state.RequestUserClose());
        Assert.Equal(ActivationImportCloseDecision.SaveInProgress, state.RequestUserClose());
        Assert.True(state.CompleteSave(succeeded: true));
        Assert.False(state.CompleteSave(succeeded: true));
        Assert.Equal(ActivationImportCloseDecision.Allowed, state.RequestUserClose());
    }

    [Fact]
    public void Closed_dialog_never_requests_a_post_await_close()
    {
        var state = new ActivationImportDialogState();
        Assert.True(state.TryBeginSave());

        state.MarkClosed();

        Assert.False(state.CompleteSave(succeeded: true));
        Assert.Equal(ActivationImportCloseDecision.AlreadyClosed, state.RequestUserClose());
    }

    [Fact]
    public void Failed_save_returns_to_idle_without_requesting_close()
    {
        var state = new ActivationImportDialogState();
        Assert.True(state.TryBeginSave());

        Assert.False(state.CompleteSave(succeeded: false));

        Assert.True(state.TryBeginSave());
    }
}
