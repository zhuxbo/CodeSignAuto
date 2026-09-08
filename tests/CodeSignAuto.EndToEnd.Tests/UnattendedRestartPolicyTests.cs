using System.Xml.Linq;
using System.Security.Principal;
using CodeSignAuto.App.Commands;
using Xunit;

namespace CodeSignAuto.EndToEnd.Tests;

public sealed class UnattendedRestartPolicyTests
{
    private const string OwnerMarker =
        "CodeSignAuto/v1/0123456789abcdef0123456789abcdef";

    [Fact]
    public void Agent_task_has_one_bounded_restart_policy_without_changing_the_interactive_contract()
    {
        var action = CreateAction();
        var document = XDocument.Parse(WindowsTaskXml.Create(action));
        XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        var restart = Assert.Single(document.Descendants(task + "RestartOnFailure"));
        Assert.Equal("PT1M", restart.Element(task + "Interval")?.Value);
        Assert.Equal("3", restart.Element(task + "Count")?.Value);
        Assert.Equal("InteractiveToken", Assert.Single(document.Descendants(task + "LogonType")).Value);
        Assert.Equal(InstallFixtureSid, Assert.Single(document.Descendants(task + "LogonTrigger"))
            .Element(task + "UserId")?.Value);
        Assert.Equal("HighestAvailable", Assert.Single(document.Descendants(task + "RunLevel")).Value);
        Assert.Equal("agent --background", Assert.Single(document.Descendants(task + "Arguments")).Value);
    }

    [Fact]
    public void Agent_task_readback_rejects_an_unbounded_or_modified_restart_policy()
    {
        var action = CreateAction();
        var exact = XDocument.Parse(WindowsTaskXml.Create(action));
        XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        Assert.True(WindowsTaskXml.IsOwned(exact.ToString(SaveOptions.DisableFormatting), action));

        var unlimited = new XDocument(exact);
        unlimited.Descendants(task + "RestartOnFailure").Single()
            .Element(task + "Count")!.Value = int.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture);
        Assert.False(WindowsTaskXml.IsOwned(
            unlimited.ToString(SaveOptions.DisableFormatting),
            action));

        var duplicate = new XDocument(exact);
        duplicate.Descendants(task + "Settings").Single().Add(
            new XElement(task + "RestartOnFailure",
                new XElement(task + "Interval", "PT1M"),
                new XElement(task + "Count", "3")));
        Assert.False(WindowsTaskXml.IsOwned(
            duplicate.ToString(SaveOptions.DisableFormatting),
            action));
    }

    [Fact]
    public void Agent_task_readback_accepts_an_omitted_default_enabled_value_but_rejects_false_or_duplicates()
    {
        var action = CreateAction();
        var exact = XDocument.Parse(WindowsTaskXml.Create(action));
        XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        var omitted = new XDocument(exact);
        omitted.Descendants(task + "LogonTrigger").Single()
            .Element(task + "Enabled")!.Remove();
        Assert.True(WindowsTaskXml.IsOwned(
            omitted.ToString(SaveOptions.DisableFormatting),
            action));

        var disabled = new XDocument(exact);
        disabled.Descendants(task + "LogonTrigger").Single()
            .Element(task + "Enabled")!.Value = "false";
        AssertRejected(disabled, action);

        var duplicate = new XDocument(exact);
        duplicate.Descendants(task + "LogonTrigger").Single().Add(
            new XElement(task + "Enabled", "true"));
        AssertRejected(duplicate, action);
    }

    [Fact]
    public void Agent_task_readback_accepts_omitted_default_settings_enabled_but_rejects_false_or_duplicates()
    {
        var action = CreateAction();
        var exact = XDocument.Parse(WindowsTaskXml.Create(action));
        XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        var omitted = new XDocument(exact);
        omitted.Descendants(task + "Settings").Single()
            .Element(task + "Enabled")!.Remove();
        Assert.True(WindowsTaskXml.IsOwned(
            omitted.ToString(SaveOptions.DisableFormatting),
            action));

        var disabled = new XDocument(exact);
        disabled.Descendants(task + "Settings").Single()
            .Element(task + "Enabled")!.Value = "false";
        AssertRejected(disabled, action);

        var duplicate = new XDocument(exact);
        duplicate.Descendants(task + "Settings").Single().Add(
            new XElement(task + "Enabled", "true"));
        AssertRejected(duplicate, action);
    }

    [WindowsFact]
    public void Agent_task_readback_accepts_the_scheduler_account_name_only_when_it_maps_to_the_expected_sid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User!.Value;
        var action = CreateAction() with
        {
            AccountName = identity.Name,
            SigningUserSid = sid,
        };
        var normalized = XDocument.Parse(WindowsTaskXml.Create(action));
        XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var trigger = normalized.Descendants(task + "LogonTrigger").Single();
        trigger.Element(task + "Enabled")!.Remove();
        trigger.Element(task + "UserId")!.Value = identity.Name;

        Assert.True(WindowsTaskXml.IsOwned(
            normalized.ToString(SaveOptions.DisableFormatting),
            action));

        trigger.Element(task + "UserId")!.Value = "BUILTIN\\Users";
        AssertRejected(normalized, action);
    }

    [Fact]
    public void Agent_task_ownership_rejects_extra_triggers_and_duplicate_critical_nodes()
    {
        var action = CreateAction();
        var exact = XDocument.Parse(WindowsTaskXml.Create(action));
        XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";

        var bootTrigger = new XDocument(exact);
        bootTrigger.Descendants(task + "Triggers").Single().Add(new XElement(task + "BootTrigger"));
        AssertRejected(bootTrigger, action);

        var timeTrigger = new XDocument(exact);
        timeTrigger.Descendants(task + "Triggers").Single().Add(new XElement(task + "TimeTrigger"));
        AssertRejected(timeTrigger, action);

        var duplicatePrincipalContainer = new XDocument(exact);
        duplicatePrincipalContainer.Root!.Add(
            new XElement(duplicatePrincipalContainer.Root.Element(task + "Principals")!));
        AssertRejected(duplicatePrincipalContainer, action);

        var duplicatePrincipal = new XDocument(exact);
        duplicatePrincipal.Descendants(task + "Principals").Single().Add(
            new XElement(duplicatePrincipal.Descendants(task + "Principal").Single()));
        AssertRejected(duplicatePrincipal, action);

        var duplicateActions = new XDocument(exact);
        duplicateActions.Root!.Add(new XElement(duplicateActions.Root.Element(task + "Actions")!));
        AssertRejected(duplicateActions, action);

        var duplicateExec = new XDocument(exact);
        duplicateExec.Descendants(task + "Actions").Single().Add(
            new XElement(duplicateExec.Descendants(task + "Exec").Single()));
        AssertRejected(duplicateExec, action);

        var duplicateSettings = new XDocument(exact);
        duplicateSettings.Root!.Add(new XElement(duplicateSettings.Root.Element(task + "Settings")!));
        AssertRejected(duplicateSettings, action);

        var duplicateSettingsValue = new XDocument(exact);
        duplicateSettingsValue.Descendants(task + "Settings").Single().Add(
            new XElement(task + "RunOnlyIfNetworkAvailable", "true"));
        AssertRejected(duplicateSettingsValue, action);
    }

    [Theory]
    [InlineData("Delay")]
    [InlineData("Repetition")]
    [InlineData("StartBoundary")]
    [InlineData("EndBoundary")]
    [InlineData("ExecutionTimeLimit")]
    public void Agent_task_ownership_rejects_every_unplanned_logon_trigger_semantic(
        string localName)
    {
        var action = CreateAction();
        var document = XDocument.Parse(WindowsTaskXml.Create(action));
        XNamespace task = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        document.Descendants(task + "LogonTrigger").Single().Add(
            localName == "Repetition"
                ? new XElement(task + localName,
                    new XElement(task + "Interval", "PT1M"),
                    new XElement(task + "Duration", "PT1H"))
                : new XElement(task + localName, "PT1M"));

        AssertRejected(document, action);
    }

    private const string InstallFixtureSid = "S-1-5-21-1000-2000-3000-4000";

    private static void AssertRejected(XDocument document, CreateInteractiveLogonTask action) =>
        Assert.False(WindowsTaskXml.IsOwned(
            document.ToString(SaveOptions.DisableFormatting),
            action));

    private static CreateInteractiveLogonTask CreateAction() => new(
        "CodeSignAuto.Agent",
        "TEST\\signer",
        InstallFixtureSid,
        Path.Combine(Path.GetTempPath(), "CodeSignAuto.exe"),
        ["agent", "--background"],
        "InteractiveToken",
        Highest: true,
        RunOnlyIfNetworkAvailable: true,
        OwnerMarker);

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Requires Windows account-to-SID translation.";
            }
        }
    }
}
