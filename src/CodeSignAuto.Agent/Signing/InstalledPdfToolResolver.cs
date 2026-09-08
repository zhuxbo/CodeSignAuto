namespace CodeSignAuto.Agent.Signing;

public enum InstalledPdfToolStatus
{
    Ready,
    NotInstalled,
    Tampered,
}

public sealed record InstalledPdfTool(
    string ExecutablePath,
    string Sha256);

public sealed record InstalledPdfToolResolution(
    InstalledPdfToolStatus Status,
    string FailureCode,
    InstalledPdfTool? Tool)
{
    public static InstalledPdfToolResolution Ready(InstalledPdfTool tool) =>
        new(InstalledPdfToolStatus.Ready, string.Empty, tool);

    public static InstalledPdfToolResolution NotInstalled() =>
        new(InstalledPdfToolStatus.NotInstalled, "pdf_support_not_installed", null);

    public static InstalledPdfToolResolution Tampered() =>
        new(InstalledPdfToolStatus.Tampered, "pdf_helper_tampered", null);
}

public interface IInstalledPdfToolResolver
{
    Task<InstalledPdfToolResolution> ResolveAsync(CancellationToken cancellationToken);
}
