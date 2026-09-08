using CodeSignAuto.App.Tools;

namespace CodeSignAuto.App.Commands;

internal sealed record PdfExtensionInstallPlan(
    PdfExtensionPaths Target,
    PdfExtensionManifest Manifest,
    string SigningUserSid,
    string InstanceId);

internal interface IPdfExtensionOperations
{
    void RequireAdministrator();

    Task<PdfExtensionInstallPlan> PlanInstallAsync(
        string mediaRoot,
        CancellationToken cancellationToken);

    Task PublishInstallAsync(
        PdfExtensionInstallPlan plan,
        CancellationToken cancellationToken);

    Task UninstallAsync(CancellationToken cancellationToken);
}

internal static class PdfExtensionCommand
{
    internal static async Task<int> ExecuteAsync(
        string[] arguments,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken,
        IPdfExtensionOperations operations)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(operations);
        try
        {
            operations.RequireAdministrator();
            switch (arguments)
            {
                case ["install", "--media-root", var mediaRoot]
                    when Path.IsPathFullyQualified(mediaRoot) && !mediaRoot.Any(char.IsControl):
                {
                    var plan = await operations.PlanInstallAsync(mediaRoot, cancellationToken)
                        .ConfigureAwait(false);
                    await output.WriteLineAsync("phase=pdf_extension_media code=ready")
                        .ConfigureAwait(false);
                    await operations.PublishInstallAsync(plan, cancellationToken)
                        .ConfigureAwait(false);
                    await output.WriteLineAsync("pdf_extension_installed").ConfigureAwait(false);
                    return 0;
                }
                case ["uninstall"]:
                    await operations.UninstallAsync(cancellationToken).ConfigureAwait(false);
                    await output.WriteLineAsync("pdf_extension_uninstalled").ConfigureAwait(false);
                    return 0;
                default:
                    throw new InstallException("pdf_extension_arguments_invalid");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InstallException failure)
        {
            await error.WriteLineAsync(failure.Code).ConfigureAwait(false);
            return 1;
        }
    }
}
