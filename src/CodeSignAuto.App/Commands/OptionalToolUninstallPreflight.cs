using CodeSignAuto.App.Tools;
using CodeSignAuto.Core.Security;

namespace CodeSignAuto.App.Commands;

internal sealed record OptionalToolUninstallTreeEntry(
    string RelativePath,
    bool IsDirectory);

internal sealed record OptionalToolUninstallTreeSnapshot(
    IReadOnlyList<OptionalToolUninstallTreeEntry> Entries);

internal sealed record InstalledProductIdentity(
    string ExecutablePath,
    string SigningUserSid);

internal interface IOptionalToolUninstallTreeInspector
{
    OptionalToolUninstallTreeSnapshot Inspect(
        string toolsRoot,
        string signingUserSid);
}

internal interface IOptionalToolUninstallPreflight
{
    Task VerifyAsync(
        InstalledProductIdentity identity,
        CancellationToken cancellationToken);
}

internal sealed class WindowsOptionalToolUninstallPreflight : IOptionalToolUninstallPreflight
{
    private readonly IInstalledPdfToolSecurity _security;
    private readonly IOptionalToolUninstallTreeInspector _treeInspector;

    internal WindowsOptionalToolUninstallPreflight()
        : this(
            new WindowsInstalledPdfToolSecurity(),
            new WindowsOptionalToolUninstallTreeInspector())
    {
    }

    internal WindowsOptionalToolUninstallPreflight(
        IInstalledPdfToolSecurity security,
        IOptionalToolUninstallTreeInspector treeInspector)
    {
        _security = security ?? throw new ArgumentNullException(nameof(security));
        _treeInspector = treeInspector ?? throw new ArgumentNullException(nameof(treeInspector));
    }

    public async Task VerifyAsync(
        InstalledProductIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var productRoot = Path.GetDirectoryName(identity.ExecutablePath)
                ?? throw new IOException("optional_tool_path_invalid");
            var programFilesRoot = Directory.GetParent(productRoot)?.FullName
                ?? throw new IOException("optional_tool_path_invalid");
            var paths = PdfExtensionPaths.FromProgramFiles(programFilesRoot);
            var manifestJson = await _security.ReadManifestAsync(
                    paths,
                    identity.SigningUserSid,
                    cancellationToken)
                .ConfigureAwait(false);
            if (manifestJson is null)
            {
                return;
            }

            var manifest = PdfExtensionManifestCodec.Decode(manifestJson);
            var tree = _treeInspector.Inspect(paths.Root, identity.SigningUserSid);
            if (!HasExactReadyTree(tree.Entries))
            {
                throw new IOException("optional_tool_tree_mismatch");
            }

            await _security.VerifyHelperAsync(
                    paths.Helper,
                    manifest,
                    identity.SigningUserSid,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    private static bool HasExactReadyTree(IReadOnlyList<OptionalToolUninstallTreeEntry> entries)
    {
        OptionalToolUninstallTreeEntry[] expected =
        [
            new("extension.json", IsDirectory: false),
            new("LICENSE.txt", IsDirectory: false),
            new("CodeSignAutoPdfSigner.exe", IsDirectory: false),
            new("THIRD-PARTY-NOTICES.txt", IsDirectory: false),
        ];
        return entries.Count == expected.Length &&
            entries.OrderBy(static entry => entry.RelativePath, StringComparer.Ordinal)
                .SequenceEqual(expected.OrderBy(
                    static entry => entry.RelativePath,
                    StringComparer.Ordinal));
    }
}

internal sealed class WindowsOptionalToolUninstallTreeInspector
    : IOptionalToolUninstallTreeInspector
{
    private const int MaximumEntries = 16;
    private readonly ILocalFileIdentityProvider _fileIdentities =
        PlatformLocalFileIdentityProvider.Instance;

    public OptionalToolUninstallTreeSnapshot Inspect(
        string toolsRoot,
        string signingUserSid)
    {
        try
        {
            if (!OperatingSystem.IsWindows() ||
                NoFollowFile.InspectPathEntry(toolsRoot) != NoFollowPathEntryKind.Directory)
            {
                throw new IOException("optional_tool_root_invalid");
            }

            using var rootHandle = WindowsNoFollowSecurity.OpenDirectoryHandle(toolsRoot);
            var rootIdentity = VerifyHandle(rootHandle, signingUserSid, requireReadExecute: true);
            var entries = new List<OptionalToolUninstallTreeEntry>();
            foreach (var path in Directory.EnumerateFileSystemEntries(toolsRoot))
            {
                AddEntry(toolsRoot, path, signingUserSid, entries, allowDirectory: true);
                if (entries[^1].IsDirectory)
                {
                    foreach (var child in Directory.EnumerateFileSystemEntries(path))
                    {
                        AddEntry(toolsRoot, child, signingUserSid, entries, allowDirectory: false);
                    }
                }
            }

            using var rootReadback = WindowsNoFollowSecurity.OpenDirectoryHandle(toolsRoot);
            var readbackIdentity = VerifyHandle(
                rootReadback,
                signingUserSid,
                requireReadExecute: true);
            if (rootIdentity != readbackIdentity)
            {
                throw new IOException("optional_tool_root_replaced");
            }

            return new OptionalToolUninstallTreeSnapshot(entries);
        }
        catch (InstallException)
        {
            throw;
        }
        catch
        {
            throw new InstallException("owned_resource_mismatch");
        }
    }

    private void AddEntry(
        string toolsRoot,
        string path,
        string signingUserSid,
        List<OptionalToolUninstallTreeEntry> entries,
        bool allowDirectory)
    {
        if (entries.Count >= MaximumEntries)
        {
            throw new IOException("optional_tool_tree_too_large");
        }

        var kind = NoFollowFile.InspectPathEntry(path);
        var isDirectory = kind == NoFollowPathEntryKind.Directory;
        if (kind != NoFollowPathEntryKind.RegularFile && (!allowDirectory || !isDirectory))
        {
            throw new IOException("optional_tool_entry_invalid");
        }

        if (isDirectory)
        {
            using var handle = WindowsNoFollowSecurity.OpenDirectoryHandle(path);
            _ = VerifyHandle(handle, signingUserSid, requireReadExecute: true);
        }
        else
        {
            using var handle = WindowsNoFollowSecurity.OpenReadFileHandleExclusive(path);
            _ = VerifyHandle(handle, signingUserSid, requireReadExecute: true);
        }

        var relativePath = Path.GetRelativePath(toolsRoot, path);
        if (relativePath.StartsWith("..", StringComparison.Ordinal) ||
            Path.IsPathFullyQualified(relativePath))
        {
            throw new IOException("optional_tool_entry_invalid");
        }

        entries.Add(new OptionalToolUninstallTreeEntry(relativePath, isDirectory));
    }

    private LocalFileIdentity VerifyHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle handle,
        string signingUserSid,
        bool requireReadExecute)
    {
        WindowsExecutableSecurity.VerifyEntry(
            WindowsNoFollowSecurity.Read(handle),
            signingUserSid,
            requireReadExecute);
        if (!_fileIdentities.TryGetIdentity(handle, out var identity) || identity.LinkCount != 1)
        {
            throw new IOException("optional_tool_link_invalid");
        }

        return identity;
    }
}
