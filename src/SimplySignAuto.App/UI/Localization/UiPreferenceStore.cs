using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using SimplySignAuto.Core.Security;

namespace SimplySignAuto.App.UI.Localization;

public sealed class UiPreferenceStore
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = true,
    };

    private readonly string _path;

    public UiPreferenceStore()
        : this(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SimplySignAuto",
            "ui.json"))
    {
    }

    public UiPreferenceStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
    }

    public async Task<CultureInfo> LoadAsync(
        CultureInfo systemUiCulture,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(systemUiCulture);
        try
        {
            var kind = NoFollowFile.InspectPathEntry(_path);
            if (kind == NoFollowPathEntryKind.Missing)
            {
                return UiCulture.ResolveDefault(systemUiCulture);
            }

            if (kind != NoFollowPathEntryKind.RegularFile)
            {
                throw InvalidPreference();
            }

            await using var stream = NoFollowFile.OpenRead(_path, FileShare.Read, 4096);
            using var document = await JsonDocument.ParseAsync(
                stream,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            return ParseStrict(document.RootElement);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception error) when (
            error is JsonException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            throw InvalidPreference(error);
        }
    }

    public async Task SaveAsync(string cultureName, CancellationToken cancellationToken)
    {
        var selected = UiCulture.ResolveSelection(cultureName);
        var directory = Path.GetDirectoryName(_path)
            ?? throw new InvalidOperationException("ui_preference_path_invalid");
        EnsureSafeDirectory(directory);
        EnsureSafeTarget();

        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        var published = false;
        try
        {
            await using (var stream = CreateProtectedTemporaryFile(temporaryPath))
            {
                await using var writer = new Utf8JsonWriter(stream, WriterOptions);
                writer.WriteStartObject();
                writer.WriteString("culture", selected.Name);
                writer.WriteEndObject();
                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            EnsureSafeDirectory(directory);
            EnsureSafeTarget();
            File.Move(temporaryPath, _path, overwrite: true);
            published = true;
        }
        finally
        {
            if (!published && NoFollowFile.InspectPathEntry(temporaryPath) == NoFollowPathEntryKind.RegularFile)
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private void EnsureSafeTarget()
    {
        if (NoFollowFile.InspectPathEntry(_path) is not (
            NoFollowPathEntryKind.Missing or NoFollowPathEntryKind.RegularFile))
        {
            throw InvalidPreference();
        }
    }

    private static void EnsureSafeDirectory(string directory)
    {
        var kind = NoFollowFile.InspectPathEntry(directory);
        if (kind == NoFollowPathEntryKind.Missing)
        {
            Directory.CreateDirectory(directory);
            kind = NoFollowFile.InspectPathEntry(directory);
        }

        if (kind != NoFollowPathEntryKind.Directory)
        {
            throw InvalidPreference();
        }
    }

    private static CultureInfo ParseStrict(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw InvalidPreference();
        }

        string? cultureName = null;
        foreach (var property in root.EnumerateObject())
        {
            if (property.Name != "culture" || cultureName is not null ||
                property.Value.ValueKind != JsonValueKind.String)
            {
                throw InvalidPreference();
            }

            cultureName = property.Value.GetString();
        }

        if (cultureName is null)
        {
            throw InvalidPreference();
        }

        try
        {
            return UiCulture.ResolveSelection(cultureName);
        }
        catch (ArgumentException error)
        {
            throw InvalidPreference(error);
        }
    }

    private static FileStream CreateProtectedTemporaryFile(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
        }

        return WindowsCurrentUserFile.CreateNew(path);
    }

    private static InvalidDataException InvalidPreference(Exception? inner = null) =>
        new("ui_preference_invalid", inner);

    private static class WindowsCurrentUserFile
    {
        private const uint GenericWrite = 0x40000000;
        private const uint CreationDispositionCreateNew = 1;
        private const uint FileAttributeNormal = 0x00000080;
        private const uint FileFlagOverlapped = 0x40000000;
        private const uint FileFlagWriteThrough = 0x80000000;

        public static FileStream CreateNew(string path)
        {
            using var identity = WindowsIdentity.GetCurrent();
            var currentUser = identity.User ?? throw InvalidPreference();
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(currentUser);
            security.AddAccessRule(new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                system,
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            var descriptorBytes = security.GetSecurityDescriptorBinaryForm();
            var descriptor = GCHandle.Alloc(descriptorBytes, GCHandleType.Pinned);
            SafeFileHandle handle;
            try
            {
                var attributes = new SecurityAttributes
                {
                    Length = Marshal.SizeOf<SecurityAttributes>(),
                    SecurityDescriptor = descriptor.AddrOfPinnedObject(),
                    InheritHandle = false,
                };
                handle = CreateFileW(
                    path,
                    GenericWrite,
                    0,
                    ref attributes,
                    CreationDispositionCreateNew,
                    FileAttributeNormal | FileFlagOverlapped | FileFlagWriteThrough,
                    nint.Zero);
                if (handle.IsInvalid)
                {
                    handle.Dispose();
                    throw new IOException(
                        "Protected UI preference file creation failed.",
                        new Win32Exception(Marshal.GetLastWin32Error()));
                }
            }
            finally
            {
                descriptor.Free();
            }

            try
            {
                return new FileStream(handle, FileAccess.Write, 4096, isAsync: true);
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes
        {
            public int Length;
            public nint SecurityDescriptor;

            [MarshalAs(UnmanagedType.Bool)]
            public bool InheritHandle;
        }

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string path,
            uint desiredAccess,
            uint shareMode,
            ref SecurityAttributes securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            nint templateFile);
    }
}
