using System.Text.Json;
using System.Text;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.Core.Security;

namespace SimplySignAuto.App.Manual;

internal sealed record ManualSettings(int SchemaVersion, int RetentionHours)
{
    public const int CurrentSchemaVersion = 1;
    public const int DefaultRetentionHours = 168;
}

internal sealed class ManualSettingsStore
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Indented = true,
    };

    private readonly string _path;
    private int _currentRetentionHours = ManualSettings.DefaultRetentionHours;

    public ManualSettingsStore()
        : this(DefaultPath)
    {
    }

    internal ManualSettingsStore(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = System.IO.Path.GetFullPath(path);
    }

    internal static string DefaultPath => System.IO.Path.GetFullPath(System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SimplySignAuto",
        "manual",
        "settings.json"));

    internal string Path => _path;

    internal int CurrentRetentionHours => Volatile.Read(ref _currentRetentionHours);

    internal async Task<ManualSettings> LoadAsync(CancellationToken cancellationToken)
    {
        try
        {
            var kind = NoFollowFile.InspectPathEntry(_path);
            if (kind == NoFollowPathEntryKind.Missing)
            {
                return SetCurrent(ManualSettings.DefaultRetentionHours);
            }

            if (kind != NoFollowPathEntryKind.RegularFile)
            {
                throw InvalidSettings();
            }

            await using var stream = NoFollowFile.OpenRead(_path, FileShare.Read, 4096);
            if (stream.Length is <= 0 or > 4096)
            {
                throw InvalidSettings();
            }

            using var reader = new StreamReader(
                stream,
                new System.Text.UTF8Encoding(false, true),
                detectEncodingFromByteOrderMarks: false,
                bufferSize: 4096,
                leaveOpen: false);
            var json = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            StrictJson.RejectDuplicatePropertiesAndSecretShapes(json);
            using var document = JsonDocument.Parse(json);
            return ParseStrict(document.RootElement);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InvalidDataException error) when (error.Message == "manual_settings_invalid")
        {
            throw;
        }
        catch (Exception error) when (
            error is JsonException or IOException or UnauthorizedAccessException or
                ArgumentException or NotSupportedException or DecoderFallbackException)
        {
            throw InvalidSettings(error);
        }
    }

    internal async Task SaveAsync(int retentionHours, CancellationToken cancellationToken)
    {
        ValidateRetention(retentionHours);
        var directory = System.IO.Path.GetDirectoryName(_path)
            ?? throw InvalidSettings();
        EnsureSafeDirectory(directory);
        EnsureSafeTarget();

        var temporaryPath = System.IO.Path.Combine(
            directory,
            $".{System.IO.Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");
        var published = false;
        try
        {
            await using (var stream = CreateProtectedTemporaryFile(temporaryPath))
            {
                await using var writer = new Utf8JsonWriter(stream, WriterOptions);
                writer.WriteStartObject();
                writer.WriteNumber("schemaVersion", ManualSettings.CurrentSchemaVersion);
                writer.WriteNumber("retentionHours", retentionHours);
                writer.WriteEndObject();
                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            EnsureSafeDirectory(directory);
            EnsureSafeTarget();
            File.Move(temporaryPath, _path, overwrite: true);
            published = true;
            Volatile.Write(ref _currentRetentionHours, retentionHours);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (InvalidDataException error) when (error.Message == "manual_settings_invalid")
        {
            throw;
        }
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw InvalidSettings(error);
        }
        finally
        {
            if (!published && NoFollowFile.InspectPathEntry(temporaryPath) == NoFollowPathEntryKind.RegularFile)
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private ManualSettings ParseStrict(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw InvalidSettings();
        }

        int? schemaVersion = null;
        int? retentionHours = null;
        foreach (var property in root.EnumerateObject())
        {
            switch (property.Name)
            {
                case "schemaVersion" when schemaVersion is null && property.Value.TryGetInt32(out var schema):
                    schemaVersion = schema;
                    break;
                case "retentionHours" when retentionHours is null && property.Value.TryGetInt32(out var retention):
                    retentionHours = retention;
                    break;
                default:
                    throw InvalidSettings();
            }
        }

        if (schemaVersion != ManualSettings.CurrentSchemaVersion || retentionHours is null)
        {
            throw InvalidSettings();
        }

        ValidateRetention(retentionHours.Value);
        return SetCurrent(retentionHours.Value);
    }

    private ManualSettings SetCurrent(int retentionHours)
    {
        Volatile.Write(ref _currentRetentionHours, retentionHours);
        return new ManualSettings(ManualSettings.CurrentSchemaVersion, retentionHours);
    }

    private void EnsureSafeTarget()
    {
        if (NoFollowFile.InspectPathEntry(_path) is not (
                NoFollowPathEntryKind.Missing or NoFollowPathEntryKind.RegularFile))
        {
            throw InvalidSettings();
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
            throw InvalidSettings();
        }
    }

    private static FileStream CreateProtectedTemporaryFile(string path) =>
        OperatingSystem.IsWindows()
            ? UiPreferenceStore.WindowsCurrentUserFile.CreateNew(path)
            : new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough);

    private static void ValidateRetention(int retentionHours)
    {
        if (retentionHours is < 0 or > 168)
        {
            throw InvalidSettings();
        }
    }

    private static InvalidDataException InvalidSettings(Exception? inner = null) =>
        new("manual_settings_invalid", inner);
}
