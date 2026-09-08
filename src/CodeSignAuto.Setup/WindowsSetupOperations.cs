using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace CodeSignAuto.Setup;

internal sealed class EmbeddedSetupPayloadSource : ISetupPayloadSource
{
    private const string MetadataResourceName = "CodeSignAuto.Setup.Metadata.json";
    private const string PayloadResourceName = "CodeSignAuto.Setup.Payload.zip";
    private const int MaximumMetadataBytes = 16 * 1024;
    private readonly Assembly _assembly = Assembly.GetExecutingAssembly();

    public string ExecutablePath => Environment.ProcessPath is { Length: > 0 } path && Path.IsPathFullyQualified(path)
        ? path
        : throw new SetupBootstrapperException("setup_signature_invalid");

    public byte[] ReadMetadata()
    {
        using var stream = OpenResource(MetadataResourceName);
        if (stream.Length <= 0 || stream.Length > MaximumMetadataBytes)
        {
            throw new SetupBootstrapperException("setup_payload_invalid");
        }

        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    public Stream OpenPayload() => OpenResource(PayloadResourceName);

    private Stream OpenResource(string name) =>
        _assembly.GetManifestResourceStream(name)
        ?? throw new SetupBootstrapperException("setup_payload_invalid");
}

internal sealed class WindowsSetupPublisherVerifier(string powerShellPath) : ISetupPublisherVerifier
{
    private static readonly TimeSpan VerificationTimeout = TimeSpan.FromSeconds(30);
    private const string VerificationCommand =
        "$ErrorActionPreference='Stop';" +
        "try{" +
        "$signature=Get-AuthenticodeSignature -LiteralPath $env:SSA_SETUP_EXE -ErrorAction Stop;" +
        "if($signature.Status-ne[System.Management.Automation.SignatureStatus]::Valid-or" +
        "$null-eq$signature.SignerCertificate-or$null-eq$signature.TimeStamperCertificate){exit 1};" +
        "$sha=[Security.Cryptography.SHA256]::Create();" +
        "try{$actual=([BitConverter]::ToString($sha.ComputeHash($signature.SignerCertificate.RawData))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()};" +
        "if($actual-cne$env:SSA_SETUP_PUBLISHER){exit 1};exit 0}catch{exit 1}";

    public async Task VerifyAsync(
        string executablePath,
        string expectedPublisherCertificateSha256,
        CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() ||
            !Path.IsPathFullyQualified(executablePath) ||
            !File.Exists(executablePath))
        {
            throw new SetupBootstrapperException("setup_signature_invalid");
        }

        try
        {
            var exitCode = await SetupProcessExecution.RunAsync(
                    powerShellPath,
                    ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "RemoteSigned", "-Command", VerificationCommand],
                    new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["SSA_SETUP_EXE"] = executablePath,
                        ["SSA_SETUP_PUBLISHER"] = expectedPublisherCertificateSha256,
                    },
                    VerificationTimeout,
                    progress: null,
                    cancellationToken)
                .ConfigureAwait(false);
            if (exitCode != 0)
            {
                throw new SetupBootstrapperException("setup_signature_invalid");
            }
        }
        catch (SetupBootstrapperException)
        {
            throw;
        }
        catch
        {
            throw new SetupBootstrapperException("setup_signature_invalid");
        }
    }
}

internal sealed class WindowsSetupWorkspace(string parentRoot) : ISetupWorkspace
{
    private const string WorkspaceSddl =
        "O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    private string? _ownedRoot;

    public string Create()
    {
        if (!OperatingSystem.IsWindows() ||
            string.IsNullOrWhiteSpace(parentRoot) ||
            !Path.IsPathFullyQualified(parentRoot) ||
            !Directory.Exists(parentRoot) ||
            _ownedRoot is not null)
        {
            throw new SetupBootstrapperException("setup_workspace_failed");
        }

        var parent = Path.GetFullPath(parentRoot).TrimEnd(Path.DirectorySeparatorChar);
        for (var attempt = 0; attempt < 8; attempt++)
        {
            var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            var candidate = Path.Combine(parent, "CodeSignAutoSetup-" + nonce);
            try
            {
                WindowsProtectedDirectory.Create(candidate, WorkspaceSddl);
                Verify(candidate);
                _ownedRoot = candidate;
                return candidate;
            }
            catch (IOException error) when (error.InnerException is Win32Exception { NativeErrorCode: 183 })
            {
                // A random-name collision can be retried without touching the existing entry.
            }
            catch (SetupBootstrapperException)
            {
                throw;
            }
            catch
            {
                throw new SetupBootstrapperException("setup_workspace_failed");
            }
        }

        throw new SetupBootstrapperException("setup_workspace_failed");
    }

    public Task CleanupAsync(string mediaRoot)
    {
        if (_ownedRoot is null ||
            !string.Equals(Path.GetFullPath(mediaRoot), _ownedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new SetupBootstrapperException("setup_cleanup_failed");
        }

        try
        {
            var attributes = File.GetAttributes(_ownedRoot);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new SetupBootstrapperException("setup_cleanup_failed");
            }

            Directory.Delete(_ownedRoot, recursive: true);
            _ownedRoot = null;
            return Task.CompletedTask;
        }
        catch (SetupBootstrapperException)
        {
            throw;
        }
        catch
        {
            throw new SetupBootstrapperException("setup_cleanup_failed");
        }
    }

    private static void Verify(string path)
    {
        var security = new DirectoryInfo(path).GetAccessControl();
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner ||
            !string.Equals(owner.Value, "S-1-5-32-544", StringComparison.Ordinal))
        {
            throw new SetupBootstrapperException("setup_workspace_failed");
        }

        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        if (rules.Length != 2 || rules.Any(rule =>
                rule.AccessControlType != AccessControlType.Allow ||
                rule.FileSystemRights != FileSystemRights.FullControl ||
                rule.IdentityReference is not SecurityIdentifier identity ||
                identity.Value is not ("S-1-5-18" or "S-1-5-32-544")))
        {
            throw new SetupBootstrapperException("setup_workspace_failed");
        }
    }
}

internal sealed class WindowsSetupProcessRunner(
    string powerShellPath,
    ISetupProcessInvoker invoker,
    string programFilesRoot) : ISetupProcessRunner
{
    private const string VerificationScriptFileName = "install-prerequisites.ps1";

    public async Task<int> RunAsync(
        SetupProductKind productKind,
        string mediaRoot,
        SetupInstallationMode? mode,
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken)
    {
        return productKind switch
        {
            SetupProductKind.Main => await RunMainAsync(
                    mediaRoot,
                    mode ?? throw new SetupBootstrapperException("setup_mode_invalid"),
                    progress,
                    cancellationToken)
                .ConfigureAwait(false),
            SetupProductKind.PdfExtension => await RunPdfExtensionAsync(
                    mediaRoot,
                    mode,
                    progress,
                    cancellationToken)
                .ConfigureAwait(false),
            _ => throw new SetupBootstrapperException("setup_product_invalid"),
        };
    }

    public async Task DisableAutoLogonAsync(
        SetupProductKind productKind,
        string mediaRoot,
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (productKind != SetupProductKind.Main)
        {
            throw new SetupBootstrapperException("setup_product_invalid");
        }

        var root = Path.GetFullPath(mediaRoot);
        var executable = Path.Combine(root, "CodeSignAuto.exe");
        WindowsProtectedFile.Apply(executable);
        var mappedProgress = new SetupStatusProgress(progress);
        progress?.Report(new SetupProgress(55, "ProgressAutoLogonCleanupStarting"));
        var exitCode = await invoker.RunAsync(
                executable,
                ["setup-disable-autologon"],
                mappedProgress,
                cancellationToken)
            .ConfigureAwait(false);
        if (exitCode != 0)
        {
            throw new SetupBootstrapperException(
                mappedProgress.FailureCode ?? "autologon_cleanup_failed");
        }

        progress?.Report(new SetupProgress(90, "ProgressAutoLogonCleanupComplete"));
    }

    private async Task<int> RunMainAsync(
        string mediaRoot,
        SetupInstallationMode mode,
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken)
    {
        var root = Path.GetFullPath(mediaRoot);
        var script = Path.Combine(root, VerificationScriptFileName);
        var common = new[]
        {
            "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", script, "-ReleaseMediaRoot", root,
            "-InstallMode", mode == SetupInstallationMode.Manual ? "manual" : "service",
        };
        var mappedProgress = new SetupStatusProgress(progress);
        var verifyExitCode = await invoker.RunAsync(
                powerShellPath,
                [.. common, "-VerifyMediaOnly"],
                mappedProgress,
                cancellationToken)
            .ConfigureAwait(false);
        if (verifyExitCode != 0)
        {
            throw new SetupBootstrapperException("setup_media_invalid");
        }

        var installExitCode = await invoker
            .RunAsync(powerShellPath, common, mappedProgress, cancellationToken)
            .ConfigureAwait(false);
        if (installExitCode != 0 && mappedProgress.FailureCode is { } failureCode)
        {
            throw new SetupBootstrapperException(failureCode);
        }

        return installExitCode;
    }

    private Task<int> RunPdfExtensionAsync(
        string mediaRoot,
        SetupInstallationMode? mode,
        IProgress<SetupProgress>? progress,
        CancellationToken cancellationToken)
    {
        if (mode is not null)
        {
            throw new SetupBootstrapperException("setup_mode_invalid");
        }

        var root = Path.GetFullPath(mediaRoot);
        WindowsProtectedFile.Apply(Path.Combine(root, "extension.json"));
        WindowsProtectedFile.Apply(Path.Combine(root, "CodeSignAutoPdfSigner.exe"));
        WindowsProtectedFile.Apply(Path.Combine(root, "LICENSE.txt"));
        WindowsProtectedFile.Apply(Path.Combine(root, "THIRD-PARTY-NOTICES.txt"));
        var mainExecutable = Path.Combine(
            Path.GetFullPath(programFilesRoot),
            "CodeSignAuto",
            "CodeSignAuto.exe");
        return invoker.RunAsync(
            mainExecutable,
            ["pdf-extension", "install", "--media-root", root],
            new SetupStatusProgress(progress),
            cancellationToken);
    }

    private sealed class SetupStatusProgress(IProgress<SetupProgress>? progress) : IProgress<string>
    {
        private int _lastPercent = 25;

        public string? FailureCode { get; private set; }

        public void Report(string line)
        {
            FailureCode ??= ReadFailureCode(line);
            var percent = line switch
            {
                "phase=media code=ready" => 35,
                "phase=manifest code=ready" => 40,
                "phase=preflight code=ready" => 45,
                "phase=detection code=ready" or
                    "phase=detection code=install_required" => 50,
                "phase=probe code=ready" => 90,
                "phase=complete code=ready" => 92,
                "phase=pdf_extension_media code=ready" => 55,
                "pdf_extension_installed" => 92,
                _ => 0,
            };
            if (percent <= _lastPercent)
            {
                return;
            }

            _lastPercent = percent;
            progress?.Report(new SetupProgress(percent, Describe(percent)));
        }

        private static string? ReadFailureCode(string line)
        {
            if (IsStableCode(line) && line is
                "administrator_required" or
                "autologon_cleanup_owned_state" or
                "autologon_cleanup_state_uncertain" or
                "autologon_cleanup_busy" or
                "autologon_cleanup_failed")
            {
                return line;
            }

            const string phasePrefix = "phase=";
            const string separator = " code=";
            if (!line.StartsWith(phasePrefix, StringComparison.Ordinal))
            {
                return null;
            }

            var separatorIndex = line.IndexOf(separator, phasePrefix.Length, StringComparison.Ordinal);
            if (separatorIndex <= phasePrefix.Length ||
                separatorIndex + separator.Length >= line.Length)
            {
                return null;
            }

            var phase = line[phasePrefix.Length..separatorIndex];
            var code = line[(separatorIndex + separator.Length)..];
            if (!IsStableCode(phase) || !IsStableCode(code) || code is "ready" or "install_required")
            {
                return null;
            }

            return code;
        }

        private static bool IsStableCode(string value) =>
            value.Length is >= 1 and <= 64 &&
            value[0] is >= 'a' and <= 'z' &&
            value.Skip(1).All(character =>
                character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_');

        private static string Describe(int percent) => percent switch
        {
            35 => "ProgressPublisherMediaVerified",
            40 => "ProgressRuntimeManifestVerified",
            45 => "ProgressSystemPrerequisitesComplete",
            50 => "ProgressRuntimeStatusChecked",
            55 => "ProgressPdfMediaVerified",
            90 => "ProgressLaunchConditionsVerified",
            92 => "ProgressProductInitializationComplete",
            _ => throw new SetupBootstrapperException("setup_progress_invalid"),
        };
    }
}

internal static class WindowsProtectedFile
{
    private static readonly SecurityIdentifier LocalSystem =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Administrators =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    internal static void Apply(string path)
    {
        try
        {
            if (!Path.IsPathFullyQualified(path) || !File.Exists(path) ||
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                throw new SetupBootstrapperException("setup_workspace_failed");
            }

            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(Administrators);
            security.AddAccessRule(Rule(LocalSystem));
            security.AddAccessRule(Rule(Administrators));
            var file = new FileInfo(path);
            file.SetAccessControl(security);
            Verify(file.GetAccessControl());
        }
        catch (SetupBootstrapperException)
        {
            throw;
        }
        catch
        {
            throw new SetupBootstrapperException("setup_workspace_failed");
        }
    }

    private static FileSystemAccessRule Rule(SecurityIdentifier identity) => new(
        identity,
        FileSystemRights.FullControl,
        InheritanceFlags.None,
        PropagationFlags.None,
        AccessControlType.Allow);

    private static void Verify(FileSecurity security)
    {
        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: true,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            LocalSystem.Value,
            Administrators.Value,
        };
        if (owner is null || owner != Administrators || !security.AreAccessRulesProtected ||
            rules.Length != 2 || rules.Any(rule =>
                rule.AccessControlType != AccessControlType.Allow ||
                rule.FileSystemRights != FileSystemRights.FullControl ||
                rule.InheritanceFlags != InheritanceFlags.None ||
                rule.PropagationFlags != PropagationFlags.None ||
                !expected.Remove(rule.IdentityReference.Value)) ||
            expected.Count != 0)
        {
            throw new SetupBootstrapperException("setup_workspace_failed");
        }
    }
}

internal sealed class PowerShellSetupProcessInvoker : ISetupProcessInvoker
{
    private static readonly TimeSpan InstallTimeout = TimeSpan.FromMinutes(30);

    public Task<int> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        IProgress<string>? progress,
        CancellationToken cancellationToken) => SetupProcessExecution.RunAsync(
        executable,
        arguments,
        environment: null,
        InstallTimeout,
        progress,
        cancellationToken,
        surfaceStableStandardError: true);
}

internal static class SetupPowerShell
{
    public static string ResolveSystemPath()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new SetupBootstrapperException("setup_powershell_missing");
        }

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var sysnative = Path.Combine(windows, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe");
        var system32 = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (File.Exists(sysnative))
        {
            return sysnative;
        }

        return File.Exists(system32)
            ? system32
            : throw new SetupBootstrapperException("setup_powershell_missing");
    }
}

internal static class SetupProcessExecution
{
    public static async Task<int> RunAsync(
        string executable,
        IReadOnlyList<string> arguments,
        IReadOnlyDictionary<string, string>? environment,
        TimeSpan timeout,
        IProgress<string>? progress,
        CancellationToken cancellationToken,
        bool surfaceStableStandardError = false)
    {
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        if (environment is not null)
        {
            foreach (var pair in environment)
            {
                start.Environment[pair.Key] = pair.Value;
            }
        }

        using var process = Process.Start(start)
            ?? throw new SetupBootstrapperException("setup_process_failed");
        var stdout = ReadOutputAsync(process.StandardOutput, progress);
        var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false);
            await stdout.ConfigureAwait(false);
            var standardError = await stderr.ConfigureAwait(false);
            if (surfaceStableStandardError &&
                process.ExitCode != 0 &&
                TryReadStableError(standardError) is { } stableError)
            {
                throw new SetupBootstrapperException(stableError);
            }
            return process.ExitCode;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            await DrainAsync(stdout, stderr).ConfigureAwait(false);
            throw new SetupBootstrapperException("setup_process_timeout");
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            await DrainAsync(stdout, stderr).ConfigureAwait(false);
            throw;
        }
        catch (SetupBootstrapperException)
        {
            TryKill(process);
            await DrainAsync(stdout, stderr).ConfigureAwait(false);
            throw;
        }
        catch
        {
            TryKill(process);
            await DrainAsync(stdout, stderr).ConfigureAwait(false);
            throw new SetupBootstrapperException("setup_process_failed");
        }
    }

    private static async Task ReadOutputAsync(
        StreamReader reader,
        IProgress<string>? progress)
    {
        while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
        {
            if (line.Length != 0)
            {
                progress?.Report(line);
            }
        }
    }

    private static async Task DrainAsync(Task stdout, Task<string> stderr)
    {
        try
        {
            await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
        }
        catch
        {
            // Preserve the stable process or cancellation result.
        }
    }

    private static string? TryReadStableError(string standardError)
    {
        var trimmed = standardError.TrimEnd('\r', '\n');
        if (trimmed.Length == 0 ||
            trimmed.Length > 129 ||
            trimmed.Contains('\r', StringComparison.Ordinal) ||
            trimmed.Contains('\n', StringComparison.Ordinal))
        {
            return null;
        }

        var codes = trimmed.Split(' ', StringSplitOptions.None);
        return codes.Length is 1 or 2 && codes.All(IsStableCode)
            ? trimmed
            : null;
    }

    private static bool IsStableCode(string value) =>
        value.Length is >= 1 and <= 64 &&
        value[0] is >= 'a' and <= 'z' &&
        value.Skip(1).All(character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_');

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit();
            }
        }
        catch
        {
            // The stable process failure takes precedence over best-effort cleanup.
        }
    }
}

internal static class WindowsProtectedDirectory
{
    private const uint SecurityDescriptorRevision = 1;

    public static void Create(string path, string sddl)
    {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                SecurityDescriptorRevision,
                out var descriptor,
                out _))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptor,
                InheritHandle = false,
            };
            if (!CreateDirectoryW(path, ref attributes))
            {
                throw new IOException(
                    "Atomic protected directory creation failed.",
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
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

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor,
        uint stringSdRevision,
        out nint securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, ref SecurityAttributes securityAttributes);

    [DllImport("kernel32.dll")]
    private static extern nint LocalFree(nint memory);
}
