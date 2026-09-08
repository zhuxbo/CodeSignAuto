using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;

namespace CodeSignAuto.Core.Security;

public interface IAuthenticodeFileValidator
{
    bool IsValid(string path, string extension);
}

internal interface IAuthenticodeFileValidationApi
{
    uint MsiOpenDatabase(string databasePath, IntPtr persistenceMode, out uint databaseHandle);

    uint MsiCloseHandle(uint handle);

    IntPtr CryptCatOpen(
        string catalogPath,
        uint openFlags,
        IntPtr cryptographicProvider,
        uint publicVersion,
        uint encodingType);

    IntPtr CryptCatEnumerateMember(IntPtr catalogHandle, IntPtr previousMember);

    bool CryptCatClose(IntPtr catalogHandle);
}

public sealed partial class AuthenticodeFileValidator : IAuthenticodeFileValidator
{
    private const uint ErrorSuccess = 0;
    private const uint CryptCatOpenExisting = 0x00000004;
    private const uint CryptCatVersion1 = 0x00000100;
    private static readonly IntPtr InvalidHandleValue = new(-1);
    private readonly IAuthenticodeFileValidationApi _nativeApi;
    private readonly bool _enforceWindowsPlatform;

    public AuthenticodeFileValidator()
        : this(new WindowsAuthenticodeFileValidationApi(), enforceWindowsPlatform: true)
    {
    }

    internal AuthenticodeFileValidator(IAuthenticodeFileValidationApi nativeApi)
        : this(nativeApi, enforceWindowsPlatform: false)
    {
    }

    private AuthenticodeFileValidator(
        IAuthenticodeFileValidationApi nativeApi,
        bool enforceWindowsPlatform)
    {
        _nativeApi = nativeApi ?? throw new ArgumentNullException(nameof(nativeApi));
        _enforceWindowsPlatform = enforceWindowsPlatform;
    }

    public bool IsValid(string path, string extension)
    {
        try
        {
            return extension.ToLowerInvariant() switch
            {
                ".exe" or ".dll" or ".sys" => IsPortableExecutable(path),
                ".msi" => IsWindowsInstallerDatabase(path),
                ".cat" => IsWindowsCatalog(path),
                _ => false,
            };
        }
        catch (Exception error) when (
            error is IOException
                or UnauthorizedAccessException
                or BadImageFormatException
                or InvalidDataException
                or ArgumentException
                or DllNotFoundException
                or EntryPointNotFoundException
                or MarshalDirectiveException)
        {
            return false;
        }
    }

    private static bool IsPortableExecutable(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);
        var headers = reader.PEHeaders;
        return headers.PEHeader is not null &&
            headers.CoffHeader.NumberOfSections > 0 &&
            headers.PEHeader.Magic is PEMagic.PE32 or PEMagic.PE32Plus;
    }

    private bool IsWindowsInstallerDatabase(string path)
    {
        if (_enforceWindowsPlatform && !OperatingSystem.IsWindows())
        {
            return false;
        }

        uint databaseHandle = 0;
        try
        {
            // MSIDBOPEN_READONLY is the predefined null persistence mode.
            return _nativeApi.MsiOpenDatabase(path, IntPtr.Zero, out databaseHandle) == ErrorSuccess &&
                databaseHandle != 0;
        }
        finally
        {
            if (databaseHandle != 0)
            {
                _ = _nativeApi.MsiCloseHandle(databaseHandle);
            }
        }
    }

    private bool IsWindowsCatalog(string path)
    {
        if (_enforceWindowsPlatform && !OperatingSystem.IsWindows())
        {
            return false;
        }

        var catalogHandle = _nativeApi.CryptCatOpen(
            path,
            CryptCatOpenExisting,
            IntPtr.Zero,
            CryptCatVersion1,
            encodingType: 0);
        if (catalogHandle == IntPtr.Zero || catalogHandle == InvalidHandleValue)
        {
            return false;
        }

        try
        {
            return _nativeApi.CryptCatEnumerateMember(catalogHandle, IntPtr.Zero) != IntPtr.Zero;
        }
        finally
        {
            _ = _nativeApi.CryptCatClose(catalogHandle);
        }
    }

    private sealed partial class WindowsAuthenticodeFileValidationApi : IAuthenticodeFileValidationApi
    {
        public uint MsiOpenDatabase(
            string databasePath,
            IntPtr persistenceMode,
            out uint databaseHandle) =>
            NativeMethods.MsiOpenDatabase(databasePath, persistenceMode, out databaseHandle);

        public uint MsiCloseHandle(uint handle) => NativeMethods.MsiCloseHandle(handle);

        public IntPtr CryptCatOpen(
            string catalogPath,
            uint openFlags,
            IntPtr cryptographicProvider,
            uint publicVersion,
            uint encodingType) =>
            NativeMethods.CryptCATOpen(
                catalogPath,
                openFlags,
                cryptographicProvider,
                publicVersion,
                encodingType);

        public IntPtr CryptCatEnumerateMember(IntPtr catalogHandle, IntPtr previousMember) =>
            NativeMethods.CryptCATEnumerateMember(catalogHandle, previousMember);

        public bool CryptCatClose(IntPtr catalogHandle) => NativeMethods.CryptCATClose(catalogHandle);

        private static partial class NativeMethods
        {
            [LibraryImport("msi.dll", EntryPoint = "MsiOpenDatabaseW", StringMarshalling = StringMarshalling.Utf16)]
            internal static partial uint MsiOpenDatabase(
                string databasePath,
                IntPtr persistenceMode,
                out uint databaseHandle);

            [LibraryImport("msi.dll", EntryPoint = "MsiCloseHandle")]
            internal static partial uint MsiCloseHandle(uint handle);

            [LibraryImport("wintrust.dll", EntryPoint = "CryptCATOpen", StringMarshalling = StringMarshalling.Utf16)]
            internal static partial IntPtr CryptCATOpen(
                string catalogPath,
                uint openFlags,
                IntPtr cryptographicProvider,
                uint publicVersion,
                uint encodingType);

            [LibraryImport("wintrust.dll", EntryPoint = "CryptCATEnumerateMember")]
            internal static partial IntPtr CryptCATEnumerateMember(
                IntPtr catalogHandle,
                IntPtr previousMember);

            [LibraryImport("wintrust.dll", EntryPoint = "CryptCATClose")]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static partial bool CryptCATClose(IntPtr catalogHandle);
        }
    }
}
