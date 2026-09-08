using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace CodeSignAuto.App;

internal static class WindowsStandardIo
{
    private const uint AttachParentProcess = uint.MaxValue;
    private const int StandardOutputHandle = -11;
    private const int StandardErrorHandle = -12;
    private const uint UnknownFileType = 0;
    private const uint DiskFileType = 1;
    private const uint CharacterFileType = 2;
    private const uint PipeFileType = 3;
    private static readonly nint InvalidHandle = new(-1);

    internal static bool Prepare(bool attachParentConsole)
    {
        if (!attachParentConsole)
        {
            return false;
        }

        if (!OperatingSystem.IsWindows())
        {
            return true;
        }

        if (HasUsableOutput())
        {
            return TryRebindStandardStreams();
        }

        if (!AttachConsole(AttachParentProcess))
        {
            return false;
        }

        return TryRebindStandardStreams();
    }

    [SupportedOSPlatform("windows")]
    private static bool TryRebindStandardStreams()
    {
        try
        {
            var outputEncoding = Console.OutputEncoding;
            var inputEncoding = Console.InputEncoding;
            var output = new StreamWriter(
                Console.OpenStandardOutput(),
                outputEncoding,
                bufferSize: 1024,
                leaveOpen: true)
            {
                AutoFlush = true,
            };
            var error = new StreamWriter(
                Console.OpenStandardError(),
                outputEncoding,
                bufferSize: 1024,
                leaveOpen: true)
            {
                AutoFlush = true,
            };
            var input = new StreamReader(
                Console.OpenStandardInput(),
                inputEncoding,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 1024,
                leaveOpen: true);
            Console.SetIn(input);
            Console.SetOut(TextWriter.Synchronized(output));
            Console.SetError(TextWriter.Synchronized(error));
        }
        catch (IOException)
        {
            return false;
        }

        return HasUsableOutput();
    }

    [SupportedOSPlatform("windows")]
    private static bool HasUsableOutput() =>
        IsUsable(GetStdHandle(StandardOutputHandle)) ||
        IsUsable(GetStdHandle(StandardErrorHandle));

    [SupportedOSPlatform("windows")]
    private static bool IsUsable(nint handle)
    {
        if (handle == 0 || handle == InvalidHandle)
        {
            return false;
        }

        var fileType = GetFileType(handle);
        var consoleModeAvailable = fileType == CharacterFileType &&
            GetConsoleMode(handle, out _);
        return IsUsableOutput(fileType, consoleModeAvailable);
    }

    internal static bool IsUsableOutput(uint fileType, bool consoleModeAvailable) =>
        fileType is DiskFileType or PipeFileType ||
        fileType == CharacterFileType && consoleModeAvailable;

    [DllImport("kernel32.dll", SetLastError = true)]
    [SupportedOSPlatform("windows")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachConsole(uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [SupportedOSPlatform("windows")]
    private static extern nint GetStdHandle(int standardHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [SupportedOSPlatform("windows")]
    private static extern uint GetFileType(nint handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [SupportedOSPlatform("windows")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(nint consoleHandle, out uint mode);
}
