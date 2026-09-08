#if CODESIGNAUTO_WPF
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Windows.Automation;
using CodeSignAuto.App.UI.Testing;

namespace CodeSignAuto.UI.Tests.Desktop;

internal readonly record struct DesktopBounds(double Left, double Top, double Width, double Height)
{
    public UiClientSize Size => new(Width, Height);
}

internal sealed record DesktopWindowGeometry(
    int Dpi,
    DesktopBounds PhysicalOuter,
    DesktopBounds LogicalOuter,
    DesktopBounds PhysicalClient,
    DesktopBounds LogicalClient);

internal sealed class DesktopTestApp : IAsyncDisposable
{
    private const uint PrintWindowRenderFullContent = 0x00000002;
    private const string ScreenshotCaptureMethod = "PrintWindow.PW_RENDERFULLCONTENT.24bppRgb";
    private static readonly Regex JobFileNamePattern = new(
        "^(?:active|failed|expired)\\.exe$|^(?:software|document)-[0-9]{3}\\.(?:exe|pdf)$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private readonly string _nonce;
    private readonly string _pipeName;
    private readonly string _runId;
    private readonly Task<string[]> _stdout;
    private readonly Task<string[]> _stderr;
    private int _disposed;

    private DesktopTestApp(
        Process process,
        FakeManagementHost host,
        AutomationElement mainWindow,
        string artifactDirectory,
        string nonce,
        string pipeName,
        string runId,
        string trayIdentity,
        Task<string[]> stdout,
        Task<string[]> stderr)
    {
        Process = process;
        Host = host;
        MainWindow = mainWindow;
        ArtifactDirectory = artifactDirectory;
        _nonce = nonce;
        _pipeName = pipeName;
        _runId = runId;
        TrayIdentity = trayIdentity;
        _stdout = stdout;
        _stderr = stderr;
    }

    public Process Process { get; }

    public FakeManagementHost Host { get; }

    public AutomationElement MainWindow { get; }

    public string ArtifactDirectory { get; }

    public string TrayIdentity { get; }

    public static async Task<DesktopTestApp> StartAsync(
        string stateCode,
        string cultureName = "zh-CN")
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("desktop_uia_windows_required");
        }

        Assert.True(UiTestState.TryParse(stateCode, out var state));
        var appHost = LocateAppHost();
        var artifactDirectory = CreateArtifactDirectory();
        var runId = ResolveRunId();
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var pipeName = $"SSA.UI.{Guid.NewGuid():N}";
        var expected = new UiTestLaunchOptions(state!, pipeName, nonce, 1);
        var host = new FakeManagementHost(expected, deferProcessBinding: true);
        Process? process = null;
        Task<string[]>? stdout = null;
        Task<string[]>? stderr = null;
        try
        {
            var start = CreateStartInfo(appHost, stateCode, pipeName, nonce, cultureName);
            process = Process.Start(start) ?? throw new InvalidOperationException("ui_test_process_start_failed");
            host.BindProcessId(process.Id);
            stdout = DrainAsync(process.StandardOutput);
            stderr = DrainAsync(process.StandardError);
            var mainWindow = await WaitForMainWindowAsync(process, TimeSpan.FromSeconds(15));
            await host.Connected.WaitAsync(TimeSpan.FromSeconds(5));
            AssertSingleTopLevelWindow(process, mainWindow);
            return new DesktopTestApp(
                process,
                host,
                mainWindow,
                artifactDirectory,
                nonce,
                pipeName,
                runId,
                UiTestTrayIdentity.Create(process.Id, pipeName),
                stdout,
                stderr);
        }
        catch (Exception startFailure)
        {
            try
            {
                await DesktopTestProcessCleanup.ExecuteAsync(
                    process,
                    host,
                    requestExit: null,
                    stdout,
                    stderr,
                    lines => AssertSafeOutput(lines, nonce, pipeName, artifactDirectory));
            }
            catch (Exception cleanupFailure)
            {
                throw new AggregateException(startFailure, cleanupFailure);
            }

            ExceptionDispatchInfo.Capture(startFailure).Throw();
            throw new InvalidOperationException("ui_test_start_unreachable");
        }
    }

    public IReadOnlyList<string> NavigationNames(string mainNavigationName = "主导航")
    {
        var navigation = WaitForElement(mainNavigationName, ControlType.List, TimeSpan.FromSeconds(5));
        return navigation.FindAll(
                TreeScope.Children,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem))
            .Cast<AutomationElement>()
            .Select(item => item.Current.Name)
            .ToArray();
    }

    public void SelectNavigation(string name)
    {
        var item = WaitForElement(name, ControlType.ListItem, TimeSpan.FromSeconds(5));
        ((SelectionItemPattern)item.GetCurrentPattern(SelectionItemPattern.Pattern)).Select();
    }

    public AutomationElement? FindElement(string name, ControlType controlType) =>
        ProcessWindows().Select(window => window.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.NameProperty, name),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, controlType))))
            .FirstOrDefault(element => element is not null);

    public AutomationElement WaitForElement(string name, ControlType controlType, TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        do
        {
            if (FindElement(name, controlType) is { } element)
            {
                return element;
            }

            Thread.Sleep(50);
        }
        while (deadline.Elapsed < timeout && !Process.HasExited);

        throw new Xunit.Sdk.XunitException($"ui_element_timeout:{name}");
    }

    public void Invoke(string name)
    {
        var button = WaitForElement(name, ControlType.Button, TimeSpan.FromSeconds(5));
        ((InvokePattern)button.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    }

    public void WaitForElementEnabled(string name, bool enabled, TimeSpan timeout) =>
        WaitUntil(
            () => FindElement(name, ControlType.Button)?.Current.IsEnabled == enabled,
            timeout,
            $"ui_element_enabled_timeout:{name}:{enabled}");

    public IReadOnlyList<string> WaitForJobFileNames(int expectedCount, TimeSpan timeout)
    {
        IReadOnlyList<string> names = [];
        WaitUntil(
            () =>
            {
                names = MainWindow.FindAll(
                        TreeScope.Descendants,
                        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text))
                    .Cast<AutomationElement>()
                    .Select(element => element.Current.Name)
                    .Where(name => JobFileNamePattern.IsMatch(name))
                    .ToArray();
                return names.Count == expectedCount;
            },
            timeout,
            $"ui_job_count_timeout:{expectedCount}");
        return names;
    }

    public bool RowButtonIsEnabled(string rowName, string buttonName)
    {
        var row = WaitForElement(rowName, ControlType.Text, TimeSpan.FromSeconds(5));
        var rowBounds = row.Current.BoundingRectangle;
        var candidates = MainWindow.FindAll(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.NameProperty, buttonName),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button)))
            .Cast<AutomationElement>()
            .Select(button => new
            {
                Button = button,
                Distance = Math.Abs(
                    (button.Current.BoundingRectangle.Top + (button.Current.BoundingRectangle.Height / 2)) -
                    (rowBounds.Top + (rowBounds.Height / 2))),
            })
            .OrderBy(candidate => candidate.Distance)
            .FirstOrDefault()
            ?? throw new Xunit.Sdk.XunitException($"ui_row_button_missing:{rowName}");
        Assert.InRange(candidates.Distance, 0, Math.Max(2, rowBounds.Height));
        return candidates.Button.Current.IsEnabled;
    }

    public void InvokeTrayExit()
    {
        var trayIcon = WaitForTrayIcon(TimeSpan.FromSeconds(8));
        var bounds = trayIcon.Current.BoundingRectangle;
        if (bounds.IsEmpty || bounds.Width <= 0 || bounds.Height <= 0)
        {
            throw new Xunit.Sdk.XunitException("ui_tray_icon_bounds_invalid");
        }

        var x = checked((int)Math.Round(bounds.Left + (bounds.Width / 2)));
        var y = checked((int)Math.Round(bounds.Top + (bounds.Height / 2)));
        Assert.True(SetCursorPos(x, y));
        mouse_event(MouseEventRightDown, 0, 0, 0, UIntPtr.Zero);
        mouse_event(MouseEventRightUp, 0, 0, 0, UIntPtr.Zero);
        var menu = WaitForTrayMenuItem("退出程序", TimeSpan.FromSeconds(5));
        ((InvokePattern)menu.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    }

    public void DismissNotice(string message)
    {
        _ = WaitForElement(message, ControlType.Text, TimeSpan.FromSeconds(5));
        var dialog = ProcessWindows().FirstOrDefault(window => window.FindFirst(
            TreeScope.Descendants,
            new AndCondition(
                new PropertyCondition(AutomationElement.NameProperty, message),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text))) is not null)
            ?? throw new Xunit.Sdk.XunitException("ui_notice_dialog_missing");
        var button = dialog.FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button))
            .Cast<AutomationElement>()
            .FirstOrDefault(candidate => candidate.Current.IsEnabled)
            ?? throw new Xunit.Sdk.XunitException("ui_notice_button_missing");
        ((InvokePattern)button.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
        WaitUntil(() => IsUnavailableOrOffscreen(dialog), TimeSpan.FromSeconds(5), "ui_notice_close_timeout");
    }

    public void WaitForProcessExit(TimeSpan timeout)
    {
        if (!Process.WaitForExit(checked((int)timeout.TotalMilliseconds)))
        {
            throw new Xunit.Sdk.XunitException("ui_process_exit_timeout");
        }
    }

    public void SetValue(string name, string value)
    {
        var edit = WaitForElement(name, ControlType.Edit, TimeSpan.FromSeconds(5));
        ((ValuePattern)edit.GetCurrentPattern(ValuePattern.Pattern)).SetValue(value);
    }

    public void FocusNavigation()
    {
        WaitForElement("主导航", ControlType.List, TimeSpan.FromSeconds(5)).SetFocus();
    }

    public void FocusAndSend(string name, string keys)
    {
        WaitForElement(name, ControlType.Button, TimeSpan.FromSeconds(5)).SetFocus();
        SendKeys(keys);
    }

    public void SendEscape() => SendKeys("{ESC}");

    public void SendKeys(string keys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keys);
        System.Windows.Forms.SendKeys.SendWait(keys);
    }

    public void CloseWindow()
    {
        ((WindowPattern)MainWindow.GetCurrentPattern(WindowPattern.Pattern)).Close();
        WaitUntil(() => MainWindow.Current.IsOffscreen, TimeSpan.FromSeconds(5), "ui_window_hide_timeout");
    }

    public void CloseVisibleWindow(string title)
    {
        var window = ProcessWindows().FirstOrDefault(candidate =>
            string.Equals(candidate.Current.Name, title, StringComparison.Ordinal))
            ?? throw new Xunit.Sdk.XunitException($"ui_window_missing:{title}");
        ((WindowPattern)window.GetCurrentPattern(WindowPattern.Pattern)).Close();
    }

    public void WaitForElementToDisappear(string name, ControlType controlType, TimeSpan timeout) =>
        WaitUntil(() => FindElement(name, controlType) is null, timeout, $"ui_element_still_visible:{name}");

    public void ChooseFile(string path)
    {
        Assert.True(Path.IsPathFullyQualified(path));
        Invoke("选择本机签名文件");
        _ = CompleteFileDialog(path);
    }

    public string SaveThroughDialog(string buttonName, string destinationPath)
    {
        Assert.True(Path.IsPathFullyQualified(destinationPath));
        var button = ProcessWindows()
            .SelectMany(window => window.FindAll(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.NameProperty, buttonName),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button)))
                .Cast<AutomationElement>())
            .First(candidate => candidate.Current.IsEnabled);
        ((InvokePattern)button.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
        return CompleteFileDialog(destinationPath);
    }

    private string CompleteFileDialog(string path)
    {
        var dialog = WaitForTopLevelWindow(exclude: MainWindow, TimeSpan.FromSeconds(5));
        var edits = dialog.FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit))
            .Cast<AutomationElement>()
            .Where(element => element.TryGetCurrentPattern(ValuePattern.Pattern, out _))
            .ToArray();
        var edit = edits.FirstOrDefault(element => element.Current.AutomationId == "1148")
            ?? edits.LastOrDefault()
            ?? throw new Xunit.Sdk.XunitException("file_dialog_edit_missing");
        var valuePattern = (ValuePattern)edit.GetCurrentPattern(ValuePattern.Pattern);
        var defaultValue = valuePattern.Current.Value;
        valuePattern.SetValue(path);
        var open = dialog.FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button))
            .Cast<AutomationElement>()
            .FirstOrDefault(element =>
                element.Current.Name.StartsWith("打开", StringComparison.Ordinal) ||
                element.Current.Name.StartsWith("保存", StringComparison.Ordinal) ||
                element.Current.Name.StartsWith("Open", StringComparison.OrdinalIgnoreCase) ||
                element.Current.Name.StartsWith("Save", StringComparison.OrdinalIgnoreCase) ||
                element.Current.Name.StartsWith("选择", StringComparison.Ordinal))
            ?? throw new Xunit.Sdk.XunitException("file_dialog_open_missing");
        ((InvokePattern)open.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
        WaitUntil(() => IsUnavailableOrOffscreen(dialog), TimeSpan.FromSeconds(5), "file_dialog_close_timeout");
        return defaultValue;
    }

    public string CreateSyntheticExecutable(int length = 4096)
    {
        length = Math.Max(length, 2);
        var path = Path.Combine(ArtifactDirectory, $"input-{Guid.NewGuid():N}.exe");
        var bytes = new byte[length];
        bytes[0] = 0x4D;
        bytes[1] = 0x5A;
        File.WriteAllBytes(path, bytes);
        return path;
    }

    public string CreateSyntheticPdf()
    {
        var path = Path.Combine(ArtifactDirectory, $"input-{Guid.NewGuid():N}.pdf");
        File.WriteAllText(path, "%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n");
        return path;
    }

    public async Task<string> CaptureWindowPngAsync(string fileName, string testName)
    {
        if (!string.Equals(Path.GetFileName(fileName), fileName, StringComparison.Ordinal) ||
            !fileName.EndsWith(".png", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("artifact_name_invalid", nameof(fileName));
        }
        if (string.IsNullOrWhiteSpace(testName) || testName.Length > 160 ||
            testName.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '_')))
        {
            throw new ArgumentException("artifact_test_name_invalid", nameof(testName));
        }

        AssertSecretInputsEmpty();

        var path = Path.Combine(ArtifactDirectory, fileName);
        var attestationPath = path + ".attestation.json";
        var window = GetBoundMainWindowHandle();
        var geometry = ReadWindowGeometry(window);
        if (File.Exists(path) || File.Exists(attestationPath))
        {
            throw new IOException("screenshot_target_invalid");
        }

        using var bitmap = CaptureTargetWindowBitmap(window, geometry, out var contentValidation);
        var artifactContract = ScreenshotArtifactContract.Validate(
            fileName,
            testName,
            contentValidation.AnchorNames);
        var width = bitmap.Width;
        var height = bitmap.Height;

        bitmap.Save(path, ImageFormat.Png);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var header = new byte[8];
        Assert.Equal(8, await stream.ReadAsync(header));
        Assert.Equal(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }, header);
        stream.Position = 0;
        var pngSha256 = Convert.ToHexString(await SHA256.HashDataAsync(stream));
        var attestation = new
        {
            schemaVersion = 3,
            runId = _runId,
            sessionId = Process.SessionId,
            testName,
            windowPid = Process.Id,
            targetHwnd = $"0x{window.ToInt64():X}",
            title = MainWindow.Current.Name,
            dpi = geometry.Dpi,
            logicalOuter = geometry.LogicalOuter,
            physicalOuter = geometry.PhysicalOuter,
            logicalClient = geometry.LogicalClient,
            physicalClient = geometry.PhysicalClient,
            pngFileName = fileName,
            pngWidth = width,
            pngHeight = height,
            pngSha256,
            captureMethod = ScreenshotCaptureMethod,
            validatedAnchorCount = contentValidation.AnchorCount,
            validatedAnchors = contentValidation.AnchorNames,
            currentPageAnchor = artifactContract.CurrentPageAnchor,
            secretInputsEmpty = true,
            secretVerificationMethod = "UIAutomationValuePattern",
        };
        var attestationBytes = JsonSerializer.SerializeToUtf8Bytes(attestation);
        ScreenshotArtifactJsonContract.ValidateSidecar(Encoding.UTF8.GetString(attestationBytes));
        await using var attestationStream = new FileStream(
            attestationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await attestationStream.WriteAsync(attestationBytes);
        await attestationStream.FlushAsync();
        attestationStream.Flush(flushToDisk: true);
        return path;
    }

    public string CaptureTargetWindowPixelHash()
    {
        var window = GetBoundMainWindowHandle();
        using var bitmap = CaptureTargetWindowBitmap(
            window,
            ReadWindowGeometry(window),
            out _);
        using var encoded = new MemoryStream();
        bitmap.Save(encoded, ImageFormat.Png);
        return Convert.ToHexString(SHA256.HashData(encoded.GetBuffer().AsSpan(0, checked((int)encoded.Length))));
    }

    public DesktopWindowGeometry ReadWindowGeometry()
    {
        var window = GetBoundMainWindowHandle();
        return ReadWindowGeometry(window);
    }

    private static DesktopWindowGeometry ReadWindowGeometry(IntPtr window)
    {
        var dpi = checked((int)GetDpiForWindow(window));
        if (dpi < UiWindowGeometry.BaseDpi ||
            !GetWindowRect(window, out var outer) ||
            !GetClientRect(window, out var client))
        {
            throw new Xunit.Sdk.XunitException("ui_window_geometry_unavailable");
        }

        var clientOrigin = new NativePoint { X = client.Left, Y = client.Top };
        if (!ClientToScreen(window, ref clientOrigin))
        {
            throw new Xunit.Sdk.XunitException("ui_window_geometry_unavailable");
        }

        var physicalOuter = new DesktopBounds(
            outer.Left,
            outer.Top,
            outer.Right - outer.Left,
            outer.Bottom - outer.Top);
        var physicalClient = new DesktopBounds(
            clientOrigin.X,
            clientOrigin.Y,
            client.Right - client.Left,
            client.Bottom - client.Top);
        var scale = dpi / (double)UiWindowGeometry.BaseDpi;
        return new DesktopWindowGeometry(
            dpi,
            physicalOuter,
            ToLogical(physicalOuter, scale),
            physicalClient,
            ToLogical(physicalClient, scale));
    }

    private Bitmap CaptureTargetWindowBitmap(
        IntPtr window,
        DesktopWindowGeometry geometry,
        out ScreenshotContentValidationResult contentValidation)
    {
        var width = checked((int)geometry.PhysicalOuter.Width);
        var height = checked((int)geometry.PhysicalOuter.Height);
        if (width <= 0 || height <= 0)
        {
            throw new Xunit.Sdk.XunitException("screenshot_target_size_invalid");
        }

        var bitmap = new Bitmap(width, height, PixelFormat.Format24bppRgb);
        try
        {
            using (var graphics = Graphics.FromImage(bitmap))
            {
                graphics.Clear(Color.Black);
                IntPtr deviceContext = IntPtr.Zero;
                var captured = false;
                try
                {
                    deviceContext = graphics.GetHdc();
                    captured = PrintWindow(window, deviceContext, PrintWindowRenderFullContent);
                }
                finally
                {
                    if (deviceContext != IntPtr.Zero)
                    {
                        graphics.ReleaseHdc(deviceContext);
                    }
                }

                if (!captured)
                {
                    throw new Xunit.Sdk.XunitException("screenshot_capture_failed");
                }
            }

            AssertTargetWindowUnchanged(window, geometry);
            contentValidation = ValidateScreenshotContent(bitmap, geometry);
            return bitmap;
        }
        catch
        {
            bitmap.Dispose();
            throw;
        }
    }

    private IntPtr GetBoundMainWindowHandle()
    {
        var window = new IntPtr(MainWindow.Current.NativeWindowHandle);
        if (window == IntPtr.Zero || !IsWindow(window) ||
            GetWindowThreadProcessId(window, out var processId) == 0 ||
            processId != checked((uint)Process.Id))
        {
            throw new Xunit.Sdk.XunitException("screenshot_target_window_invalid");
        }

        return window;
    }

    private void AssertTargetWindowUnchanged(IntPtr window, DesktopWindowGeometry expected)
    {
        if (!IsWindow(window) ||
            GetWindowThreadProcessId(window, out var processId) == 0 ||
            processId != checked((uint)Process.Id) ||
            !GetWindowRect(window, out var bounds) ||
            bounds.Left != checked((int)expected.PhysicalOuter.Left) ||
            bounds.Top != checked((int)expected.PhysicalOuter.Top) ||
            bounds.Right - bounds.Left != checked((int)expected.PhysicalOuter.Width) ||
            bounds.Bottom - bounds.Top != checked((int)expected.PhysicalOuter.Height))
        {
            throw new Xunit.Sdk.XunitException("screenshot_target_changed");
        }
    }

    private ScreenshotContentValidationResult ValidateScreenshotContent(
        Bitmap bitmap,
        DesktopWindowGeometry geometry)
    {
        var client = ToBitmapRegion(geometry.PhysicalClient, geometry.PhysicalOuter);
        var navigation = WaitForElement("主导航", ControlType.List, TimeSpan.FromSeconds(5));
        var fixedHeader = WaitForElement("管理控制台", ControlType.Text, TimeSpan.FromSeconds(5));
        var selectedNavigation = navigation.FindAll(
                TreeScope.Children,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem))
            .Cast<AutomationElement>()
            .FirstOrDefault(item =>
                item.TryGetCurrentPattern(SelectionItemPattern.Pattern, out var pattern) &&
                ((SelectionItemPattern)pattern).Current.IsSelected)
            ?? throw new Xunit.Sdk.XunitException("screenshot_current_page_unavailable");
        var pageTitleName = selectedNavigation.Current.Name;
        var navigationBounds = navigation.Current.BoundingRectangle;
        var pageTitle = ProcessWindows()
            .SelectMany(window => window.FindAll(
                    TreeScope.Descendants,
                    new AndCondition(
                        new PropertyCondition(AutomationElement.NameProperty, pageTitleName),
                        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text)))
                .Cast<AutomationElement>())
            .Where(candidate =>
                !candidate.Current.IsOffscreen &&
                candidate.Current.BoundingRectangle.Left >= navigationBounds.Right - 0.5)
            .OrderBy(candidate => candidate.Current.BoundingRectangle.Top)
            .FirstOrDefault()
            ?? throw new Xunit.Sdk.XunitException("screenshot_current_page_title_unavailable");
        ScreenshotAnchor[] anchors =
        [
            new("main_navigation", ToBitmapRegion(navigation.Current.BoundingRectangle, geometry.PhysicalOuter)),
            new("fixed_header", ToBitmapRegion(fixedHeader.Current.BoundingRectangle, geometry.PhysicalOuter)),
            new(
                $"current_page_title:{pageTitleName}",
                ToBitmapRegion(pageTitle.Current.BoundingRectangle, geometry.PhysicalOuter)),
        ];
        return ScreenshotContentPolicy.Validate(
            bitmap.Width,
            bitmap.Height,
            ReadOpaquePixels(bitmap),
            client,
            anchors);
    }

    private static ScreenshotPixel[] ReadOpaquePixels(Bitmap bitmap)
    {
        if (bitmap.PixelFormat != PixelFormat.Format24bppRgb)
        {
            throw new InvalidDataException("screenshot_pixel_format_invalid");
        }

        var data = bitmap.LockBits(
            new Rectangle(0, 0, bitmap.Width, bitmap.Height),
            ImageLockMode.ReadOnly,
            PixelFormat.Format24bppRgb);
        try
        {
            var row = new byte[Math.Abs(data.Stride)];
            var pixels = new ScreenshotPixel[checked(bitmap.Width * bitmap.Height)];
            for (var y = 0; y < bitmap.Height; y++)
            {
                Marshal.Copy(IntPtr.Add(data.Scan0, checked(y * data.Stride)), row, 0, row.Length);
                for (var x = 0; x < bitmap.Width; x++)
                {
                    var offset = x * 3;
                    pixels[(y * bitmap.Width) + x] = new ScreenshotPixel(
                        row[offset + 2],
                        row[offset + 1],
                        row[offset],
                        byte.MaxValue);
                }
            }

            return pixels;
        }
        finally
        {
            bitmap.UnlockBits(data);
        }
    }

    private static ScreenshotRegion ToBitmapRegion(DesktopBounds bounds, DesktopBounds physicalOuter) =>
        ToBitmapRegion(
            new System.Windows.Rect(bounds.Left, bounds.Top, bounds.Width, bounds.Height),
            physicalOuter);

    private static ScreenshotRegion ToBitmapRegion(
        System.Windows.Rect bounds,
        DesktopBounds physicalOuter)
    {
        var left = checked((int)Math.Floor(bounds.Left - physicalOuter.Left));
        var top = checked((int)Math.Floor(bounds.Top - physicalOuter.Top));
        var right = checked((int)Math.Ceiling(bounds.Right - physicalOuter.Left));
        var bottom = checked((int)Math.Ceiling(bounds.Bottom - physicalOuter.Top));
        return new ScreenshotRegion(left, top, checked(right - left), checked(bottom - top));
    }

    public void AssertAutomationTreeDoesNotContain(string sensitive)
    {
        foreach (var element in ProcessWindows().SelectMany(window =>
            window.FindAll(TreeScope.Subtree, Condition.TrueCondition).Cast<AutomationElement>()))
        {
            Assert.DoesNotContain(sensitive, element.Current.Name ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain(sensitive, element.Current.HelpText ?? string.Empty, StringComparison.Ordinal);
            Assert.DoesNotContain(sensitive, element.Current.ItemStatus ?? string.Empty, StringComparison.Ordinal);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        await DesktopTestProcessCleanup.ExecuteAsync(
            Process,
            Host,
            RequestExitSafelyAsync,
            _stdout,
            _stderr,
            lines => AssertSafeOutput(lines, _nonce, _pipeName, ArtifactDirectory));
    }

    private static ProcessStartInfo CreateStartInfo(
        string appHost,
        string state,
        string pipeName,
        string nonce,
        string cultureName)
    {
        var start = new ProcessStartInfo
        {
            FileName = appHost,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        start.ArgumentList.Add("--ui-test-state");
        start.ArgumentList.Add(state);
        var retained = new[]
        {
            "SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "COMSPEC", "DOTNET_ROOT",
        }.Select(key => (Key: key, Value: Environment.GetEnvironmentVariable(key)))
            .Where(item => !string.IsNullOrEmpty(item.Value))
            .ToArray();
        start.Environment.Clear();
        foreach (var item in retained)
        {
            start.Environment[item.Key] = item.Value!;
        }

        start.Environment[UiTestLaunchOptions.ModeEnvironmentVariable] = "1";
        start.Environment[UiTestLaunchOptions.PipeEnvironmentVariable] = pipeName;
        start.Environment[UiTestLaunchOptions.NonceEnvironmentVariable] = nonce;
        start.Environment[UiTestLaunchOptions.CultureEnvironmentVariable] = cultureName;
        return start;
    }

    private static string LocateAppHost()
    {
        var configured = Environment.GetEnvironmentVariable("SIMPLYSIGN_UI_TEST_APPHOST");
        var candidate = string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(AppContext.BaseDirectory, "CodeSignAuto.exe")
            : configured;
        if (!Path.IsPathFullyQualified(candidate) ||
            !string.Equals(Path.GetFullPath(candidate), candidate, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(candidate), "CodeSignAuto.exe", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(candidate))
        {
            throw new InvalidOperationException("ui_test_apphost_invalid");
        }

        return candidate;
    }

    private static string ResolveRunId()
    {
        var configured = Environment.GetEnvironmentVariable("SIMPLYSIGN_UI_TEST_RUN_ID");
        if (string.IsNullOrWhiteSpace(configured))
        {
            return Guid.NewGuid().ToString("N");
        }

        if (configured.Length != 32 || configured.Any(character =>
                !(character is >= '0' and <= '9' or >= 'a' and <= 'f')))
        {
            throw new InvalidOperationException("ui_test_run_id_invalid");
        }

        return configured;
    }

    private static string CreateArtifactDirectory()
    {
        var configured = Environment.GetEnvironmentVariable("SIMPLYSIGN_UI_TEST_ARTIFACTS");
        var root = string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(Path.GetTempPath(), "CodeSignAuto", "ui-acceptance")
            : configured;
        if (!Path.IsPathFullyQualified(root) || !string.Equals(Path.GetFullPath(root), root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("ui_test_artifact_root_invalid");
        }

        Directory.CreateDirectory(root);
        var directory = Path.Combine(root, Guid.NewGuid().ToString("N"));
        if (Directory.Exists(directory))
        {
            throw new IOException("ui_test_artifact_collision");
        }

        Directory.CreateDirectory(directory);
        return directory;
    }

    private static async Task<AutomationElement> WaitForMainWindowAsync(Process process, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            process.Refresh();
            if (process.HasExited)
            {
                throw new InvalidOperationException($"ui_test_process_exit:{process.ExitCode}");
            }

            if (process.MainWindowHandle != IntPtr.Zero)
            {
                var element = AutomationElement.FromHandle(process.MainWindowHandle);
                if (element.Current.ControlType == ControlType.Window)
                {
                    return element;
                }
            }

            await Task.Delay(50);
        }
        while (watch.Elapsed < timeout);

        throw new TimeoutException("ui_test_main_window_timeout");
    }

    private AutomationElement WaitForTrayIcon(TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        var overflowOpened = false;
        do
        {
            var buttons = AutomationElement.RootElement.FindAll(
                    TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button))
                .Cast<AutomationElement>()
                .ToArray();
            var icon = buttons.FirstOrDefault(candidate =>
                string.Equals(candidate.Current.Name, TrayIdentity, StringComparison.Ordinal));
            if (icon is not null)
            {
                return icon;
            }

            if (!overflowOpened)
            {
                var overflow = buttons.FirstOrDefault(candidate =>
                    candidate.Current.Name.Contains("显示隐藏的图标", StringComparison.OrdinalIgnoreCase) ||
                    candidate.Current.Name.Contains("Show hidden icons", StringComparison.OrdinalIgnoreCase) ||
                    candidate.Current.Name.Contains("通知 V 形", StringComparison.OrdinalIgnoreCase) ||
                    candidate.Current.Name.Contains("Notification Chevron", StringComparison.OrdinalIgnoreCase));
                if (overflow?.TryGetCurrentPattern(InvokePattern.Pattern, out var pattern) == true)
                {
                    ((InvokePattern)pattern).Invoke();
                    overflowOpened = true;
                }
            }

            Thread.Sleep(100);
        }
        while (watch.Elapsed < timeout && !Process.HasExited);

        throw new Xunit.Sdk.XunitException("ui_tray_icon_timeout");
    }

    private AutomationElement WaitForTrayMenuItem(string name, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            var candidates = AutomationElement.RootElement.FindAll(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.NameProperty, name),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.MenuItem),
                    new PropertyCondition(AutomationElement.ProcessIdProperty, Process.Id)))
                .Cast<AutomationElement>();
            foreach (var candidate in candidates)
            {
                var popupOwner = FindTopLevelPopupOwner(candidate);
                if (popupOwner is not null &&
                    popupOwner.Current.ProcessId == Process.Id &&
                    popupOwner.Current.NativeWindowHandle != 0)
                {
                    return candidate;
                }
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < timeout);

        throw new Xunit.Sdk.XunitException($"ui_tray_menu_item_timeout:{name}:{Process.Id}");
    }

    private static AutomationElement? FindTopLevelPopupOwner(AutomationElement element)
    {
        var current = element;
        while (true)
        {
            var parent = TreeWalker.RawViewWalker.GetParent(current);
            if (parent is null || Automation.Compare(parent, AutomationElement.RootElement))
            {
                return current;
            }

            current = parent;
        }
    }

    private AutomationElement WaitForTopLevelWindow(AutomationElement exclude, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            var windows = AutomationElement.RootElement.FindAll(
                TreeScope.Children,
                new AndCondition(
                    new PropertyCondition(AutomationElement.ProcessIdProperty, Process.Id),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Window)));
            var found = windows.Cast<AutomationElement>().FirstOrDefault(candidate =>
                candidate.Current.NativeWindowHandle != exclude.Current.NativeWindowHandle &&
                !candidate.Current.IsOffscreen);
            if (found is not null)
            {
                return found;
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < timeout && !Process.HasExited);

        throw new Xunit.Sdk.XunitException("ui_dialog_timeout");
    }

    private static void AssertSingleTopLevelWindow(Process process, AutomationElement expected)
    {
        var windows = AutomationElement.RootElement.FindAll(
            TreeScope.Children,
            new AndCondition(
                new PropertyCondition(AutomationElement.ProcessIdProperty, process.Id),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Window)))
            .Cast<AutomationElement>()
            .Where(window => !window.Current.IsOffscreen)
            .ToArray();
        var only = Assert.Single(windows);
        Assert.Equal(expected.Current.NativeWindowHandle, only.Current.NativeWindowHandle);
    }

    private IEnumerable<AutomationElement> ProcessWindows()
    {
        var windows = AutomationElement.RootElement.FindAll(
            TreeScope.Children,
            new AndCondition(
                new PropertyCondition(AutomationElement.ProcessIdProperty, Process.Id),
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Window)))
            .Cast<AutomationElement>()
            .Where(window => !window.Current.IsOffscreen)
            .ToArray();
        return windows.Length == 0 ? [MainWindow] : windows;
    }

    private static async Task<string[]> DrainAsync(StreamReader reader)
    {
        var lines = new List<string>();
        while (await reader.ReadLineAsync() is { } line)
        {
            if (line.Length > 1024 || lines.Count >= 128)
            {
                throw new IOException("ui_test_output_invalid");
            }

            lines.Add(line);
        }

        return lines.ToArray();
    }

    private void AssertSecretInputsEmpty()
    {
        var secrets = new List<ScreenshotSecretInput>();
        foreach (var edit in ProcessWindows().SelectMany(window => window.FindAll(
                     TreeScope.Subtree,
                     new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit))
                 .Cast<AutomationElement>()))
        {
            var name = edit.Current.Name ?? string.Empty;
            if (!ScreenshotSecretPolicy.IsSecretInput(name, edit.Current.IsPassword))
            {
                continue;
            }

            if (!edit.TryGetCurrentPattern(ValuePattern.Pattern, out var pattern))
            {
                throw new InvalidDataException("screenshot_secret_unreadable");
            }

            secrets.Add(new ScreenshotSecretInput(name, ((ValuePattern)pattern).Current.Value));
        }

        ScreenshotSecretPolicy.AssertEmpty(secrets);
    }

    private async Task RequestExitSafelyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Host.RequestExitAsync(cancellationToken);
        }
        catch (Exception error) when (error is OperationCanceledException or IOException or InvalidOperationException)
        {
        }
    }

    private static void AssertSafeOutput(
        IEnumerable<string> lines,
        string nonce,
        string pipeName,
        string artifactDirectory)
    {
        foreach (var line in lines)
        {
            Assert.DoesNotContain(nonce, line, StringComparison.Ordinal);
            Assert.DoesNotContain(pipeName, line, StringComparison.Ordinal);
            Assert.DoesNotContain(artifactDirectory, line, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("otpauth://", line, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Authorization", line, StringComparison.OrdinalIgnoreCase);
        }
    }

    private static void WaitUntil(Func<bool> predicate, TimeSpan timeout, string code)
    {
        var watch = Stopwatch.StartNew();
        while (!predicate() && watch.Elapsed < timeout)
        {
            Thread.Sleep(50);
        }

        if (!predicate())
        {
            throw new Xunit.Sdk.XunitException(code);
        }
    }

    private static bool IsUnavailableOrOffscreen(AutomationElement element)
    {
        try
        {
            return element.Current.IsOffscreen;
        }
        catch (ElementNotAvailableException)
        {
            return true;
        }
    }

    private static DesktopBounds ToLogical(DesktopBounds physical, double scale) => new(
        physical.Left / scale,
        physical.Top / scale,
        physical.Width / scale,
        physical.Height / scale);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeRect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr window, out NativeRect rect);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PrintWindow(IntPtr window, IntPtr deviceContext, uint flags);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(IntPtr window);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetClientRect(IntPtr window, out NativeRect rect);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ClientToScreen(IntPtr window, ref NativePoint point);

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr window);

    private const uint MouseEventRightDown = 0x0008;
    private const uint MouseEventRightUp = 0x0010;

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    private static extern void mouse_event(
        uint flags,
        uint dx,
        uint dy,
        uint data,
        UIntPtr extraInfo);
}
#endif
