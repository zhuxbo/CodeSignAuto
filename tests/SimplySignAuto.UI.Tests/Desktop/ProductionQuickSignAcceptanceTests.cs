#if SIMPLYSIGN_WPF
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows.Automation;

namespace SimplySignAuto.UI.Tests.Desktop;

[Collection(DesktopUiAutomationCollection.Name)]
public sealed class ProductionQuickSignAcceptanceTests
{
    [ProductionAcceptanceFact]
    [Trait("Category", "ProductionAcceptance")]
    public async Task Production_composition_signs_exe_and_pdf_hides_during_completion_and_restores_from_tray()
    {
        try
        {
            await ProductionQuickSignApp.RunAsync();
        }
        catch (Exception error)
        {
            var code = error is InvalidOperationException &&
                error.Message.StartsWith("production_ui_", StringComparison.Ordinal) &&
                error.Message.Length <= 80 &&
                error.Message.All(character =>
                    character is >= 'a' and <= 'z' or >= '0' and <= '9' or '_')
                ? error.Message
                : "production_ui_acceptance_failed";
            throw new InvalidOperationException(code, error);
        }
    }
}

internal static class ProductionQuickSignApp
{
    private const int LegacyAccessiblePatternId = 10018;
    private const uint MouseLeftDown = 0x0002;
    private const uint MouseLeftUp = 0x0004;
    private const uint MouseRightDown = 0x0008;
    private const uint MouseRightUp = 0x0010;
    private const uint GetWindowOwner = 4;
    private const int ShowRestore = 9;
    private static readonly TimeSpan ShortTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan SigningTimeout = TimeSpan.FromSeconds(300);

    public static async Task RunAsync()
    {
        var appHost = ResolveFile("SIMPLYSIGN_PRODUCTION_UI_APPHOST", ".exe");
        var exeInput = ResolveFile("SIMPLYSIGN_PRODUCTION_UI_EXE_INPUT", ".exe");
        var pdfInput = ResolveFile("SIMPLYSIGN_PRODUCTION_UI_PDF_INPUT", ".pdf");
        var otpUriFile = ResolveOptionalFile("SIMPLYSIGN_PRODUCTION_UI_OTP_URI_FILE");
        var outputDirectory = ResolveDirectory("SIMPLYSIGN_PRODUCTION_UI_ARTIFACT_DIRECTORY");
        Require(
            string.Equals(Path.GetFileName(appHost), "SimplySignAuto.exe", StringComparison.OrdinalIgnoreCase),
            "production_ui_apphost_invalid");

        var exeOutput = Path.Combine(outputDirectory, "quick-exe.signed.exe");
        var pdfOutput = Path.Combine(outputDirectory, "quick-pdf.signed.pdf");
        var resultPath = Path.Combine(outputDirectory, "production-ui-result.json");
        Require(
            !File.Exists(exeOutput) && !File.Exists(pdfOutput) && !File.Exists(resultPath),
            "production_ui_artifact_collision");

        var exeInputBefore = HashFile(exeInput);
        var pdfInputBefore = HashFile(pdfInput);
        using var process = await ActivateAndResolveOwnedProcessAsync(appHost);
        var mainWindow = await WaitForMainWindowAsync(process, ShortTimeout);
        try
        {
            if (otpUriFile is not null)
            {
                ImportOtpThroughAdministratorConsole(process, mainWindow, otpUriFile);
            }

            EnsureSimplySignLogin(process, mainWindow);

            SelectNavigation(process, mainWindow, "快速签名");
            _ = WaitForElement(
                process,
                mainWindow,
                "请选择签名文件",
                ControlType.Text,
                ShortTimeout);
            var secretScanClean = AssertAutomationTreeSafe(process, mainWindow);

            ChooseFile(process, mainWindow, exeInput);
            _ = WaitForElement(process, mainWindow, "代码签名", ControlType.Text, ShortTimeout);
            SelectCertificateIfRequired(process, mainWindow);
            _ = WaitForElement(process, mainWindow, "可以提交到本机签名队列", ControlType.Text, SigningTimeout);
            Invoke(process, mainWindow, "提交本机签名任务");
            _ = WaitForElement(process, mainWindow, "签名任务", ControlType.Text, ShortTimeout);
            WaitForButtonEnabled(process, mainWindow, "保存签名结果副本", SigningTimeout);
            SaveThroughDialog(process, mainWindow, "保存签名结果副本", exeOutput);
            WaitForOrdinaryOutput(exeOutput, ShortTimeout);

            SelectNavigation(process, mainWindow, "快速签名");
            ChooseFile(process, mainWindow, pdfInput);
            _ = WaitForElement(process, mainWindow, "PDF 文档签名", ControlType.Text, ShortTimeout);
            SelectCertificateIfRequired(process, mainWindow);
            SetValue(process, mainWindow, "PDF 签名页码", "2");
            SetValue(process, mainWindow, "签名区域左边界", "200");
            SetValue(process, mainWindow, "签名区域下边界", "642");
            SetValue(process, mainWindow, "签名区域右边界", "548");
            SetValue(process, mainWindow, "签名区域上边界", "680");
            _ = WaitForElement(process, mainWindow, "可以提交到本机签名队列", ControlType.Text, SigningTimeout);
            Invoke(process, mainWindow, "提交本机签名任务");
            _ = WaitForElement(process, mainWindow, "签名任务", ControlType.Text, ShortTimeout);
            var pendingSave = WaitForElement(
                process,
                mainWindow,
                "保存签名结果副本",
                ControlType.Button,
                ShortTimeout);
            Require(!pendingSave.Current.IsEnabled, "production_ui_hidden_completion_not_observed");
            CloseToTray(process, mainWindow);
            WaitForHiddenButtonEnabled(process, mainWindow, pendingSave, SigningTimeout);
            RestoreFromOwnedTray(process, SigningTimeout);
            mainWindow = await WaitForMainWindowAsync(process, ShortTimeout);
            SelectNavigation(process, mainWindow, "签名任务");
            WaitForButtonEnabled(process, mainWindow, "保存签名结果副本", ShortTimeout);
            SaveThroughDialog(process, mainWindow, "保存签名结果副本", pdfOutput);
            WaitForOrdinaryOutput(pdfOutput, ShortTimeout);
            secretScanClean &= AssertAutomationTreeSafe(process, mainWindow);

            var exeInputAfter = HashFile(exeInput);
            var pdfInputAfter = HashFile(pdfInput);
            var exeResult = HashFile(exeOutput);
            var pdfResult = HashFile(pdfOutput);
            Require(
                string.Equals(exeInputBefore, exeInputAfter, StringComparison.Ordinal) &&
                string.Equals(pdfInputBefore, pdfInputAfter, StringComparison.Ordinal) &&
                !string.Equals(exeInputBefore, exeResult, StringComparison.Ordinal) &&
                !string.Equals(pdfInputBefore, pdfResult, StringComparison.Ordinal),
                "production_ui_hash_invalid");

            var evidence = JsonSerializer.Serialize(new
            {
                schemaVersion = 1,
                exeInputBefore,
                exeInputAfter,
                exeResult,
                pdfInputBefore,
                pdfInputAfter,
                pdfResult,
                productionComposition = true,
                readinessVisible = true,
                hiddenSubmissionCompleted = true,
                trayRestoreObserved = true,
                secretScanClean,
            });
            using var stream = new FileStream(
                resultPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.WriteThrough);
            using var writer = new StreamWriter(stream, new System.Text.UTF8Encoding(false));
            writer.Write(evidence);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }
        finally
        {
            TryHideWindow(process, mainWindow);
        }
    }

    private static async Task<Process> ActivateAndResolveOwnedProcessAsync(string appHost)
    {
        var start = new ProcessStartInfo
        {
            FileName = appHost,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var key in start.Environment.Keys
                     .Where(key => key.StartsWith("SIMPLYSIGN_UI_TEST_", StringComparison.Ordinal))
                     .ToArray())
        {
            start.Environment.Remove(key);
        }

        var activation = Process.Start(start)
            ?? throw new InvalidOperationException("production_ui_activation_failed");
        var stdout = activation.StandardOutput.ReadToEndAsync();
        var stderr = activation.StandardError.ReadToEndAsync();
        var watch = Stopwatch.StartNew();
        do
        {
            activation.Refresh();
            if (!activation.HasExited &&
                activation.MainWindowHandle != IntPtr.Zero &&
                IsExactOwnedProcess(activation, appHost))
            {
                return activation;
            }

            if (!activation.HasExited)
            {
                await Task.Delay(100);
                continue;
            }

            Require(
                activation.ExitCode == 0 &&
                string.IsNullOrWhiteSpace(await stdout) &&
                string.IsNullOrWhiteSpace(await stderr),
                "production_ui_activation_failed");
            activation.Dispose();
            var resolutionWatch = Stopwatch.StartNew();
            do
            {
                var matches = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(appHost))
                    .Where(candidate => IsExactOwnedProcess(candidate, appHost))
                    .ToArray();
                if (matches.Length == 1)
                {
                    return matches[0];
                }

                foreach (var candidate in matches)
                {
                    candidate.Dispose();
                }

                await Task.Delay(100);
            }
            while (resolutionWatch.Elapsed < ShortTimeout);

            throw new InvalidOperationException("production_ui_owner_invalid");
        }
        while (watch.Elapsed < ShortTimeout);

        activation.Dispose();
        throw new InvalidOperationException("production_ui_owner_invalid");
    }

    private static bool IsExactOwnedProcess(Process process, string appHost)
    {
        try
        {
            return process.SessionId == Process.GetCurrentProcess().SessionId &&
                string.Equals(process.MainModule?.FileName, appHost, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static async Task<AutomationElement> WaitForMainWindowAsync(Process process, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            process.Refresh();
            Require(!process.HasExited, "production_ui_owner_exited");
            if (process.MainWindowHandle != IntPtr.Zero)
            {
                var candidate = AutomationElement.FromHandle(process.MainWindowHandle);
                if (candidate.Current.ControlType == ControlType.Window && !candidate.Current.IsOffscreen)
                {
                    return candidate;
                }
            }

            await Task.Delay(100);
        }
        while (watch.Elapsed < timeout);

        throw new InvalidOperationException("production_ui_window_timeout");
    }

    private static void SelectNavigation(Process process, AutomationElement mainWindow, string name)
    {
        var item = WaitForElement(process, mainWindow, name, ControlType.ListItem, ShortTimeout);
        ((SelectionItemPattern)item.GetCurrentPattern(SelectionItemPattern.Pattern)).Select();
    }

    private static void Invoke(Process process, AutomationElement mainWindow, string name)
    {
        var button = WaitForElement(process, mainWindow, name, ControlType.Button, ShortTimeout);
        ((InvokePattern)button.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
    }

    private static void SetValue(
        Process process,
        AutomationElement mainWindow,
        string name,
        string value)
    {
        var edit = WaitForElement(process, mainWindow, name, ControlType.Edit, ShortTimeout);
        ((ValuePattern)edit.GetCurrentPattern(ValuePattern.Pattern)).SetValue(value);
    }

    private static void SelectCertificateIfRequired(Process process, AutomationElement mainWindow)
    {
        var comboBox = WaitForElement(process, mainWindow, "选择签名证书", ControlType.ComboBox, ShortTimeout);
        if (comboBox.TryGetCurrentPattern(SelectionPattern.Pattern, out var pattern) &&
            ((SelectionPattern)pattern).Current.GetSelection().Length > 0)
        {
            return;
        }

        comboBox.SetFocus();
        System.Windows.Forms.SendKeys.SendWait("%{DOWN}{HOME}{ENTER}");
    }

    private static void ImportOtpThroughAdministratorConsole(
        Process process,
        AutomationElement mainWindow,
        string otpUriFile)
    {
        var uri = File.ReadAllText(otpUriFile).Trim();
        try
        {
            Require(
                uri.Length is > 0 and <= 4096 &&
                uri.StartsWith("otpauth://totp/", StringComparison.OrdinalIgnoreCase),
                "production_ui_otp_input_invalid");
            SelectNavigation(process, mainWindow, "激活凭证");
            FocusAndInvoke(process, mainWindow, "导入 Certum 激活内容");
            var dialog = WaitForTopLevelWindow(process, mainWindow, ShortTimeout);
            var input = dialog.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.NameProperty, "Certum 激活内容"),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit)))
                ?? throw new InvalidOperationException("production_ui_otp_dialog_invalid");
            ((ValuePattern)input.GetCurrentPattern(ValuePattern.Pattern)).SetValue(uri);
            var save = dialog.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(
                        AutomationElement.NameProperty,
                        "验证并保存 Certum 激活内容"),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button)))
                ?? throw new InvalidOperationException("production_ui_otp_dialog_invalid");
            ((InvokePattern)save.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
            WaitUntil(
                () => IsUnavailableOrOffscreen(dialog),
                SigningTimeout,
                "production_ui_otp_import_timeout");
            WaitForButtonEnabled(
                process,
                mainWindow,
                "清除激活凭证",
                SigningTimeout);
            Require(
                AssertAutomationTreeSafe(process, mainWindow),
                "production_ui_secret_scan_failed");
        }
        finally
        {
            uri = string.Empty;
        }
    }

    private static void EnsureSimplySignLogin(Process process, AutomationElement mainWindow)
    {
        SelectNavigation(process, mainWindow, "概览");
        var login = WaitForElement(process, mainWindow, "登录", ControlType.Button, ShortTimeout);
        ((InvokePattern)login.GetCurrentPattern(InvokePattern.Pattern)).Invoke();

        var watch = Stopwatch.StartNew();
        do
        {
            if (TryFindTopLevelWindow(process, mainWindow) is { } confirmation)
            {
                var message = confirmation.FindFirst(
                    TreeScope.Descendants,
                    new AndCondition(
                        new PropertyCondition(
                            AutomationElement.NameProperty,
                            "检测到 SimplySign 正在其他 Windows 会话运行。将关闭该会话并在当前会话登录，是否继续？"),
                        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text)));
                _ = message ?? throw new InvalidOperationException("production_ui_login_confirmation_invalid");
                var confirm = confirmation.FindAll(
                        TreeScope.Descendants,
                        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button))
                    .Cast<AutomationElement>()
                    .FirstOrDefault(element =>
                        element.Current.Name.StartsWith("是", StringComparison.Ordinal) ||
                        element.Current.Name.StartsWith("Yes", StringComparison.OrdinalIgnoreCase))
                    ?? throw new InvalidOperationException("production_ui_login_confirmation_invalid");
                ((InvokePattern)confirm.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
                WaitUntil(
                    () => IsUnavailableOrOffscreen(confirmation),
                    ShortTimeout,
                    "production_ui_login_confirmation_timeout");
                continue;
            }

            var logout = mainWindow.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.NameProperty, "退出"),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button)));
            try
            {
                if (logout?.Current.IsEnabled == true)
                {
                    return;
                }
            }
            catch (ElementNotAvailableException)
            {
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < SigningTimeout && !process.HasExited);

        throw new InvalidOperationException("production_ui_login_timeout");
    }

    private static void FocusAndInvoke(
        Process process,
        AutomationElement mainWindow,
        string name)
    {
        var button = WaitForElement(process, mainWindow, name, ControlType.Button, ShortTimeout);
        button.SetFocus();
        System.Windows.Forms.SendKeys.SendWait(" ");
    }

    private static void ChooseFile(Process process, AutomationElement mainWindow, string path)
    {
        var existingWindows = CaptureTopLevelWindowHandles();
        ClickButton(process, mainWindow, "选择本机签名文件");
        CompleteFileDialog(process, mainWindow, path, existingWindows);
    }

    private static void SaveThroughDialog(
        Process process,
        AutomationElement mainWindow,
        string buttonName,
        string path)
    {
        var existingWindows = CaptureTopLevelWindowHandles();
        ClickButton(process, mainWindow, buttonName);
        CompleteFileDialog(process, mainWindow, path, existingWindows);
    }

    private static void ClickButton(
        Process process,
        AutomationElement mainWindow,
        string buttonName)
    {
        BringToForeground(new IntPtr(mainWindow.Current.NativeWindowHandle));
        var button = WaitForElement(process, mainWindow, buttonName, ControlType.Button, ShortTimeout);
        var point = button.GetClickablePoint();
        Require(
            SetCursorPos(
                checked((int)Math.Round(point.X)),
                checked((int)Math.Round(point.Y))),
            "production_ui_cursor_invalid");
        mouse_event(MouseLeftDown, 0, 0, 0, UIntPtr.Zero);
        mouse_event(MouseLeftUp, 0, 0, 0, UIntPtr.Zero);
    }

    private static void BringToForeground(IntPtr window)
    {
        var foreground = GetForegroundWindow();
        var currentThread = GetCurrentThreadId();
        var foregroundThread = foreground == IntPtr.Zero
            ? 0
            : GetWindowThreadProcessId(foreground, out _);
        var attached = foregroundThread != 0 &&
            foregroundThread != currentThread &&
            AttachThreadInput(currentThread, foregroundThread, attachInput: true);
        try
        {
            _ = ShowWindowAsync(window, ShowRestore);
            _ = BringWindowToTop(window);
            _ = SetForegroundWindow(window);
        }
        finally
        {
            if (attached)
            {
                _ = AttachThreadInput(currentThread, foregroundThread, attachInput: false);
            }
        }

        WaitUntil(
            () => GetForegroundWindow() == window,
            TimeSpan.FromSeconds(2),
            "production_ui_foreground_invalid");
    }

    private static void CompleteFileDialog(
        Process process,
        AutomationElement mainWindow,
        string path,
        IReadOnlySet<int> existingWindows)
    {
        var dialog = WaitForTopLevelWindow(process, mainWindow, ShortTimeout, existingWindows);
        var edits = dialog.FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit))
            .Cast<AutomationElement>()
            .Where(element => element.TryGetCurrentPattern(ValuePattern.Pattern, out _))
            .ToArray();
        var edit = edits.FirstOrDefault(element => element.Current.AutomationId == "1148")
            ?? edits.LastOrDefault()
            ?? throw new InvalidOperationException("production_ui_file_dialog_invalid");
        ((ValuePattern)edit.GetCurrentPattern(ValuePattern.Pattern)).SetValue(path);
        var action = dialog.FindAll(
                TreeScope.Descendants,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button))
            .Cast<AutomationElement>()
            .FirstOrDefault(element =>
                element.Current.Name.StartsWith("打开", StringComparison.Ordinal) ||
                element.Current.Name.StartsWith("保存", StringComparison.Ordinal) ||
                element.Current.Name.StartsWith("Open", StringComparison.OrdinalIgnoreCase) ||
                element.Current.Name.StartsWith("Save", StringComparison.OrdinalIgnoreCase) ||
                element.Current.Name.StartsWith("选择", StringComparison.Ordinal))
            ?? throw new InvalidOperationException("production_ui_file_dialog_invalid");
        ((InvokePattern)action.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
        WaitUntil(
            () => IsUnavailableOrOffscreen(dialog),
            ShortTimeout,
            "production_ui_file_dialog_timeout");
    }

    private static AutomationElement WaitForTopLevelWindow(
        Process process,
        AutomationElement excluded,
        TimeSpan timeout,
        IReadOnlySet<int>? existingWindows = null)
    {
        var watch = Stopwatch.StartNew();
        var excludedHandle = new IntPtr(excluded.Current.NativeWindowHandle);
        do
        {
            var candidate = TryFindTopLevelWindow(process, excluded, excludedHandle, existingWindows);
            if (candidate is not null)
            {
                return candidate;
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < timeout && !process.HasExited);

        WriteDialogDiagnostics(process, excluded, existingWindows);
        throw new InvalidOperationException("production_ui_dialog_timeout");
    }

    private static void WriteDialogDiagnostics(
        Process process,
        AutomationElement excluded,
        IReadOnlySet<int>? existingWindows)
    {
        try
        {
            var outputDirectory = Environment.GetEnvironmentVariable(
                "SIMPLYSIGN_PRODUCTION_UI_ARTIFACT_DIRECTORY");
            if (string.IsNullOrWhiteSpace(outputDirectory))
            {
                return;
            }

            var windows = AutomationElement.RootElement.FindAll(
                    TreeScope.Children,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Window))
                .Cast<AutomationElement>()
                .Select(element => new
                {
                    handle = element.Current.NativeWindowHandle,
                    processId = element.Current.ProcessId,
                    className = element.Current.ClassName,
                    offscreen = element.Current.IsOffscreen,
                    owner = GetWindow(
                        new IntPtr(element.Current.NativeWindowHandle),
                        GetWindowOwner).ToInt64(),
                    existedBefore = existingWindows?.Contains(element.Current.NativeWindowHandle),
                })
                .ToArray();
            var evidence = JsonSerializer.Serialize(new
            {
                processId = process.Id,
                sessionId = process.SessionId,
                excludedHandle = excluded.Current.NativeWindowHandle,
                windows,
            });
            File.WriteAllText(
                Path.Combine(outputDirectory, "dialog-diagnostics.json"),
                evidence,
                new System.Text.UTF8Encoding(false));
        }
        catch (Exception error) when (error is
            IOException or
            UnauthorizedAccessException or
            InvalidOperationException or
            ElementNotAvailableException)
        {
        }
    }

    private static AutomationElement? TryFindTopLevelWindow(
        Process process,
        AutomationElement excluded) =>
        TryFindTopLevelWindow(
            process,
            excluded,
            new IntPtr(excluded.Current.NativeWindowHandle),
            existingWindows: null);

    private static AutomationElement? TryFindTopLevelWindow(
        Process process,
        AutomationElement excluded,
        IntPtr excludedHandle,
        IReadOnlySet<int>? existingWindows) =>
        AutomationElement.RootElement.FindAll(
                TreeScope.Children,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Window))
            .Cast<AutomationElement>()
            .FirstOrDefault(element => IsExpectedTopLevelWindow(
                process,
                excluded,
                excludedHandle,
                existingWindows,
                element));

    private static HashSet<int> CaptureTopLevelWindowHandles() =>
        AutomationElement.RootElement.FindAll(
                TreeScope.Children,
                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Window))
            .Cast<AutomationElement>()
            .Select(element => element.Current.NativeWindowHandle)
            .Where(handle => handle != 0)
            .ToHashSet();

    private static bool IsExpectedTopLevelWindow(
        Process process,
        AutomationElement excluded,
        IntPtr excludedHandle,
        IReadOnlySet<int>? existingWindows,
        AutomationElement element)
    {
        try
        {
            var handleValue = element.Current.NativeWindowHandle;
            if (handleValue == 0 ||
                handleValue == excluded.Current.NativeWindowHandle ||
                element.Current.IsOffscreen)
            {
                return false;
            }

            if (element.Current.ProcessId == process.Id ||
                IsOwnedBy(new IntPtr(handleValue), excludedHandle))
            {
                return true;
            }

            if (existingWindows is null ||
                existingWindows.Contains(handleValue) ||
                !string.Equals(element.Current.ClassName, "#32770", StringComparison.Ordinal))
            {
                return false;
            }

            using var owner = Process.GetProcessById(element.Current.ProcessId);
            return owner.SessionId == process.SessionId;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (ElementNotAvailableException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static bool IsOwnedBy(IntPtr candidate, IntPtr expectedOwner)
    {
        for (var depth = 0; depth < 8; depth++)
        {
            candidate = GetWindow(candidate, GetWindowOwner);
            if (candidate == IntPtr.Zero)
            {
                return false;
            }

            if (candidate == expectedOwner)
            {
                return true;
            }
        }

        return false;
    }

    private static AutomationElement WaitForElement(
        Process process,
        AutomationElement mainWindow,
        string name,
        ControlType type,
        TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            var candidate = mainWindow.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.NameProperty, name),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, type)));
            if (candidate is not null && !candidate.Current.IsOffscreen)
            {
                return candidate;
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < timeout && !process.HasExited);

        throw new InvalidOperationException("production_ui_element_timeout");
    }

    private static void WaitForButtonEnabled(
        Process process,
        AutomationElement mainWindow,
        string name,
        TimeSpan timeout) =>
        WaitUntil(
            () =>
            {
                try
                {
                    return mainWindow.FindFirst(
                            TreeScope.Descendants,
                            new AndCondition(
                                new PropertyCondition(AutomationElement.NameProperty, name),
                                new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Button)))
                        is { Current.IsEnabled: true, Current.IsOffscreen: false };
                }
                catch (ElementNotAvailableException)
                {
                    return false;
                }
            },
            timeout,
            "production_ui_result_timeout");

    private static void CloseToTray(Process process, AutomationElement mainWindow)
    {
        ((WindowPattern)mainWindow.GetCurrentPattern(WindowPattern.Pattern)).Close();
        WaitUntil(
            () => IsUnavailableOrOffscreen(mainWindow) && !process.HasExited,
            ShortTimeout,
            "production_ui_hide_timeout");
    }

    private static void WaitForHiddenButtonEnabled(
        Process process,
        AutomationElement mainWindow,
        AutomationElement button,
        TimeSpan timeout)
    {
        WaitUntil(
            () =>
            {
                try
                {
                    return !process.HasExited && mainWindow.Current.IsOffscreen && button.Current.IsEnabled;
                }
                catch (ElementNotAvailableException)
                {
                    return false;
                }
            },
            timeout,
            "production_ui_hidden_completion_timeout");
    }

    private static void WaitForRootTextContaining(Process process, string expected, TimeSpan timeout)
    {
        WaitUntil(
            () => AutomationElement.RootElement.FindAll(
                    TreeScope.Descendants,
                    new AndCondition(
                        new PropertyCondition(AutomationElement.ProcessIdProperty, process.Id),
                        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text)))
                .Cast<AutomationElement>()
                .Any(element => element.Current.Name.Contains(expected, StringComparison.Ordinal)),
            timeout,
            "production_ui_hidden_completion_timeout");
    }

    private static void RestoreFromOwnedTray(Process process, TimeSpan timeout)
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

            foreach (var icon in buttons.Where(candidate =>
                         candidate.Current.Name.StartsWith("SimplySignAuto -", StringComparison.Ordinal)))
            {
                var bounds = icon.Current.BoundingRectangle;
                if (bounds.IsEmpty || bounds.Width <= 0 || bounds.Height <= 0)
                {
                    continue;
                }

                var x = checked((int)Math.Round(bounds.Left + (bounds.Width / 2)));
                var y = checked((int)Math.Round(bounds.Top + (bounds.Height / 2)));
                if (!SetCursorPos(x, y))
                {
                    continue;
                }

                mouse_event(MouseLeftDown, 0, 0, 0, UIntPtr.Zero);
                mouse_event(MouseLeftUp, 0, 0, 0, UIntPtr.Zero);
                Thread.Sleep(checked((int)Math.Min(GetDoubleClickTime() / 2, 100u)));
                mouse_event(MouseLeftDown, 0, 0, 0, UIntPtr.Zero);
                mouse_event(MouseLeftUp, 0, 0, 0, UIntPtr.Zero);
                if (TryWaitForVisibleOwnedMainWindow(process, TimeSpan.FromSeconds(2)))
                {
                    return;
                }

                // A popup-menu restore is diagnostic only. It must never satisfy the acceptance result.
                mouse_event(MouseRightDown, 0, 0, 0, UIntPtr.Zero);
                mouse_event(MouseRightUp, 0, 0, 0, UIntPtr.Zero);
                var menu = TryWaitForOwnedTrayMenu(process, TimeSpan.FromSeconds(1));
                if (menu is not null)
                {
                    ((InvokePattern)menu.GetCurrentPattern(InvokePattern.Pattern)).Invoke();
                    _ = TryWaitForVisibleOwnedMainWindow(process, TimeSpan.FromSeconds(1));
                    throw new InvalidOperationException("production_ui_tray_double_click_required");
                }

                System.Windows.Forms.SendKeys.SendWait("{ESC}");
            }

            Thread.Sleep(100);
        }
        while (watch.Elapsed < timeout && !process.HasExited);

        throw new InvalidOperationException("production_ui_tray_restore_timeout");
    }

    private static bool TryWaitForVisibleOwnedMainWindow(Process process, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            process.Refresh();
            if (process.HasExited)
            {
                return false;
            }
            if (process.MainWindowHandle != IntPtr.Zero)
            {
                try
                {
                    var candidate = AutomationElement.FromHandle(process.MainWindowHandle);
                    if (candidate.Current.ProcessId == process.Id &&
                        candidate.Current.ControlType == ControlType.Window &&
                        !candidate.Current.IsOffscreen)
                    {
                        return true;
                    }
                }
                catch (ElementNotAvailableException)
                {
                }
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < timeout);

        return false;
    }

    private static AutomationElement? TryWaitForOwnedTrayMenu(Process process, TimeSpan timeout)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            var menu = AutomationElement.RootElement.FindFirst(
                TreeScope.Descendants,
                new AndCondition(
                    new PropertyCondition(AutomationElement.ProcessIdProperty, process.Id),
                    new PropertyCondition(AutomationElement.NameProperty, "打开控制台"),
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.MenuItem)));
            if (menu is not null)
            {
                return menu;
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < timeout && !process.HasExited);

        return null;
    }

    private static bool AssertAutomationTreeSafe(Process process, AutomationElement mainWindow)
    {
        var observations = new List<AutomationSecretObservation>();
        foreach (var element in mainWindow.FindAll(TreeScope.Subtree, Condition.TrueCondition)
                     .Cast<AutomationElement>())
        {
            Require(element.Current.ProcessId == process.Id, "production_ui_tree_owner_invalid");
            string? valuePatternValue = null;
            if (element.TryGetCurrentPattern(ValuePattern.Pattern, out var valuePattern))
            {
                valuePatternValue = ((ValuePattern)valuePattern).Current.Value;
            }
            string? legacyValue = null;
            var legacyPatternIdentifier = AutomationPattern.LookupById(LegacyAccessiblePatternId);
            if (legacyPatternIdentifier is not null &&
                element.TryGetCurrentPattern(legacyPatternIdentifier, out var legacyPattern))
            {
                var current = legacyPattern.GetType().GetProperty("Current")?.GetValue(legacyPattern)
                    ?? throw new InvalidOperationException("production_ui_secret_scan_failed");
                legacyValue = current.GetType().GetProperty("Value")?.GetValue(current) as string
                    ?? string.Empty;
            }
            observations.Add(new AutomationSecretObservation(
                element.Current.Name ?? string.Empty,
                element.Current.AutomationId ?? string.Empty,
                element.Current.IsPassword,
                valuePatternValue,
                legacyValue,
                new[]
                {
                    element.Current.Name ?? string.Empty,
                    element.Current.HelpText ?? string.Empty,
                    element.Current.ItemStatus ?? string.Empty,
                    element.Current.AutomationId ?? string.Empty,
                    element.Current.AccessKey ?? string.Empty,
                    element.Current.AcceleratorKey ?? string.Empty,
                }));
        }

        return ScreenshotSecretPolicy.AssertAutomationTreeSafe(observations);
    }

    private static string ResolveFile(string variable, string extension)
    {
        var path = Environment.GetEnvironmentVariable(variable);
        Require(IsCanonical(path), "production_ui_path_invalid");
        Require(
            File.Exists(path) &&
            string.Equals(Path.GetExtension(path), extension, StringComparison.OrdinalIgnoreCase) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0,
            "production_ui_path_invalid");
        return path!;
    }

    private static string? ResolveOptionalFile(string variable)
    {
        var path = Environment.GetEnvironmentVariable(variable);
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        Require(IsCanonical(path), "production_ui_path_invalid");
        Require(
            File.Exists(path) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0,
            "production_ui_path_invalid");
        return path;
    }

    private static string ResolveDirectory(string variable)
    {
        var path = Environment.GetEnvironmentVariable(variable);
        Require(IsCanonical(path), "production_ui_path_invalid");
        Require(
            Directory.Exists(path) &&
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0,
            "production_ui_path_invalid");
        return path!;
    }

    private static bool IsCanonical(string? path) =>
        !string.IsNullOrWhiteSpace(path) &&
        Path.IsPathFullyQualified(path) &&
        string.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase) &&
        path.IndexOfAny(['\r', '\n', '\0']) < 0;

    private static string HashFile(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    private static void WaitForOrdinaryOutput(string path, TimeSpan timeout)
    {
        WaitUntil(
            () =>
            {
                try
                {
                    var info = new FileInfo(path);
                    return info.Exists && info.Length > 0 &&
                        (info.Attributes & FileAttributes.ReparsePoint) == 0;
                }
                catch (IOException)
                {
                    return false;
                }
            },
            timeout,
            "production_ui_output_timeout");
    }

    private static void WaitUntil(Func<bool> condition, TimeSpan timeout, string code)
    {
        var watch = Stopwatch.StartNew();
        do
        {
            if (condition())
            {
                return;
            }

            Thread.Sleep(50);
        }
        while (watch.Elapsed < timeout);

        throw new InvalidOperationException(code);
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

    private static void TryHideWindow(Process process, AutomationElement mainWindow)
    {
        try
        {
            if (!process.HasExited && !mainWindow.Current.IsOffscreen)
            {
                ((WindowPattern)mainWindow.GetCurrentPattern(WindowPattern.Pattern)).Close();
            }
        }
        catch (ElementNotAvailableException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static void Require(bool condition, string code)
    {
        if (!condition)
        {
            throw new InvalidOperationException(code);
        }
    }

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AttachThreadInput(uint attach, uint attachTo, bool attachInput);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindowAsync(IntPtr window, int command);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BringWindowToTop(IntPtr window);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    private static extern uint GetDoubleClickTime();

    [DllImport("user32.dll")]
    private static extern IntPtr GetWindow(IntPtr window, uint command);

    [DllImport("user32.dll")]
    private static extern void mouse_event(
        uint flags,
        uint dx,
        uint dy,
        uint data,
        UIntPtr extraInfo);
}
#else
namespace SimplySignAuto.UI.Tests.Desktop;

public sealed class ProductionQuickSignAcceptanceTests
{
    [Fact(Skip = "Requires production WPF in a WTS Active non-zero Windows session.")]
    [Trait("Category", "ProductionAcceptance")]
    public void Production_composition_signs_exe_and_pdf_hides_during_completion_and_restores_from_tray()
    {
    }
}
#endif
