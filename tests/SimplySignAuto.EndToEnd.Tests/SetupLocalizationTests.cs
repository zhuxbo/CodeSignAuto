using System.Collections;
using System.Globalization;
using System.Resources;
using System.Runtime.ExceptionServices;
using System.Windows.Forms;
using SimplySignAuto.Setup;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class SetupLocalizationTests
{
    [Theory]
    [InlineData("zh-CN", "zh-CN")]
    [InlineData("zh-HK", "zh-CN")]
    [InlineData("en-US", "en-US")]
    [InlineData("fr-FR", "en-US")]
    public void Windows_ui_culture_selects_only_the_supported_default(
        string windowsCulture,
        string expected)
    {
        var selected = SetupCulture.ResolveDefault(CultureInfo.GetCultureInfo(windowsCulture));

        Assert.Equal(expected, selected.Name);
    }

    [Fact]
    public void Explicit_setup_language_accepts_only_zh_cn_and_en_us()
    {
        Assert.Equal("zh-CN", SetupCulture.ResolveSelection("zh-CN").Name);
        Assert.Equal("en-US", SetupCulture.ResolveSelection("en-US").Name);
        Assert.Throws<ArgumentException>(() => SetupCulture.ResolveSelection("zh"));
        Assert.Throws<ArgumentException>(() => SetupCulture.ResolveSelection("en"));
        Assert.Throws<ArgumentException>(() => SetupCulture.ResolveSelection("fr-FR"));
    }

    [Fact]
    public void Chinese_and_english_setup_resources_have_identical_nonempty_keys()
    {
        var manager = new ResourceManager(
            "SimplySignAuto.Setup.Resources.SetupStrings",
            typeof(SetupCulture).Assembly);
        var chinese = ReadResourceSet(manager, CultureInfo.InvariantCulture);
        var english = ReadResourceSet(manager, CultureInfo.GetCultureInfo("en-US"));

        Assert.NotEmpty(chinese);
        Assert.Equal(chinese.Keys.Order(), english.Keys.Order());
        Assert.All(chinese.Values, value => Assert.False(string.IsNullOrWhiteSpace(value)));
        Assert.All(english.Values, value => Assert.False(string.IsNullOrWhiteSpace(value)));
    }

    [Theory]
    [InlineData("zh-CN", "required_runtime_missing", ".NET 10", ".NET Desktop Runtime", "错误代码：")]
    [InlineData("en-US", "required_runtime_missing", ".NET 10", ".NET Desktop Runtime", "Error code: ")]
    [InlineData("zh-CN", "simplysign_desktop_missing", "SimplySign Desktop", "下载", "错误代码：")]
    [InlineData("en-US", "simplysign_desktop_missing", "SimplySign Desktop", "Download", "Error code: ")]
    [InlineData("zh-CN", "simplysign_pkcs11_missing", "SimplySignPKCS.dll", "修复或重新安装", "错误代码：")]
    [InlineData("en-US", "simplysign_pkcs11_missing", "SimplySignPKCS.dll", "repair or reinstall", "Error code: ")]
    [InlineData("zh-CN", "os_unsupported", "Windows 10 22H2", "Windows Server 2019/2022/2025", "错误代码：")]
    [InlineData("en-US", "os_unsupported", "Windows 10 22H2", "Windows Server 2019/2022/2025", "Error code: ")]
    [InlineData("zh-CN", "desktop_experience_required", "Desktop Experience", "Server Core", "错误代码：")]
    [InlineData("en-US", "desktop_experience_required", "Desktop Experience", "Server Core", "Error code: ")]
    [InlineData("zh-CN", "architecture_unsupported", "x64", "64 位", "错误代码：")]
    [InlineData("en-US", "architecture_unsupported", "x64", "64-bit", "Error code: ")]
    [InlineData("zh-CN", "elevation_required", "管理员", "以管理员身份运行", "错误代码：")]
    [InlineData("en-US", "elevation_required", "administrator", "Run as administrator", "Error code: ")]
    [InlineData("zh-CN", "domain_controller_unsupported", "域控制器", "成员服务器", "错误代码：")]
    [InlineData("en-US", "domain_controller_unsupported", "domain controller", "member server", "Error code: ")]
    [InlineData("zh-CN", "autologon_conflict", "自动登录", "不会覆盖", "错误代码：")]
    [InlineData("en-US", "autologon_conflict", "AutoLogon", "will not overwrite", "Error code: ")]
    [InlineData("zh-CN", "autologon_plaintext_password_present", "明文自动登录密码", "安全移除", "错误代码：")]
    [InlineData("en-US", "autologon_plaintext_password_present", "plaintext AutoLogon password", "remove it securely", "Error code: ")]
    public void Stable_prerequisite_codes_have_actionable_messages_in_both_languages(
        string cultureName,
        string code,
        string expectedReason,
        string expectedAction,
        string expectedCodeLabel)
    {
        var failure = new SetupBootstrapperException(code);

        var message = failure.GetLocalizedMessage(SetupCulture.ResolveSelection(cultureName));

        Assert.Equal(code, failure.Code);
        Assert.Contains(expectedReason, message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(expectedAction, message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains($"{expectedCodeLabel}{code}", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("zh-CN", "安装未完成", "错误代码：setup_resource_conflict")]
    [InlineData("en-US", "Setup did not complete", "Error code: setup_resource_conflict")]
    public void Unknown_setup_failure_is_localized_without_exposing_an_exception(
        string cultureName,
        string expectedReason,
        string expectedCode)
    {
        var failure = new SetupBootstrapperException("setup_resource_conflict");

        var message = failure.GetLocalizedMessage(SetupCulture.ResolveSelection(cultureName));

        Assert.Contains(expectedReason, message, StringComparison.Ordinal);
        Assert.Contains(expectedCode, message, StringComparison.Ordinal);
        Assert.DoesNotContain("Exception", message, StringComparison.OrdinalIgnoreCase);
    }

    [WindowsFact]
    public void Setup_form_switches_language_twice_without_starting_installation()
    {
        RunInSta(() =>
        {
            var operations = new CountingOperations();
            using var form = new SetupForm(
                new SetupBootstrapper(operations),
                SetupProductKind.Main,
                SetupCulture.ResolveSelection("zh-CN"));
            var language = Find<ComboBox>(form, "SetupLanguage");

            Assert.Equal("SimplySignAuto 安装", form.Text);
            Assert.Equal("准备安装", Find<Label>(form, "SetupStatus").Text);

            language.SelectedIndex = 1;

            Assert.Equal("SimplySignAuto Setup", form.Text);
            Assert.Equal("Ready to install", Find<Label>(form, "SetupStatus").Text);
            Assert.Equal("Install", Find<Button>(form, "SetupInstall").Text);

            language.SelectedIndex = 0;

            Assert.Equal("SimplySignAuto 安装", form.Text);
            Assert.Equal("准备安装", Find<Label>(form, "SetupStatus").Text);
            Assert.Equal(0, operations.StageCalls);
        });
    }

    private static IReadOnlyDictionary<string, string> ReadResourceSet(
        ResourceManager manager,
        CultureInfo culture)
    {
        var resourceSet = manager.GetResourceSet(culture, createIfNotExists: true, tryParents: false);
        Assert.NotNull(resourceSet);
        return resourceSet.Cast<DictionaryEntry>().ToDictionary(
            entry => Assert.IsType<string>(entry.Key),
            entry => Assert.IsType<string>(entry.Value),
            StringComparer.Ordinal);
    }

    private static T Find<T>(Control root, string name) where T : Control =>
        Assert.IsType<T>(Assert.Single(root.Controls.Find(name, searchAllChildren: true)));

    private static void RunInSta(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception error)
            {
                failure = error;
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private sealed class CountingOperations : ISetupBootstrapperOperations
    {
        public int StageCalls { get; private set; }

        public Task<StagedSetupPayload> StageAsync(CancellationToken cancellationToken)
        {
            StageCalls++;
            throw new NotSupportedException();
        }

        public Task<int> InstallAsync(
            StagedSetupPayload staged,
            IProgress<SetupProgress>? progress,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task CleanupAsync(string mediaRoot) => throw new NotSupportedException();
    }

    private sealed class WindowsFactAttribute : FactAttribute
    {
        public WindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Windows only";
            }
        }
    }
}
