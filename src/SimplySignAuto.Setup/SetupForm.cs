namespace SimplySignAuto.Setup;

internal sealed class SetupForm : Form
{
    private readonly SetupBootstrapper _bootstrapper;
    private readonly Label _status;
    private readonly ProgressBar _progress;
    private readonly Button _install;
    private readonly Button _close;
    private bool _running;
    private bool _finished;

    public SetupForm(SetupBootstrapper bootstrapper, SetupProductKind productKind)
    {
        _bootstrapper = bootstrapper ?? throw new ArgumentNullException(nameof(bootstrapper));
        var isPdfExtension = productKind == SetupProductKind.PdfExtension;
        Text = isPdfExtension ? "SimplySignAuto PDF 扩展安装" : "SimplySignAuto 安装";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(520, 220);
        AutoScaleMode = AutoScaleMode.Dpi;

        var title = new Label
        {
            AutoSize = true,
            Font = new Font(Font, FontStyle.Bold),
            Text = isPdfExtension ? "安装 SimplySignAuto PDF 扩展" : "安装 SimplySignAuto",
            Location = new Point(28, 24),
        };
        var description = new Label
        {
            AutoSize = false,
            Text = isPdfExtension
                ? "安装程序将验证离线扩展介质并安装 PDF 签名支持。"
                : "安装程序将验证安装介质并初始化代码签名服务。",
            Location = new Point(28, 58),
            Size = new Size(464, 38),
        };
        _status = new Label
        {
            AutoSize = false,
            Text = "准备安装",
            Location = new Point(28, 105),
            Size = new Size(464, 24),
        };
        _progress = new ProgressBar
        {
            Location = new Point(28, 132),
            Size = new Size(464, 18),
            Style = ProgressBarStyle.Blocks,
        };
        _install = new Button
        {
            Text = "安装",
            Location = new Point(326, 170),
            Size = new Size(80, 30),
        };
        _install.Click += InstallClicked;
        _close = new Button
        {
            Text = "取消",
            DialogResult = DialogResult.Cancel,
            Location = new Point(412, 170),
            Size = new Size(80, 30),
        };
        _close.Click += (_, _) => Close();
        Controls.AddRange([title, description, _status, _progress, _install, _close]);
        CancelButton = _close;
        AcceptButton = _install;
        FormClosing += HandleFormClosing;
    }

    public int ExitCode { get; private set; } = 2;

    private async void InstallClicked(object? sender, EventArgs eventArgs)
    {
        if (_finished)
        {
            Close();
            return;
        }

        if (_running)
        {
            return;
        }

        _running = true;
        _install.Enabled = false;
        _close.Enabled = false;
        _progress.Minimum = 0;
        _progress.Maximum = 100;
        _progress.Value = 0;
        _status.Text = "正在验证安装介质…";
        try
        {
            var progress = new Progress<SetupProgress>(value =>
            {
                _progress.Value = value.Percent;
                _status.Text = value.Message;
            });
            ExitCode = await _bootstrapper.RunAsync(progress, CancellationToken.None);
            _status.Text = ExitCode == 0 ? "安装完成" : $"安装失败（代码 {ExitCode}）";
        }
        catch (SetupBootstrapperException error)
        {
            ExitCode = 1;
            _status.Text = "安装失败";
            MessageBox.Show(
                this,
                error.Message,
                Text,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        catch
        {
            ExitCode = 1;
            _status.Text = "setup_failed";
        }
        finally
        {
            _running = false;
            _finished = true;
            _install.Enabled = true;
            _install.Text = "关闭";
            _close.Visible = false;
            AcceptButton = _install;
        }
    }

    private void HandleFormClosing(object? sender, FormClosingEventArgs eventArgs)
    {
        if (_running)
        {
            eventArgs.Cancel = true;
        }
    }
}
