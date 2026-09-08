namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class DpiLayoutContractTests
{
    [Fact]
    public void Quick_sign_progress_does_not_write_back_to_the_read_only_view_model_property()
    {
        var xaml = File.ReadAllText(Path.Combine(LocateViews(), "QuickSignView.xaml"));

        Assert.Contains(
            "Value=\"{Binding CopyProgressPercent, Mode=OneWay}\"",
            xaml,
            StringComparison.Ordinal);
    }

    private static string LocateViews()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "src", "CodeSignAuto.App", "UI", "Views");
            if (Directory.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("ui_views_missing");
    }
}
