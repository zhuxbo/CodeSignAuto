using SimplySignAuto.App.UI.Testing;

namespace SimplySignAuto.UI.Tests.Desktop;

public sealed class UiTestOwnedDirectoryTests
{
    [Fact]
    public void Random_owned_directory_is_new_private_scope_and_is_removed_on_dispose()
    {
        string path;
        using (var directory = UiTestOwnedDirectory.Create())
        {
            path = directory.Path;
            Assert.True(Path.IsPathFullyQualified(path));
            Assert.True(Directory.Exists(path));
            Assert.StartsWith("SSA-UI-", Path.GetFileName(path), StringComparison.Ordinal);
            File.WriteAllText(Path.Combine(path, "window.json"), "synthetic");
        }

        Assert.False(Directory.Exists(path));
    }
}
