namespace CodeSignAuto.Agent.Tests;

internal static class TestPaths
{
    private static readonly string ControlledRoot = Path.Combine(
        Path.GetTempPath(),
        "CodeSignAuto.Tests",
        "controlled");

    public static string Controlled(string fileName) =>
        Path.GetFullPath(Path.Combine(ControlledRoot, fileName));
}
