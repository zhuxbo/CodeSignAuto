using System.Reflection.PortableExecutable;
using CodeSignAuto.App;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class ApplicationHostContractTests
{
    [Fact]
    public void Main_application_uses_the_Windows_GUI_subsystem()
    {
        using var stream = File.OpenRead(typeof(ApplicationEntryRoute).Assembly.Location);
        using var pe = new PEReader(stream);

        Assert.Equal(Subsystem.WindowsGui, pe.PEHeaders.PEHeader?.Subsystem);
    }

    [Theory]
    [InlineData(0u, false, false)]
    [InlineData(1u, false, true)]
    [InlineData(2u, false, false)]
    [InlineData(2u, true, true)]
    [InlineData(3u, false, true)]
    public void Standard_output_requires_a_console_or_an_actual_redirected_file(
        uint fileType,
        bool consoleModeAvailable,
        bool expected)
    {
        Assert.Equal(
            expected,
            WindowsStandardIo.IsUsableOutput(fileType, consoleModeAvailable));
    }
}
