using CodeSignAuto.Core.Security;
using Xunit;

namespace CodeSignAuto.Core.Tests;

public sealed class NoFollowFileTests
{
    [Fact]
    public void Path_entry_inspection_reports_a_dangling_reparse_without_following_its_target()
    {
        var root = Path.Combine(Path.GetTempPath(), "CodeSignAuto-nofollow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var missingTarget = Path.Combine(root, "missing-target");
            var link = Path.Combine(root, "dangling-link");
            File.CreateSymbolicLink(link, missingTarget);

            var kind = NoFollowFile.InspectPathEntry(link);

            Assert.Equal(NoFollowPathEntryKind.ReparsePoint, kind);
            Assert.False(File.Exists(missingTarget));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Path_entry_inspection_distinguishes_a_missing_entry_from_a_regular_file()
    {
        var root = Path.Combine(Path.GetTempPath(), "CodeSignAuto-nofollow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var missing = Path.Combine(root, "missing.part");
            var regular = Path.Combine(root, "input.part");
            File.WriteAllText(regular, "controlled");

            Assert.Equal(NoFollowPathEntryKind.Missing, NoFollowFile.InspectPathEntry(missing));
            Assert.Equal(NoFollowPathEntryKind.RegularFile, NoFollowFile.InspectPathEntry(regular));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
