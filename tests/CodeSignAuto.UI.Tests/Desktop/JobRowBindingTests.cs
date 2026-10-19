#if CODESIGNAUTO_WPF
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using CodeSignAuto.App.UI.Views;
using CodeSignAuto.App.UI.ViewModels;
using CodeSignAuto.Protocol;

namespace CodeSignAuto.UI.Tests.Desktop;

public sealed class JobRowBindingTests
{
    [Fact]
    public async Task Job_row_renders_read_only_metadata()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                var view = new JobsView();
                var list = Descendants(view).OfType<ItemsControl>().Single();
                var row = (FrameworkElement)list.ItemTemplate.LoadContent();
                var now = DateTimeOffset.UtcNow;
                var item = new JobListItemViewModel(new JobPageItem(
                    Guid.NewGuid(), "api", "authenticode", "failed", "test.exe",
                    now, now, now, "authenticode_sign_failed", Guid.NewGuid(), false));
                row.DataContext = item;
                row.Measure(new System.Windows.Size(800, 300));
                row.Arrange(new Rect(0, 0, 800, 300));
                var text = Descendants(row).OfType<TextBlock>()
                    .SelectMany(block => block.Inlines.OfType<Run>()).Select(run => run.Text).ToArray();
                Assert.Contains(item.KindText, text);
                Assert.Contains(item.ErrorCode, text);
                Assert.Contains(item.CorrelationId.ToString(), text);
                completion.SetResult();
            }
            catch (Exception exception)
            {
                completion.SetException(exception);
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        foreach (var child in LogicalTreeHelper.GetChildren(parent).OfType<DependencyObject>())
        {
            yield return child;
            foreach (var descendant in Descendants(child))
                yield return descendant;
        }
    }
}
#endif
