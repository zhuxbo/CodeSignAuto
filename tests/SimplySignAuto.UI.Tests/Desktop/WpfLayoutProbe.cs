#if SIMPLYSIGN_WPF
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Testing;
using SimplySignAuto.App.UI.ViewModels;

namespace SimplySignAuto.UI.Tests.Desktop;

internal sealed record WpfPageLayoutResult(
    string Page,
    bool NavigationVisible,
    bool TitleVisible,
    bool PrimaryActionReachable,
    bool StatusAreaReachable,
    bool RectanglesFiniteAndNonNegative,
    bool FixedChromeOverlapsContent,
    bool NamedControlsInsideClient,
    bool NamedControlsDoNotOverlap,
    bool PrimaryActionNestedInStatus,
    bool PrimaryActionContainmentValid,
    bool NoHorizontalClipping,
    bool VerticalScrollReachable,
    bool RenderHasNonEmptyPixels,
    bool NamedRegionsHaveNonEmptyPixels);

internal sealed record WpfLayoutResult(
    int Dpi,
    IReadOnlyList<WpfPageLayoutResult> Pages,
    int ContentScrollViewerCount);

internal static class WpfLayoutProbe
{
    private static readonly IReadOnlyDictionary<string, PageLayoutSpec> PageSpecifications =
        new Dictionary<string, PageLayoutSpec>(StringComparer.Ordinal)
        {
            ["概览"] = new("退出", "SimplySign 状态面板"),
            ["快速签名"] = new("选择本机签名文件", "快速签名状态区"),
            ["签名任务"] = new("刷新签名任务", "签名任务状态区"),
            ["激活凭证"] = new("导入 Certum 激活内容", "激活状态区"),
            ["服务设置"] = new("修改", "服务设置状态区"),
        };

    private static readonly Lazy<Task<Dispatcher>> ProbeDispatcher = new(StartDispatcher);

    public static async Task<WpfLayoutResult> RenderAsync(
        int dpi,
        UiClientSize size,
        string stateCode)
    {
        var dispatcher = await ProbeDispatcher.Value;
        return await dispatcher.InvokeAsync(
            () => RenderOnDispatcher(dpi, size, stateCode),
            DispatcherPriority.Send);
    }

    private static WpfLayoutResult RenderOnDispatcher(int dpi, UiClientSize size, string stateCode)
    {
        Assert.Contains(dpi, new[] { 96, 120, 144, 192 });
        Assert.True(UiTestState.TryParse(stateCode, out var state));
        using var services = UiTestDesktopServices.Create(state!);
        using var clipboard = new UiTestClipboardService();
        using var ownedDirectory = UiTestOwnedDirectory.Create();
        var placementStore = new WindowPlacementStore(
            Path.Combine(ownedDirectory.Path, "window.json"),
            new EmptyScreenWorkAreaSource());
        var window = new MainWindow(placementStore)
        {
            Width = size.Width,
            Height = size.Height,
        };
        window.Resources["BooleanToVisibilityConverter"] = new BooleanToVisibilityConverter();
        window.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = ThemeResourceUris.For(ShellTheme.Light),
        });
        window.Resources.MergedDictionaries.Add(new ResourceDictionary
        {
            Source = new Uri(
                "/SimplySignAuto;component/UI/Themes/Controls.xaml",
                UriKind.Relative),
        });
        using var viewModel = new ShellViewModel(
            services.Management,
            services.LocalJobs,
            services.Configuration,
            new DenyConfirmation(),
            window,
            new NoopLifetime(),
            new InlineDispatcher(),
            terminalJobs: null,
            clipboard);
        window.Initialize(viewModel);
        window.Show();
        window.UpdateLayout();
        var results = new List<WpfPageLayoutResult>();
        foreach (var page in viewModel.Pages)
        {
            var specification = PageSpecifications[page.Title];
            viewModel.CurrentPage = page;
            var physical = UiWindowGeometry.ToPhysical(size, dpi);
            window.Measure(new System.Windows.Size(size.Width, size.Height));
            window.Arrange(new Rect(0, 0, size.Width, size.Height));
            window.UpdateLayout();
            var navigation = (FrameworkElement?)window.FindName("NavigationList");
            var header = (FrameworkElement?)window.FindName("FixedHeader");
            var scroller = (ScrollViewer?)window.FindName("PageContentScroller");
            var title = Descendants<TextBlock>(window)
                .FirstOrDefault(text => text.IsVisible && text.Text == page.Title);
            var action = FindNamed<System.Windows.Controls.Button>(window, specification.PrimaryAction);
            var status = FindNamed<Border>(window, specification.StatusArea);
            var fixedOverlap = header is not null && scroller is not null &&
                Bounds(header, window).IntersectsWith(Bounds(scroller, window));
            var actionReachable = BringIntoViewport(action, scroller, window);
            var actionInside = IsInside(action, window);
            var actionHorizontal = IsHorizontallyInside(action, scroller, window);
            var actionRender = InspectRender(
                window,
                physical,
                dpi,
                [navigation, header, action]);
            var statusReachable = BringIntoViewport(status, scroller, window);
            var statusInside = IsInside(status, window);
            var statusHorizontal = IsHorizontallyInside(status, scroller, window);
            var statusRender = InspectRender(
                window,
                physical,
                dpi,
                [navigation, header, status]);
            FrameworkElement?[] contentElements = [title, action, status];
            var presentContentElements = contentElements.Where(element => element is not null)
                .Select(element => element!)
                .ToArray();
            var independentContentPairs = presentContentElements
                .SelectMany((left, index) => presentContentElements.Skip(index + 1).Select(right => (left, right)))
                .Where(pair => !IsAncestorOf(pair.left, pair.right) && !IsAncestorOf(pair.right, pair.left));
            var primaryActionNestedInStatus = action is not null && status is not null && IsAncestorOf(status, action);
            var primaryActionContainmentValid = action is not null && status is not null &&
                !IsAncestorOf(action, status) &&
                (!primaryActionNestedInStatus || Contains(Bounds(status, window), Bounds(action, window)));
            var namedControlsDoNotOverlap = navigation is not null && header is not null && scroller is not null &&
                !Bounds(navigation, window).IntersectsWith(Bounds(header, window)) &&
                !Bounds(navigation, window).IntersectsWith(Bounds(scroller, window)) &&
                !Bounds(header, window).IntersectsWith(Bounds(scroller, window)) &&
                independentContentPairs.All(pair =>
                    !Bounds(pair.left, window).IntersectsWith(Bounds(pair.right, window)));
            var contentOverflowsVertically = scroller is not null && scroller.ExtentHeight > scroller.ViewportHeight + 0.5;
            results.Add(new WpfPageLayoutResult(
                page.Title,
                IsInside(navigation, window),
                IsInside(title, window),
                actionReachable,
                statusReachable,
                Descendants<FrameworkElement>(window).Where(element => element.IsVisible).All(IsFinite),
                fixedOverlap,
                IsInside(navigation, window) && IsInside(header, window) && actionInside && statusInside,
                namedControlsDoNotOverlap,
                primaryActionNestedInStatus,
                primaryActionContainmentValid,
                actionHorizontal && statusHorizontal && IsHorizontallyInside(title, scroller, window),
                actionReachable && statusReachable &&
                    (!contentOverflowsVertically || scroller?.ComputedVerticalScrollBarVisibility == Visibility.Visible),
                actionRender.HasNonEmptyPixels && statusRender.HasNonEmptyPixels,
                actionRender.NamedRegionsHavePixels && statusRender.NamedRegionsHavePixels));
        }

        var contentScrollers = Descendants<ScrollViewer>(window).Count(scroll =>
            string.Equals(
                System.Windows.Automation.AutomationProperties.GetName(scroll),
                "页面内容",
                StringComparison.Ordinal));
        window.PrepareForShutdown();
        window.Close();
        return new WpfLayoutResult(dpi, results, contentScrollers);
    }

    private static T? FindNamed<T>(DependencyObject root, string automationName)
        where T : FrameworkElement =>
        Descendants<T>(root).FirstOrDefault(element =>
            element.IsVisible && string.Equals(
                System.Windows.Automation.AutomationProperties.GetName(element),
                automationName,
                StringComparison.Ordinal));

    private static bool BringIntoViewport(
        FrameworkElement? element,
        ScrollViewer? scroller,
        FrameworkElement window)
    {
        if (element is null || scroller is null || !element.IsVisible)
        {
            return false;
        }

        element.BringIntoView();
        window.UpdateLayout();
        var bounds = Bounds(element, window);
        var viewport = Bounds(scroller, window);
        return IsInside(element, window) &&
            bounds.Left >= viewport.Left - 0.5 && bounds.Right <= viewport.Right + 0.5 &&
            bounds.Top >= viewport.Top - 0.5 && bounds.Bottom <= viewport.Bottom + 0.5;
    }

    private static bool IsHorizontallyInside(
        FrameworkElement? element,
        ScrollViewer? scroller,
        FrameworkElement window)
    {
        if (element is null || scroller is null || !element.IsVisible)
        {
            return false;
        }

        var bounds = Bounds(element, window);
        var viewport = Bounds(scroller, window);
        return bounds.Left >= viewport.Left - 0.5 && bounds.Right <= viewport.Right + 0.5;
    }

    private static bool IsAncestorOf(DependencyObject ancestor, DependencyObject descendant)
    {
        for (var current = VisualTreeHelper.GetParent(descendant); current is not null; current = VisualTreeHelper.GetParent(current))
        {
            if (ReferenceEquals(current, ancestor))
            {
                return true;
            }
        }

        return false;
    }

    private static bool Contains(Rect outer, Rect inner) =>
        inner.Left >= outer.Left - 0.5 && inner.Top >= outer.Top - 0.5 &&
        inner.Right <= outer.Right + 0.5 && inner.Bottom <= outer.Bottom + 0.5;

    private static RenderEvidence InspectRender(
        FrameworkElement window,
        UiClientSize physical,
        int dpi,
        IReadOnlyList<FrameworkElement?> regions)
    {
        var width = checked((int)physical.Width);
        var height = checked((int)physical.Height);
        var bitmap = new RenderTargetBitmap(width, height, dpi, dpi, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var stride = checked(width * 4);
        var pixels = new byte[checked(stride * height)];
        bitmap.CopyPixels(pixels, stride, 0);
        var hasNonEmptyPixels = false;
        for (var offset = 0; offset < pixels.Length; offset += 4)
        {
            if (pixels[offset + 3] != 0 &&
                (pixels[offset] != 0 || pixels[offset + 1] != 0 || pixels[offset + 2] != 0))
            {
                hasNonEmptyPixels = true;
                break;
            }
        }

        var scale = dpi / (double)UiWindowGeometry.BaseDpi;
        var namedRegionsHavePixels = regions.All(region =>
            region is not null && RegionHasVisibleVariation(
                pixels,
                width,
                height,
                stride,
                Bounds(region, window),
                scale));
        return new RenderEvidence(hasNonEmptyPixels, namedRegionsHavePixels);
    }

    private static bool RegionHasVisibleVariation(
        byte[] pixels,
        int width,
        int height,
        int stride,
        Rect logicalBounds,
        double scale)
    {
        var left = Math.Clamp((int)Math.Floor(logicalBounds.Left * scale), 0, width - 1);
        var top = Math.Clamp((int)Math.Floor(logicalBounds.Top * scale), 0, height - 1);
        var right = Math.Clamp((int)Math.Ceiling(logicalBounds.Right * scale), left + 1, width);
        var bottom = Math.Clamp((int)Math.Ceiling(logicalBounds.Bottom * scale), top + 1, height);
        uint? first = null;
        for (var y = top; y < bottom; y++)
        {
            for (var x = left; x < right; x++)
            {
                var offset = (y * stride) + (x * 4);
                if (pixels[offset + 3] == 0)
                {
                    continue;
                }

                var color = BitConverter.ToUInt32(pixels, offset);
                if (first is null)
                {
                    first = color;
                }
                else if (first.Value != color)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsInside(FrameworkElement? element, FrameworkElement ancestor)
    {
        if (element is null || !element.IsVisible)
        {
            return false;
        }

        var bounds = Bounds(element, ancestor);
        var client = new Rect(0, 0, ancestor.ActualWidth, ancestor.ActualHeight);
        return IsFinite(element) && client.IntersectsWith(bounds) &&
            bounds.Left >= -0.5 && bounds.Top >= -0.5 &&
            bounds.Right <= client.Right + 0.5 && bounds.Bottom <= client.Bottom + 0.5;
    }

    private static bool IsFinite(FrameworkElement element) =>
        double.IsFinite(element.ActualWidth) && double.IsFinite(element.ActualHeight) &&
        element.ActualWidth >= 0 && element.ActualHeight >= 0;

    private static Rect Bounds(FrameworkElement element, FrameworkElement ancestor)
    {
        var point = element.TransformToAncestor(ancestor).Transform(new System.Windows.Point());
        return new Rect(point, new System.Windows.Size(element.ActualWidth, element.ActualHeight));
    }

    private static IEnumerable<T> Descendants<T>(DependencyObject root)
        where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(root); index++)
        {
            var child = VisualTreeHelper.GetChild(root, index);
            if (child is T match)
            {
                yield return match;
            }

            foreach (var descendant in Descendants<T>(child))
            {
                yield return descendant;
            }
        }
    }

    private static Task<Dispatcher> StartDispatcher()
    {
        var ready = new TaskCompletionSource<Dispatcher>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                ready.TrySetResult(Dispatcher.CurrentDispatcher);
                Dispatcher.Run();
            }
            catch (Exception error)
            {
                ready.TrySetException(error);
            }
        })
        {
            IsBackground = true,
            Name = "SimplySignAuto DPI layout probe",
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return ready.Task;
    }

    private sealed record PageLayoutSpec(string PrimaryAction, string StatusArea);

    private readonly record struct RenderEvidence(bool HasNonEmptyPixels, bool NamedRegionsHavePixels);

    private sealed class InlineDispatcher : IUiDispatcher
    {
        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }

    private sealed class NoopLifetime : IDesktopAgentLifetime
    {
        public Task StopAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    private sealed class DenyConfirmation : IReloginConfirmation
    {
        public Task<bool> ConfirmAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(false);
        }
    }
}
#endif
