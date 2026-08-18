namespace SimplySignAuto.App.UI;

public sealed record NavigationPage(
    string Title,
    string Icon,
    string PlaceholderText,
    object? Content = null);
