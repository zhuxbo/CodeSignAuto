#if CODESIGNAUTO_WPF
using System.Windows.Markup;

namespace CodeSignAuto.App.UI.Localization;

[MarkupExtensionReturnType(typeof(string))]
public sealed class UiStringExtension(string key) : MarkupExtension
{
    public string Key { get; } = key;

    public override object ProvideValue(IServiceProvider serviceProvider) => UiCulture.Text(Key);
}
#endif
