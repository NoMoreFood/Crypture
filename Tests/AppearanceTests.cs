using System;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Media;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestSecretFonts(ItemBrowser oBrowser)
    {
        string sOriginal = Crypture.Properties.Settings.Default.SecretFontFamily;
        ItemEditor oEditor = null;
        ItemEditor oLocked = null;
        PasswordGenerator oGenerator = null;
        try
        {
            // Exercise a live preference across all windows without changing secret content or Vault options.
            Crypture.Properties.Settings.Default.SecretFontFamily = "Consolas";
            oEditor = new ItemEditor();
            oLocked = new ItemEditor(false);
            oGenerator = new PasswordGenerator(true);
            TextBox oContent = (TextBox)oEditor.FindName("oItemData");
            TextBox oLockedContent = (TextBox)oLocked.FindName("oItemData");
            TextBox oPassword = (TextBox)oGenerator.FindName("oGeneratedPassword");
            oContent.Text = "I l 1 O 0 o |: font changes preserve this unsaved secret.";
            oContent.Select(3, 7);
            FieldInfo oChanged = typeof(ItemEditor).GetField("bHasChanges",
                BindingFlags.Instance | BindingFlags.NonPublic);
            oChanged.SetValue(oEditor, false);
            ((Button)oGenerator.FindName("oGenerateButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            string sPassword = oPassword.Text;
            string sStatus = ((TextBlock)oGenerator.FindName("oPasswordStatus")).Text;
            ShowTestWindow(oEditor);
            ShowTestWindow(oLocked);
            ShowTestWindow(oGenerator);
            ((System.Windows.Controls.Ribbon.RibbonTab)oBrowser.FindName("oViewTab")).IsSelected = true;
            Application.Current.Dispatcher.Invoke(() => { },
                System.Windows.Threading.DispatcherPriority.ApplicationIdle);
            SecretFontSelector oEditorFont = (SecretFontSelector)oEditor.FindName("oSecretFontSelector");
            SecretFontSelector oGeneratorFont = (SecretFontSelector)oGenerator.FindName("oSecretFontSelector");
            SecretFontSelector oBrowserFont = (SecretFontSelector)oBrowser.FindName("oSecretFontSelector");
            Check(oContent.FontFamily.Source == "Consolas" && oPassword.FontFamily.Source == "Consolas" &&
                ((FontFamily)oEditorFont.SelectedItem).Source == "Consolas", "Secret fields default to Consolas");
            Check(typeof(Crypture.Properties.Settings).GetProperty("SecretFontFamily")
                .GetCustomAttribute<DefaultSettingValueAttribute>().Value == "Consolas",
                "The portable executable includes a Consolas default without a config file");
            string[] oNames = oEditorFont.Items.Cast<FontFamily>().Select(f => f.Source).ToArray();
            Check(oNames.Contains("Consolas") && oNames.SequenceEqual(oNames.Order(StringComparer.OrdinalIgnoreCase)) &&
                !oEditorFont.IsEditable, "Font choices contain sorted installed Windows fonts");
            FontFamily oArial = oEditorFont.Items.Cast<FontFamily>().Single(f => f.Source == "Arial");
            oEditorFont.SetCurrentValue(Selector.SelectedItemProperty, oArial);
            PumpUntil(() => oContent.FontFamily.Source == "Arial" && oPassword.FontFamily.Source == "Arial");
            Check(((FontFamily)oGeneratorFont.SelectedItem).Source == "Arial" &&
                ((FontFamily)oBrowserFont.SelectedItem).Source == "Arial",
                "Selecting a font updates every open selector");
            Check(((TextBox)oGenerator.FindName("oSymbolCharacters")).FontFamily.Source == "Arial" &&
                ((TextBox)oGenerator.FindName("oExcludedCharacters")).FontFamily.Source == "Arial",
                "Password character fields use the chosen secret font");
            Check(oContent.Text == "I l 1 O 0 o |: font changes preserve this unsaved secret." &&
                oContent.SelectionStart == 3 && oContent.SelectionLength == 7 && !(bool)oChanged.GetValue(oEditor),
                "Changing the font preserves secret text and selection without marking the item changed");
            Check(oPassword.Text == sPassword && ((TextBlock)oGenerator.FindName("oPasswordStatus")).Text == sStatus &&
                ((Button)oGenerator.FindName("oCopyButton")).IsEnabled &&
                ((Button)oGenerator.FindName("oInsertButton")).IsEnabled,
                "Changing the font preserves the generated password and copy and insertion actions");
            Check(!oLockedContent.IsEnabled && oLockedContent.Visibility == Visibility.Collapsed &&
                oLockedContent.Text.Length == 0 && oLockedContent.FontFamily.Source == "Arial",
                "Font changes preserve the locked editor state");
            var oSaved = new Crypture.Properties.Settings();
            oSaved.Reload();
            Check(oSaved.SecretFontFamily == "Arial", "The selected secret font persists for the Windows profile");
            FontFamily oConsolas = oGeneratorFont.Items.Cast<FontFamily>().Single(f => f.Source == "Consolas");
            oGeneratorFont.SetCurrentValue(Selector.SelectedItemProperty, oConsolas);
            PumpUntil(() => oContent.FontFamily.Source == "Consolas");
            Check(BindingOperations.IsDataBound(oEditorFont, Selector.SelectedItemProperty) &&
                oPassword.FontFamily.Source == "Consolas",
                "Selecting a font in the generator updates existing editors");
            oBrowserFont.SetCurrentValue(Selector.SelectedItemProperty, oArial);
            PumpUntil(() => oContent.FontFamily.Source == "Arial");
            oGenerator.Close();
            oGenerator = new PasswordGenerator();
            Check(((TextBox)oGenerator.FindName("oGeneratedPassword")).FontFamily.Source == "Arial" &&
                ((FontFamily)((SecretFontSelector)oGenerator.FindName("oSecretFontSelector"))
                    .SelectedItem).Source == "Arial",
                "Reopened dialogs use the saved font preference");

            // Missing or invalid saved names cannot load an external font or change the Consolas fallback.
            SecretFontConverter oConverter = new SecretFontConverter();
            foreach (string sName in new[] { "", "Unknown Font Family",
                "file:///C:/missing.ttf#Font", "consolas", null })
                Check(((FontFamily)oConverter.Convert(sName, typeof(FontFamily), null, CultureInfo.InvariantCulture))
                    .Source == "Consolas", "Unavailable font preference falls back to Consolas: " + (sName ?? "null"));
        }
        finally
        {
            Crypture.Properties.Settings.Default.SecretFontFamily = sOriginal;
            Crypture.Properties.Settings.Default.Save();
            if (oEditor != null)
            {
                typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                    .SetValue(oEditor, false);
                oEditor.Close();
            }
            oLocked?.Close();
            oGenerator?.Close();
        }
    }
}
