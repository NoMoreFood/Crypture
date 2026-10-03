using System;
using System.Linq;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Ribbon;
using Crypture;
using Microsoft.Win32;

internal static partial class RegressionTests
{
    private static void TestPrivacyConcealment(ItemEditor oEditor)
    {
        oEditor.Left = oEditor.Top = -20000;
        oEditor.WindowStartupLocation = WindowStartupLocation.Manual;
        oEditor.ShowActivated = oEditor.ShowInTaskbar = false;
        oEditor.Show();
        PumpUntil(() => oEditor.IsLoaded);
        Border oShield = (Border)oEditor.FindName("oPrivacyShield");
        TextBox oContent = (TextBox)oEditor.FindName("oItemData");
        Ribbon oRibbon = (Ribbon)oEditor.FindName("ribbon");
        DockPanel oPanels = (DockPanel)oEditor.FindName("oEditorPanels");
        Button oReveal = (Button)oEditor.FindName("oRevealButton");
        FieldInfo oChanges = typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic);

        // A saved clean item clears plaintext before the shield can be removed.
        oEditor.SetEditingControls(true);
        oContent.Text = "Saved secret awaiting concealment";
        byte[] oBuffer = [5, 6, 7];
        oEditor.BinaryItemData = oBuffer;
        oChanges.SetValue(oEditor, false);
        MethodInfo oSessionSwitch = typeof(App).GetMethod("OnSessionSwitch",
            BindingFlags.Static | BindingFlags.NonPublic);
        oSessionSwitch.Invoke(null, [null, new SessionSwitchEventArgs(SessionSwitchReason.SessionUnlock)]);
        Check(oShield.Visibility == Visibility.Collapsed, "Session unlock leaves an active editor unchanged");
        oSessionSwitch.Invoke(null, [null, new SessionSwitchEventArgs(SessionSwitchReason.SessionLock)]);
        PumpUntil(() => oShield.Visibility == Visibility.Visible);
        oEditor.UpdateLayout();
        Grid oRoot = (Grid)oEditor.Content;
        Check(oShield.Visibility == Visibility.Visible && !oRibbon.IsEnabled && !oPanels.IsEnabled &&
            oPanels.Visibility == Visibility.Collapsed &&
            oShield.ActualWidth >= oRoot.ActualWidth - 1 && oShield.ActualHeight >= oRoot.ActualHeight - 1 &&
            oContent.Text.Length == 0 && oEditor.BinaryItemData == null && oBuffer.All(b => b == 0),
            "Concealing a saved item covers the editor and clears decrypted text and binary data");
        oReveal.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Check(oShield.Visibility == Visibility.Collapsed && oPanels.Visibility == Visibility.Visible &&
            !oContent.IsEnabled,
            "Reveal returns a cleared saved item to its locked state");

        // Preserve unsaved edits behind the disabled shield until explicitly revealed.
        oEditor.SetEditingControls(true);
        oContent.Text = "Unsaved draft that must remain available";
        App.ConcealOpenSecrets();
        Check(oShield.Visibility == Visibility.Visible && !oRibbon.IsEnabled && !oPanels.IsEnabled &&
            oPanels.Visibility == Visibility.Collapsed &&
            oContent.Text == "Unsaved draft that must remain available" &&
            ((TextBlock)oEditor.FindName("oPrivacyMessage")).Text.Contains("Unsaved edits"),
            "Concealing an unsaved editor hides input while preserving the draft");
        oReveal.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
        Check(oShield.Visibility == Visibility.Collapsed && oPanels.Visibility == Visibility.Visible &&
            oContent.IsEnabled &&
            oContent.Text == "Unsaved draft that must remain available",
            "Reveal restores the unsaved editor and its text");
        oChanges.SetValue(oEditor, false);

        string sConnection = CryptureEntities.ConnectionString;
        CryptureEntities.ConnectionString = "";
        PasswordGenerator oGenerator = null;
        try
        {
            oGenerator = new PasswordGenerator
            {
                Width = 520, Height = 600, Left = -20000, Top = -20000,
                WindowStartupLocation = WindowStartupLocation.Manual,
                ShowActivated = false, ShowInTaskbar = false
            };
            oGenerator.Show();
            PumpUntil(() => oGenerator.IsLoaded);
            typeof(PasswordGenerator).GetMethod("oGenerateButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oGenerator, [null, null]);
            TextBox oPassword = (TextBox)oGenerator.FindName("oGeneratedPassword");
            string sPassword = oPassword.Text;
            Border oGeneratorShield = (Border)oGenerator.FindName("oPrivacyShield");
            App.ConcealOpenSecrets();
            oGenerator.UpdateLayout();
            Grid oGeneratorRoot = (Grid)oGenerator.Content;
            Check(sPassword.Length > 0 && oGeneratorShield.Visibility == Visibility.Visible &&
                oGeneratorShield.ActualWidth >= oGeneratorRoot.ActualWidth - 1 &&
                oGeneratorShield.ActualHeight >= oGeneratorRoot.ActualHeight - 1 &&
                !((ScrollViewer)oGenerator.FindName("oGeneratorContent")).IsEnabled &&
                ((ScrollViewer)oGenerator.FindName("oGeneratorContent")).Visibility == Visibility.Collapsed &&
                !((StackPanel)oGenerator.FindName("oGeneratorActions")).IsEnabled &&
                ((StackPanel)oGenerator.FindName("oGeneratorActions")).Visibility == Visibility.Collapsed &&
                oPassword.Text == sPassword,
                "Generated passwords remain available behind a full-window disabled shield");
            ((Button)oGenerator.FindName("oRevealButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            Check(oGeneratorShield.Visibility == Visibility.Collapsed &&
                ((ScrollViewer)oGenerator.FindName("oGeneratorContent")).Visibility == Visibility.Visible &&
                oPassword.IsEnabled &&
                oPassword.Text == sPassword,
                "Reveal restores the generated password and its controls");
        }
        finally
        {
            oGenerator?.Close();
            CryptureEntities.ConnectionString = sConnection;
        }
    }
}
