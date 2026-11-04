using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Ribbon;
using System.Windows.Threading;
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

        // A saved clean item clears plaintext before the shield can be removed.
        oEditor.SetEditingControls(true);
        oContent.Text = "Saved secret awaiting concealment";
        byte[] oBuffer = [5, 6, 7];
        oEditor.BinaryItemData = oBuffer;
        oEditor.bHasChanges = false;
        App.OnSessionSwitch(null, new SessionSwitchEventArgs(SessionSwitchReason.SessionUnlock));
        Check(oShield.Visibility == Visibility.Collapsed, "Session unlock leaves an active editor unchanged");
        App.OnSessionSwitch(null, new SessionSwitchEventArgs(SessionSwitchReason.SessionLock));
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
        oEditor.bHasChanges = false;

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
            oGenerator.oGenerateButton_Click(null, null);
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

        // A modal editor action must finish before concealment can discard its input state.
        foreach (bool bInsert in new[] { true, false })
        {
            oReveal.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            oEditor.SetEditingControls(true);
            oContent.Text = "Saved prefix: ";
            oContent.Select(oContent.Text.Length, 0);
            oEditor.bHasChanges = false;
            Exception oFailure = null;
            string sInserted = null;
            Application.Current.Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() =>
            {
                PasswordGenerator oChild = oEditor.OwnedWindows.OfType<PasswordGenerator>().Single();
                try
                {
                    oChild.oGenerateButton_Click(null, null);
                    sInserted = ((TextBox)oChild.FindName("oGeneratedPassword")).Text;
                    App.ConcealOpenSecrets();
                    Check(oContent.Text == "Saved prefix: " && oShield.Visibility == Visibility.Visible,
                        "Concealment preserves the editor while its password generator is open");
                    ((Button)oChild.FindName("oRevealButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    if (bInsert)
                        ((Button)oChild.FindName("oInsertButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                }
                catch (Exception oError) { oFailure = oError; }
                finally { if (oChild.IsVisible) oChild.Close(); }
            }));
            try
            {
                ((RibbonButton)oEditor.FindName("oGeneratePasswordButton"))
                    .RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                if (oFailure != null) throw oFailure;
                Check(!oEditor.bBusy && oShield.Visibility == Visibility.Visible &&
                    (bInsert ? oEditor.bHasChanges && oContent.Text == "Saved prefix: " + sInserted
                        : !oEditor.bHasChanges && oContent.Text.Length == 0),
                    bInsert ? "A generated password remains an editable draft behind the privacy shield"
                        : "Cancelling the generator locks a concealed saved item after the dialog closes");
            }
            finally { oEditor.bHasChanges = false; }
        }
    }
}
