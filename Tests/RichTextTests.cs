using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Ribbon;
using System.Windows.Documents;
using System.Windows.Threading;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestRichTextVaultRoundTrip(string sDirectory)
    {
        string sPreviousConnection = CryptureEntities.ConnectionString;
        string sVault = Path.Combine(sDirectory, "rich-text.cryptdb");
        DatabaseOperations.CreateDatabase(sVault,
            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
        CryptureEntities.DatabasePath = sVault;
        SynchronizationContext oPreviousContext = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext());
        ItemEditor oDraft = null, oSaved = null;
        try
        {
            // Save formatted content through the editor and reopen the encrypted Vault item.
            oDraft = new ItemEditor
            {
                Left = -20000, Top = -20000, WindowStartupLocation = WindowStartupLocation.Manual,
                ShowActivated = false, ShowInTaskbar = false
            };
            oDraft.Show();
            PumpUntil(() => oDraft.IsLoaded && oDraft.CertificateLoading.IsCompleted);
            ((TextBox)oDraft.FindName("oItemLabel")).Text = "Saved rich text";
            ((ComboBox)oDraft.FindName("oItemTypeSelector")).SelectedIndex = 1;
            ((ComboBox)oDraft.FindName("oProtectionMode")).SelectedIndex = 0;
            ((ComboBox)oDraft.FindName("oPrincipalScope")).SelectedIndex = 1;
            RichTextBox oContent = (RichTextBox)oDraft.FindName("oRichItemData");
            oContent.Document.Blocks.Clear();
            Paragraph oParagraph = new Paragraph { Margin = new Thickness(0) };
            oParagraph.Inlines.Add(new Run("Formatted") { FontWeight = FontWeights.Bold });
            oParagraph.Inlines.Add(new Run(" secret"));
            oContent.Document.Blocks.Add(oParagraph);
            Check(((RibbonButton)oDraft.FindName("oSaveItemButton")).IsEnabled,
                "A rich text item can be saved with Windows user protection");
            typeof(ItemEditor).GetMethod("oSaveItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oDraft, [null, new RoutedEventArgs()]);
            PumpUntil(() => !oDraft.IsVisible);
            oDraft = null;

            long nItemId;
            using (CryptureEntities oContext = new CryptureEntities())
                nItemId = oContext.Items.Single().ItemId;
            oSaved = new ItemEditor(DatabaseOperations.LoadItem(nItemId))
            {
                Left = -20000, Top = -20000, WindowStartupLocation = WindowStartupLocation.Manual,
                ShowActivated = false, ShowInTaskbar = false
            };
            oSaved.Show();
            PumpUntil(() => oSaved.IsLoaded);
            typeof(ItemEditor).GetMethod("oLoadItemButton_Click", BindingFlags.Instance | BindingFlags.NonPublic)
                .Invoke(oSaved, [null, new RoutedEventArgs()]);
            RichTextBox oReopened = (RichTextBox)oSaved.FindName("oRichItemData");
            PumpUntil(() => oReopened.IsVisible);
            TextPointer oFirstText = oReopened.Document.ContentStart;
            while (oFirstText.GetPointerContext(LogicalDirection.Forward) != TextPointerContext.Text)
                oFirstText = oFirstText.GetNextContextPosition(LogicalDirection.Forward);
            object oWeight = new TextRange(oFirstText, oFirstText.GetPositionAtOffset(1))
                .GetPropertyValue(TextElement.FontWeightProperty);
            Check(oSaved.ThisItem.ItemType == "richtext" &&
                Utilities.GetRichText(oReopened) == "Formatted secret" &&
                oWeight is FontWeight nWeight && nWeight == FontWeights.Bold,
                "A rich text Vault item reopens with its content and formatting");
        }
        finally
        {
            if (oDraft != null)
            {
                typeof(ItemEditor).GetField("bHasChanges", BindingFlags.Instance | BindingFlags.NonPublic)
                    .SetValue(oDraft, false);
                oDraft.Close();
            }
            oSaved?.Close();
            CryptureEntities.ConnectionString = sPreviousConnection;
            SynchronizationContext.SetSynchronizationContext(oPreviousContext);
        }
    }
}
