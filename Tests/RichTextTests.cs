using System;
using System.IO;
using System.Linq;
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
        RichTextBox oCopySource = new RichTextBox();
        Utilities.EnableClipboardTimeout(oCopySource, s => true);
        Check(!System.Windows.Input.ApplicationCommands.Copy.CanExecute("All", oCopySource),
            "An empty rich text document disables whole-document copy");
        oCopySource.Document.Blocks.Add(new Paragraph(new Run("Secret")));
        Check(System.Windows.Input.ApplicationCommands.Copy.CanExecute("All", oCopySource),
            "A populated rich text document enables whole-document copy");
        oCopySource.Document.Blocks.Clear();
        oCopySource.Document.Blocks.Add(new Paragraph());
        Check(!System.Windows.Input.ApplicationCommands.Copy.CanExecute("All", oCopySource),
            "An empty rich text paragraph disables whole-document copy");
        oCopySource.Document.Blocks.Add(new Paragraph());
        Check(System.Windows.Input.ApplicationCommands.Copy.CanExecute("All", oCopySource),
            "Blank lines remain copyable in a rich text document");
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
            oDraft = CreateEditor();
            oDraft.Left = -20000;
            oDraft.Top = -20000;
            oDraft.WindowStartupLocation = WindowStartupLocation.Manual;
            oDraft.ShowActivated = false;
            oDraft.ShowInTaskbar = false;
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
            oDraft.oSaveItemButton_Click(null, new RoutedEventArgs());
            PumpUntil(() => !oDraft.IsVisible);
            oDraft = null;

            long nItemId;
            using (CryptureEntities oContext = new CryptureEntities())
                nItemId = oContext.Items.Single().ItemId;
            oSaved = CreateEditor(LoadItem(nItemId));
            oSaved.Left = -20000;
            oSaved.Top = -20000;
            oSaved.WindowStartupLocation = WindowStartupLocation.Manual;
            oSaved.ShowActivated = false;
            oSaved.ShowInTaskbar = false;
            oSaved.Show();
            PumpUntil(() => oSaved.IsLoaded);
            oSaved.oLoadItemButton_Click(null, new RoutedEventArgs());
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
                oDraft.bHasChanges = false;
                oDraft.Close();
            }
            oSaved?.Close();
            CryptureEntities.ConnectionString = sPreviousConnection;
            SynchronizationContext.SetSynchronizationContext(oPreviousContext);
        }
    }
}
