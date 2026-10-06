using System.Windows.Controls.Ribbon;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;

namespace Crypture
{
    public partial class ItemEditor : Window
    {
        // Item format selector positions.
        private const int PlainTextTypeIndex = 0;
        private const int RichTextTypeIndex = 1;
        private const int TotpTypeIndex = 2;
        private const int FileTypeIndex = 3;

        // Encryption method selector positions.
        private const int UserProtectionIndex = 0;
        private const int CertificateProtectionIndex = 1;
        private const int FidoProtectionIndex = 2;

        // Windows principal scope selector positions.
        private const int DomainScopeIndex = 0;
        private const int LocalUserScopeIndex = 1;
        private const int LocalMachineScopeIndex = 2;

        // Principal matching selector positions.
        private const int AnyPrincipalIndex = 0;
        private const int AllPrincipalsIndex = 1;

        public Item ThisItem { get; set; } = new Item();
        public ObservableCollection<User> UserList { get; set; } = new ObservableCollection<User>();
        public ObservableCollection<User> UserListSelected { get; set; } = new ObservableCollection<User>();
        public byte[] BinaryItemData { get; set; }
        private bool bLoading = true;
        private bool bHasChanges;
        private bool bCompleted;
        private bool bBusy;
        private bool bEditing;
        private bool bLoadingCertificates;
        private bool bClosed;
        private readonly CancellationTokenSource oCertificateCancellation = new CancellationTokenSource();
        internal Task CertificateLoading { get; private set; } = Task.CompletedTask;
        private readonly bool bDpapiNgEnabled = Properties.Settings.Default.EnableDpapiNgProtection;
        private readonly bool bCertificatesEnabled = Properties.Settings.Default.EnableCertificateProtection;
        private readonly bool bFidoEnabled = Properties.Settings.Default.EnableFidoProtection &&
            !CryptureEntities.Storage.IsSqlServer && FidoNative.IsAvailable;
        private byte[] oFidoCredentialId;
        private readonly bool bDomainJoined = PrincipalProtection.IsDomainJoined;
        private readonly ObservableCollection<ProtectionPrincipal> PrincipalList =
            new ObservableCollection<ProtectionPrincipal>();
        private string sStoredLabel;
        private string sStoredItemType;
        private long? nStoredModifiedBy;
        private readonly bool bIncludeOwnCertificates = true;

        public ItemEditor(bool bNewItem = true)
        {
            // Apply configured choices only to new items; saved items supply their own settings.
            ConfigurationDefaults oDefaults = bNewItem ? new ConfigurationDefaults("NewItem") : null;
            ThisItem.Label = oDefaults?.Text("Label", "My New Item") ?? "My New Item";
            string sType = oDefaults?.Choice("Type", "Text", "Text", "RichText", "Totp", "File") ?? "Text";
            ThisItem.ItemType = sType == "RichText" ? "richtext" : sType == "Totp" ? "totp" : sType == "File" &&
                Properties.Settings.Default.ShowItemFileUpload ? "" : "text";
            string sProtection = oDefaults?.Choice("ProtectionMode", "Automatic",
                "Automatic", "UserBased", "CertificateBased", "Fido2") ?? "Automatic";
            string sScope = oDefaults?.Choice("WindowsScope", "Automatic",
                "Automatic", "Domain", "LocalUser", "LocalMachine") ?? "Automatic";
            bool bRequireAll = oDefaults?.Flag("RequireAllPrincipals", false) ?? false;
            bool bIncludeCurrentUser = oDefaults?.Flag("IncludeCurrentUser", true) ?? true;
            bIncludeOwnCertificates = oDefaults?.Flag("IncludeOwnCertificates", true) ?? true;
            DataContext = ThisItem;
            InitializeComponent();

            // Cancel pending certificate lookups when the editor closes.
            Closed += (s, e) =>
            {
                bClosed = true;
                oCertificateCancellation.Cancel();
                oCertificateCancellation.Dispose();
            };
            Utilities.EnableClipboardTimeout(oItemData);
            Utilities.EnableClipboardTimeout(oRichItemData);
            Utilities.EnableClipboardTimeout(oItemLabel);
            oTotpPanel.SettingsChanged += (s, e) =>
            {
                if (!bLoading && bEditing) bHasChanges = true;
            };

            // Sort recipient displays by the certificate name, including the templated list.
            oItemSharedWith.Items.IsLiveSorting = true;
            oItemSharedWith.Items.SortDescriptions.Add(
                new SortDescription(nameof(User.Name), ListSortDirection.Ascending));

            oAddCertDropDown.Items.IsLiveSorting = true;
            oAddCertDropDown.Items.SortDescriptions.Add(
                new SortDescription(nameof(User.Name), ListSortDirection.Ascending));

            // add in our keys by default
            if (bNewItem && bCertificatesEnabled) LoadUsers(true);
            bool bSqlWindowsProtection = !CryptureEntities.Storage.IsSqlServer || bDomainJoined;
            oDpapiNgProtection.IsEnabled = bDpapiNgEnabled && bSqlWindowsProtection;
            oDpapiNgProtection.Visibility = oDpapiNgProtection.IsEnabled
                ? Visibility.Visible : Visibility.Collapsed;
            oCertificateProtection.IsEnabled = bCertificatesEnabled;
            oCertificateProtection.Visibility = bCertificatesEnabled ? Visibility.Visible : Visibility.Collapsed;
            oFidoProtection.IsEnabled = bFidoEnabled;
            oFidoProtection.Visibility = bFidoEnabled ? Visibility.Visible : Visibility.Collapsed;
            oPrincipalList.ItemsSource = PrincipalList;
            oDomainScope.IsEnabled = bDomainJoined;
            oPrincipalScope.SelectedIndex = !bDomainJoined || String.Equals(Environment.UserDomainName,
                Environment.MachineName, StringComparison.OrdinalIgnoreCase) ? LocalUserScopeIndex : DomainScopeIndex;
            if (bNewItem)
            {
                if (sScope != "Automatic") oPrincipalScope.SelectedIndex = sScope == "LocalMachine"
                    ? LocalMachineScopeIndex : sScope == "Domain" && bDomainJoined ? DomainScopeIndex
                    : LocalUserScopeIndex;
                oPrincipalMatch.SelectedIndex = bRequireAll ? AllPrincipalsIndex : AnyPrincipalIndex;
                if (bIncludeCurrentUser)
                    PrincipalList.Add(new ProtectionPrincipal(CertificateOperations.CurrentUserSid));
                oProtectionMode.SelectedIndex = bCertificatesEnabled &&
                    (!bDpapiNgEnabled || CertificateOperations.GetAutomaticCertificates().Count != 0)
                    ? CertificateProtectionIndex : bDpapiNgEnabled ? UserProtectionIndex :
                    bFidoEnabled ? FidoProtectionIndex : -1;
                if (sProtection == "CertificateBased" && bCertificatesEnabled)
                    oProtectionMode.SelectedIndex = CertificateProtectionIndex;
                else if (sProtection == "UserBased" && bDpapiNgEnabled &&
                    CertificateOperations.GetAutomaticCertificates().Count == 0)
                    oProtectionMode.SelectedIndex = UserProtectionIndex;
                else if (sProtection == "Fido2" && bFidoEnabled)
                    oProtectionMode.SelectedIndex = FidoProtectionIndex;
            }
            if (CryptureEntities.Storage.IsSqlServer)
            {
                oLocalUserScope.IsEnabled = false;
                oLocalMachineScope.IsEnabled = false;
                oPrincipalScope.SelectedIndex = bDomainJoined ? DomainScopeIndex : -1;
                if (!bDomainJoined && oProtectionMode.SelectedIndex == UserProtectionIndex)
                    oProtectionMode.SelectedIndex = bCertificatesEnabled ? CertificateProtectionIndex : -1;
            }

            // show certificate generator based on settings file
            oUploadAFile.Visibility = Properties.Settings.Default.ShowItemFileUpload
                ? Visibility.Visible : Visibility.Collapsed;

            // set editing controls
            SetEditingControls(bNewItem);
            bLoading = false;
        }

        public ItemEditor(Item oItem) : this(false)
        {
            ThisItem = DatabaseOperations.LoadItem(oItem.ItemId);
            sStoredLabel = ThisItem.Label;
            sStoredItemType = ThisItem.ItemType;
            nStoredModifiedBy = ThisItem.ModifiedBy;
            DataContext = ThisItem;
            LoadUsers(false);
            LoadProtection();
            SetEditingControls(false);
        }

        private void LoadUsers(bool bNewItem)
        {
            using (CryptureEntities oContent = new CryptureEntities())
                UserList = new ObservableCollection<User>(oContent.Users.ToList());
            List<byte[]> oAutomatic = CertificateOperations.GetAutomaticCertificates();

            // Filter new choices while retaining saved and administrator-required recipients.
            UserListSelected = new ObservableCollection<User>(UserList.Where(u => bNewItem
                ? oAutomatic.Any(c => c.SequenceEqual(u.Certificate))
                : ThisItem.Instances.Any(i => i.UserId == u.UserId)));
            oItemSharedWith.ItemsSource = UserListSelected;
            oAddCertDropDown.ItemsSource = UserListSelected.ToList();
            bLoadingCertificates = true;
            oCertificateUsageNotice.Text = "Checking recipient certificates...";
            oCertificateUsageNotice.Visibility = Visibility.Visible;
            CertificateLoading = Dispatcher.InvokeAsync(() => LoadCertificateChoices(bNewItem, oAutomatic))
                .Task.Unwrap();
        }

        private async Task LoadCertificateChoices(bool bNewItem, List<byte[]> oAutomatic)
        {
            if (bClosed) return;
            CancellationToken oToken = oCertificateCancellation.Token;
            try
            {
                CertificateUsageFilter oUsageFilter = null;
                string sNotice = null;
                try
                {
                    oUsageFilter = CertificateUsageFilter.Read();
                }
                catch (ConfigurationErrorsException oError)
                {
                    sNotice = oError.Message;
                }
                List<User> oUsers = UserList.ToList();

                // Chain building may fetch issuers and revocation data; keep it off the dispatcher.
                var (oAvailable, oPrivateCertificates) = await Task.Run(() =>
                {
                    HashSet<string> oPrivate = CertificateOperations.GetPrivateCertificateData();
                    HashSet<long> oChoices = new HashSet<long>();
                    foreach (User oUser in oUsers)
                    {
                        oToken.ThrowIfCancellationRequested();
                        if (oAutomatic.Any(c => c.SequenceEqual(oUser.Certificate)) ||
                            CertificateOperations.CanSelectCertificate(oUser.Certificate, oUsageFilter))
                            oChoices.Add(oUser.UserId);
                    }
                    return (oChoices, oPrivate);
                }, oToken);
                if (bClosed) return;
                if (bNewItem)
                {
                    foreach (User oUser in oUsers.Where(u => bIncludeOwnCertificates && oAvailable.Contains(u.UserId) &&
                        oPrivateCertificates.Contains(Convert.ToBase64String(u.Certificate))))
                        if (!UserListSelected.Contains(oUser)) UserListSelected.Add(oUser);
                    ThisItem.ModifiedBy = UserListSelected.FirstOrDefault(u =>
                        oPrivateCertificates.Contains(Convert.ToBase64String(u.Certificate)))?.UserId;
                }
                oAddCertDropDown.ItemsSource = oUsers.Where(u => oAvailable.Contains(u.UserId) ||
                    UserListSelected.Contains(u)).ToList();
                oCertificateUsageNotice.Text = sNotice;
                oCertificateUsageNotice.Visibility = sNotice == null ? Visibility.Collapsed : Visibility.Visible;
            }
            catch (OperationCanceledException) when (oToken.IsCancellationRequested) { }
            catch (Exception oError)
            {
                if (bClosed) return;
                oCertificateUsageNotice.Text = "Certificate choices could not be loaded. " +
                    oError.GetBaseException().Message;
                oCertificateUsageNotice.Visibility = Visibility.Visible;
            }
            finally
            {
                bLoadingCertificates = false;
                if (!bClosed)
                {
                    oAddCertDropDown.IsEnabled = bEditing && bCertificatesEnabled;
                    UpdateProtectionControls();
                }
            }
        }

        public void SetEditingControls(bool bEnabled)
        {
            // toggle what controls are available based on whether item item is decoded
            bEditing = bEnabled;
            bool bPlainText = ThisItem.ItemType == "text";
            bool bRichText = ThisItem.ItemType == "richtext";
            oAddCertDropDown.IsEnabled = bEnabled && bCertificatesEnabled && !bLoadingCertificates;
            oProtectionMode.IsEnabled = bEnabled && (bDpapiNgEnabled || bCertificatesEnabled || bFidoEnabled);
            oPrincipalScope.IsEnabled = bEnabled && bDpapiNgEnabled;
            oPrincipalControls.IsEnabled = bEnabled && bDpapiNgEnabled && bDomainJoined;
            oPrincipalMatch.IsEnabled = bEnabled && bDpapiNgEnabled && bDomainJoined;
            bool bCanUseFido = ThisItem.Cipher?.CipherParams != ItemCryptography.FidoFormat || FidoNative.IsAvailable;
            oLoadItemButton.IsEnabled = !bEnabled && bCanUseFido;
            oLoadItemButton.Visibility = bCanUseFido ? Visibility.Visible : Visibility.Collapsed;
            oItemData.IsEnabled = bEnabled && bPlainText;
            oRichItemData.IsEnabled = bEnabled && bRichText;
            oItemTypeSelector.IsEnabled = bEnabled && (ThisItem.ItemType is "text" or "richtext" or "totp" ||
                ThisItem.ItemId == 0 && BinaryItemData == null);
            bool bWasLoading = bLoading;
            bLoading = true;
            oItemTypeSelector.SelectedIndex = bPlainText ? PlainTextTypeIndex : bRichText ? RichTextTypeIndex
                : ThisItem.ItemType == "totp" ? TotpTypeIndex : FileTypeIndex;
            bLoading = bWasLoading;
            oItemLabel.IsReadOnly = !bEnabled;
            oUploadAFile.IsEnabled = bEnabled;
            oGeneratePasswordButton.IsEnabled = bEnabled && (bPlainText || bRichText);
            oRemoveItemButton.IsEnabled = ThisItem.ItemId != 0;
            oLockItemButton.IsEnabled = bEnabled && ThisItem.ItemId != 0;

            // control panel display
            oTextLockImage.Visibility = bEnabled ? Visibility.Collapsed : Visibility.Visible;
            oTextContentPanel.Visibility = bEnabled && (bPlainText || bRichText)
                ? Visibility.Visible : Visibility.Collapsed;
            oItemData.Visibility = bEnabled && bPlainText ? Visibility.Visible : Visibility.Collapsed;
            oRichItemData.Visibility = bEnabled && bRichText ? Visibility.Visible : Visibility.Collapsed;
            oRichTextToolbar.Visibility = bEnabled && bRichText ? Visibility.Visible : Visibility.Collapsed;
            oCopyContentButton.Visibility = oTextContentPanel.Visibility;
            oCopyContentButton.CommandTarget = bRichText ? oRichItemData : oItemData;
            oDownloadPanel.Visibility = bEnabled && ThisItem.ItemType is not ("text" or "richtext" or "totp")
                ? Visibility.Visible : Visibility.Collapsed;
            oDownloadTextBox.Content = BinaryItemData == null && ThisItem.ItemId == 0
                ? "Choose File Attachment..." : "Save Decrypted File...";
            System.Windows.Automation.AutomationProperties.SetName(oDownloadPanel, (string)oDownloadTextBox.Content);
            oTotpPanel.Visibility = bEnabled && ThisItem.ItemType == "totp" ? Visibility.Visible : Visibility.Collapsed;
            oTotpPanel.SetActive(bEnabled && ThisItem.ItemType == "totp");
            oContentTitle.Content = ThisItem.ItemType == "totp" ? "TOTP Authenticator" : "Protected Item Content";
            oItemStatus.Text = !bEnabled ? "Locked - decrypt to view or edit this item."
                : ThisItem.ItemId != 0 && ThisItem.Cipher.CipherParams == ItemCryptography.LegacyFormat
                ? "Legacy encryption - save this item to add tamper detection." : "Unlocked - content is visible.";
            UpdateProtectionControls();
        }

        private async void oSaveItemButton_Click(object sender, RoutedEventArgs e)
        {
            if (bBusy || !oSaveItemButton.IsEnabled) return;
            bool bSaved = false;
            SetBusy(true, "Encrypting and saving...");
            try
            {
                bSaved = await Utilities.TryOperationAsync(this, async () =>
                {
                    if (String.IsNullOrWhiteSpace(ThisItem.Label))
                        throw new InvalidOperationException("Enter an item label before saving.");

                    // Apply the text filter to visible content in either secret-text format.
                    if (ThisItem.ItemType is "text" or "richtext" &&
                        !String.IsNullOrWhiteSpace(Properties.Settings.Default.ItemTextExpressionFilter) &&
                        !Regex.IsMatch(ThisItem.ItemType == "richtext"
                            ? Utilities.GetRichText(oRichItemData) : oItemData.Text,
                            Properties.Settings.Default.ItemTextExpressionFilter,
                            RegexOptions.None, TimeSpan.FromSeconds(2)))
                        throw new InvalidOperationException(
                            "The item text provided does not satisfy the content filter.");

                    string sDescriptor = null;
                    bool bFido = oProtectionMode.SelectedIndex == FidoProtectionIndex;
                    if (oProtectionMode.SelectedIndex == UserProtectionIndex)
                    {
                        if (CertificateOperations.GetAutomaticCertificates().Count != 0)
                            throw new InvalidOperationException(
                                "Required recipient certificates are configured. Use Certificate Based" +
                                (bFidoEnabled ? " or FIDO2" : "") + " encryption or ask the administrator " +
                                "to update that configuration.");
                        if (oPrincipalScope.SelectedIndex == DomainScopeIndex &&
                            !String.IsNullOrWhiteSpace(oPrincipalName.Text))
                            throw new InvalidOperationException("Add the entered account to the recipient list, " +
                                "or clear the account field before saving.");
                        sDescriptor = oPrincipalScope.SelectedIndex == LocalUserScopeIndex
                            ? PrincipalProtection.LocalUserDescriptor
                            : oPrincipalScope.SelectedIndex == LocalMachineScopeIndex
                            ? PrincipalProtection.LocalMachineDescriptor
                            : PrincipalProtection.CreateDescriptor(PrincipalList,
                                oPrincipalMatch.SelectedIndex == AllPrincipalsIndex);
                    }
                    else
                    {
                        foreach (byte[] oRequired in CertificateOperations.GetAutomaticCertificates())
                        {
                            User oUser = UserList.FirstOrDefault(u => u.Certificate.SequenceEqual(oRequired));
                            if (oUser == null)
                                throw new InvalidOperationException(
                                    "A required certificate is missing. Reopen the Vault.");
                            if (!UserListSelected.Contains(oUser)) UserListSelected.Add(oUser);
                        }

                        // error if there are no selected users
                        if (!bFido && UserListSelected.Count == 0 &&
                            RecoveryPolicy.ReadForStorage(CryptureEntities.Storage).Certificate == null)
                            throw new InvalidOperationException("Select at least one recipient using Share With.");
                    }
                    List<byte[]> oRequiredCertificates = CertificateOperations.GetAutomaticCertificates();
                    List<User> oRecipients = UserListSelected.Where(u => !bFido ||
                        oRequiredCertificates.Any(c => c.SequenceEqual(u.Certificate))).ToList();
                    IntPtr hOwner = bFido ? new WindowInteropHelper(this).EnsureHandle() : IntPtr.Zero;
                    if (bFido) oItemStatus.Text = "Complete the security key PIN and touch prompts...";
                    byte[] oPlainText = ThisItem.ItemType switch
                    {
                        "text" => Encoding.Unicode.GetBytes(oItemData.Text),
                        "richtext" => SaveRichText(),
                        "totp" => Encoding.UTF8.GetBytes(oTotpPanel.ReadUri()),
                        _ => BinaryItemData
                    };
                    try
                    {
                        // verify the selected users
                        await Task.Run(() =>
                        {
                            if (sDescriptor == null)
                            {
                                foreach (User oUser in oRecipients)
                                {
                                    using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(
                                        oUser.Certificate))
                                    {
                                        CertificateKeyProtection.ValidateForEncryption(oCert);
                                        if (!CertificateOperations.CheckCertificateStatus(oCert, true))
                                            throw new InvalidOperationException("The certificate for '" + oUser.Name +
                                                "' is not valid for encryption. Review the sharing list " +
                                                "and certificate settings.");
                                    }
                                }
                            }

                            // Complete hardware prompts before taking the Vault's write lock.
                            if (bFido && oFidoCredentialId == null)
                                oFidoCredentialId = FidoNative.CreateCredential(hOwner);
                            using FidoKeyAccess oFidoKey = bFido ? FidoNative.Open(hOwner, oFidoCredentialId,
                                RandomNumberGenerator.GetBytes(FidoKeyProtection.SaltBytes)) : null;
                            DatabaseOperations.SaveItem(ThisItem, oPlainText, oRecipients, sDescriptor, oFidoKey);
                        });
                    }
                    finally
                    {
                        if (ThisItem.ItemType is "text" or "richtext" or "totp" && oPlainText != null)
                            Array.Clear(oPlainText, 0, oPlainText.Length);
                    }
                });
            }
            finally
            {
                // A successful save closes the editor without refreshing its draft model.
                if (bSaved) bBusy = false;
                else SetBusy(false);
            }
            if (!bSaved) return;

            // close and return to calling dialog
            bCompleted = true;
            Close();
        }

        private byte[] SaveRichText()
        {
            using (MemoryStream oStream = new MemoryStream())
            {
                new TextRange(oRichItemData.Document.ContentStart, oRichItemData.Document.ContentEnd)
                    .Save(oStream, DataFormats.Rtf);
                return oStream.ToArray();
            }
        }

        private X509Certificate2 GetUserKey(IEnumerable<User> SourceUserList)
        {
            // Open the user and computer personal certificate stores.
            X509Certificate2Collection oStoreCertificates = CertificateOperations.GetPersonalCertificates();
            try
            {
                // collate the database certificates to those locally available
                X509Certificate2Collection oMyCertCollection = new X509Certificate2Collection();
                foreach (X509Certificate2 oStoreUser in oStoreCertificates)
                {
                    if (oStoreUser.HasPrivateKey && SourceUserList.Any(u =>
                        u.Certificate.SequenceEqual(oStoreUser.RawData))) oMyCertCollection.Add(oStoreUser);
                }

                // Report when neither store contains a matching private key.
                if (oMyCertCollection.Count == 0)
                    throw new InvalidOperationException("No matching private key was found in the user or " +
                        "computer personal certificate stores.");

                // allow the certificate
                X509Certificate2Collection oCollection = X509Certificate2UI.SelectFromCollection(oMyCertCollection,
                    "Select Certificate", "Select Certificate To Decode", X509SelectionFlag.SingleSelection,
                    new WindowInteropHelper(this).Handle);
                return oCollection.Count == 0 ? null : new X509Certificate2(oCollection[0]);
            }
            finally
            {
                foreach (X509Certificate2 oStoreUser in oStoreCertificates) oStoreUser.Dispose();
            }
        }

        private async void oLoadItemButton_Click(object sender, RoutedEventArgs e)
        {
            await LoadItem(false);
        }

        private async void oFidoRecovery_Click(object sender, RoutedEventArgs e)
        {
            await LoadItem(true);
        }

        private async Task LoadItem(bool bRecoveryOnly)
        {
            if (bBusy) return;
            SetBusy(true, "Checking access and decrypting...");
            try
            {
                await Utilities.TryOperationAsync(this, async () =>
                {
                    byte[] oPlainText;
                    long? nModifier = null;
                    oPlainText = null;
                    bool bFido = ThisItem.Cipher.CipherParams == ItemCryptography.FidoFormat;
                    if (bFido && !bRecoveryOnly)
                    {
                        FidoKeyEnvelope oEnvelope = FidoKeyProtection.Read(ThisItem.Cipher);
                        IntPtr hOwner = new WindowInteropHelper(this).EnsureHandle();
                        oItemStatus.Text = "Complete the security key PIN and touch prompts...";
                        oPlainText = await Task.Run(() =>
                        {
                            using FidoKeyAccess oAccess = FidoNative.Open(hOwner,
                                oEnvelope.CredentialId, oEnvelope.Salt);
                            return ItemCryptography.Decrypt(ThisItem, oFidoKey: oAccess);
                        });
                    }
                    else if (bFido || ThisItem.Cipher.CipherParams == ItemCryptography.PrincipalFormat ||
                        ThisItem.Cipher.CipherParams == ItemCryptography.RecoveryFormat)
                    {
                        try
                        {
                            oPlainText = await Task.Run(() => ItemCryptography.Decrypt(ThisItem));
                        }
                        catch (CryptographicException) when (ThisItem.Instances.Count != 0)
                        {
                            // A recovery certificate remains available when Windows cannot grant access.
                        }
                    }
                    if (oPlainText == null)
                    {
                        // Cancellation codes from the smart card, cryptography, and Windows APIs.
                        const uint SmartCardUserCancelledHResult = 0x8010006E;
                        const uint CryptographyUserCancelledHResult = 0x80090036;
                        const uint WindowsUserCancelledHResult = 0x800704C7;

                        // select all the certs associated with this user
                        using (X509Certificate2 oCert = GetUserKey(UserListSelected))
                        {
                            if (oCert == null) return;
                            Instance oInstance = ThisItem.Instances.FirstOrDefault(
                                i => i.User.Certificate.SequenceEqual(oCert.RawData));
                            try
                            {
                                oPlainText = await Task.Run(() => ItemCryptography.Decrypt(ThisItem, oInstance, oCert));
                            }
                            catch (CryptographicException oError) when (
                                (uint)oError.HResult == SmartCardUserCancelledHResult ||
                                (uint)oError.HResult == CryptographyUserCancelledHResult ||
                                (uint)oError.HResult == WindowsUserCancelledHResult)
                            {
                                return;
                            }
                            nModifier = oInstance.UserId;
                        }
                    }
                    bLoading = true;
                    try
                    {
                        // process text item
                        if (ThisItem.ItemType == "text") oItemData.Text = Encoding.Unicode.GetString(oPlainText);
                        else if (ThisItem.ItemType == "richtext")
                        {
                            using (MemoryStream oStream = new MemoryStream(oPlainText, false))
                                new TextRange(oRichItemData.Document.ContentStart, oRichItemData.Document.ContentEnd)
                                    .Load(oStream, DataFormats.Rtf);
                            oRichItemData.Document.PagePadding = new Thickness(0);
                            Utilities.NormalizeRichTextAppearance(oRichItemData);
                        }
                        else if (ThisItem.ItemType == "totp")
                            oTotpPanel.LoadUri(new UTF8Encoding(false, true).GetString(oPlainText));
                        // text binary item
                        else BinaryItemData = oPlainText;
                        ThisItem.ModifiedBy = nModifier;
                        SetEditingControls(true);
                    }
                    finally
                    {
                        if (ThisItem.ItemType is "text" or "richtext" or "totp")
                            Array.Clear(oPlainText, 0, oPlainText.Length);
                        bLoading = false;
                    }
                });
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void SetBusy(bool bEnabled, string sStatus = null)
        {
            bBusy = bEnabled;
            bool bConcealed = oPrivacyShield.Visibility == Visibility.Visible;
            ribbon.IsEnabled = !bEnabled && !bConcealed;
            oEditorPanels.IsEnabled = !bEnabled && !bConcealed;
            Cursor = bEnabled ? Cursors.Wait : null;
            if (bEnabled) oItemStatus.Text = sStatus;
            else
            {
                SetEditingControls(bEditing);
                if (bConcealed && !bHasChanges && ThisItem.ItemId != 0 && bEditing)
                {
                    LockItem();
                    oPrivacyMessage.Text = "This saved item was locked. Choose Reveal to return to the editor.";
                }
                else if (bConcealed) oPrivacyMessage.Text = bEditing
                    ? "This editor is concealed. Unsaved edits remain here. Choose Reveal to continue."
                    : "This item is locked. Choose Reveal to return to the editor.";
            }
        }

        private void LoadProtection()
        {
            bool bWasLoading = bLoading;
            bLoading = true;
            try
            {
                bool bPrincipals = ItemCryptography.UsesWindowsProtection(ThisItem.Cipher);
                bool bFido = ThisItem.Cipher?.CipherParams == ItemCryptography.FidoFormat;
                oProtectionMode.SelectedIndex = bFido ? FidoProtectionIndex :
                    bPrincipals ? UserProtectionIndex : CertificateProtectionIndex;
                oFidoCredentialId = bFido ? FidoKeyProtection.Read(ThisItem.Cipher).CredentialId : null;
                PrincipalList.Clear();
                if (!bPrincipals) return;
                string sDescriptor = ThisItem.Cipher.ProtectionDescriptor;
                bool bRequireAll;
                foreach (ProtectionPrincipal oPrincipal in PrincipalProtection.ParseDescriptor(
                    sDescriptor, out bRequireAll)) PrincipalList.Add(oPrincipal);
                oPrincipalScope.SelectedIndex = sDescriptor == PrincipalProtection.LocalUserDescriptor
                    ? LocalUserScopeIndex : sDescriptor == PrincipalProtection.LocalMachineDescriptor
                    ? LocalMachineScopeIndex : DomainScopeIndex;
                oPrincipalMatch.SelectedIndex = bRequireAll ? AllPrincipalsIndex : AnyPrincipalIndex;
            }
            finally
            {
                bLoading = bWasLoading;
                UpdateProtectionControls();
            }
        }

        private void UpdateProtectionControls()
        {
            if (oPrincipalPanel == null || oPrincipalHint == null || oCertificatePanel == null || oFidoPanel == null)
                return;
            bool bPrincipals = oProtectionMode.SelectedIndex == UserProtectionIndex;
            bool bCertificates = oProtectionMode.SelectedIndex == CertificateProtectionIndex;
            bool bFido = oProtectionMode.SelectedIndex == FidoProtectionIndex;
            bool bProtectionEnabled = bPrincipals && oDpapiNgProtection.IsEnabled ||
                bCertificates && bCertificatesEnabled || bFido && bFidoEnabled;
            oSaveItemButton.IsEnabled = bEditing && bProtectionEnabled &&
                (!bCertificates || !bLoadingCertificates) &&
                (ThisItem.ItemType is "text" or "richtext" or "totp" || BinaryItemData != null);
            oProtectionDisabledNotice.Visibility = bProtectionEnabled ? Visibility.Collapsed : Visibility.Visible;
            oProtectionDisabledNotice.Text = bFido && !FidoNative.IsAvailable
                ? "FIDO2 encryption is unavailable in this Windows session. Use saved recovery access, " +
                    "or open this Vault on a computer supporting FIDO2 hmac-secret."
                : !bDpapiNgEnabled && !bCertificatesEnabled && !bFidoEnabled
                ? "Encryption methods are disabled in Crypture.exe.config. Existing items can still be decrypted."
                : "This encryption method is disabled in Crypture.exe.config. " +
                    "Decrypt the item, then select an enabled encryption method before saving.";
            bool bLocal = oPrincipalScope.SelectedIndex != DomainScopeIndex;
            bool bRequiredCertificates = CertificateOperations.GetAutomaticCertificates().Count != 0;
            oRequiredCertificateNotice.Visibility = bRequiredCertificates ? Visibility.Visible : Visibility.Collapsed;
            oRequiredCertificateNotice.Text = bPrincipals
                ? "Required recipient certificates are configured. Use Certificate Based" +
                    (bFidoEnabled ? " or FIDO2" : "") + " encryption."
                : "Required recipient certificates are included on every save and can decrypt independently.";
            UpdateRecoveryNotice();
            oPrincipalPanel.Visibility = bPrincipals && bDpapiNgEnabled ? Visibility.Visible : Visibility.Collapsed;
            oCertificatePanel.Visibility = bCertificates && bCertificatesEnabled
                ? Visibility.Visible : Visibility.Collapsed;
            oCertificateSharingGroup.Visibility = oCertificatePanel.Visibility;
            oFidoPanel.Visibility = bFido ? Visibility.Visible : Visibility.Collapsed;
            oFidoKeyStatus.Text = oFidoCredentialId == null ? "A security key will be set up when you save."
                : "Use the security key that protected this item.";
            oChangeFidoKeyButton.Visibility = bEditing && bFidoEnabled && oFidoCredentialId != null
                ? Visibility.Visible : Visibility.Collapsed;
            bool bFidoRecovery = ThisItem.Cipher?.CipherParams == ItemCryptography.FidoFormat &&
                (ThisItem.Instances.Count != 0 || FidoKeyProtection.Read(ThisItem.Cipher).RecoveryKey != null);
            oFidoRecoveryButton.Visibility = !bEditing && bFidoRecovery ? Visibility.Visible : Visibility.Collapsed;
            oPrincipalTargets.Visibility = bLocal ? Visibility.Collapsed : Visibility.Visible;
            oDomainNotice.Visibility = bDomainJoined ? Visibility.Collapsed : Visibility.Visible;
            oPrincipalHint.Text = oPrincipalScope.SelectedIndex == LocalMachineScopeIndex
                ? "Every user on the computer used to encrypt this item can decrypt it " +
                    "if they can read the Vault. This grants access to all local users, " +
                    "not a selected group. Copying it to another computer does not grant access."
                : bLocal ? "Only the Windows profile used to encrypt this item can decrypt it. " +
                    "Copying the Vault does not transfer access."
                : "Domain users and security groups require Active Directory key distribution. " +
                    "Local accounts and groups are not supported in this scope. " +
                    "Include yourself or a recovery group if you need access after saving.";
        }

        private void UpdateRecoveryNotice()
        {
            if (oRecoveryNotice == null) return;
            List<string> oDetails = new List<string>();
            try
            {
                RecoveryPolicy oPolicy = RecoveryPolicy.ReadForStorage(CryptureEntities.Storage);
                string sEscrowLabel = (CryptureEntities.Storage as SqlServerVaultStorage)?.Escrow?.Label;
                if (sEscrowLabel != null) oDetails.Add("Vault Escrow: " + sEscrowLabel);
                else if (oPolicy.Descriptor != null)
                    oDetails.Add("User Based Recovery: " + oPolicy.Descriptor);
                if (oPolicy.Certificate != null)
                {
                    using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oPolicy.Certificate))
                        if (sEscrowLabel == null) oDetails.Add("Certificate Based Recovery: " +
                            oCert.GetNameInfo(X509NameType.SimpleName, false));
                }
                if (oDetails.Count != 0) oDetails.Add("Recovery is added automatically on every save. " +
                    "Decrypt and save older items to add it. Recovery recipients can decrypt independently.");
                if (!String.IsNullOrWhiteSpace(ThisItem.Cipher?.EscrowLabel))
                    oDetails.Add("Saved Escrow: " + ThisItem.Cipher.EscrowLabel);
                if (ThisItem.Cipher?.CipherParams is ItemCryptography.RecoveryFormat or ItemCryptography.FidoFormat)
                {
                    bool bFido = ThisItem.Cipher.CipherParams == ItemCryptography.FidoFormat;
                    Cipher oRecoveryCipher = bFido ? new Cipher
                        { ProtectedKey = FidoKeyProtection.Read(ThisItem.Cipher).RecoveryKey } : ThisItem.Cipher;
                    if (oRecoveryCipher.ProtectedKey != null)
                        foreach (var oEntry in RecoveryProtection.ReadWindowsKeys(oRecoveryCipher))
                            if (oEntry.Key != ThisItem.Cipher.ProtectionDescriptor)
                                oDetails.Add("Saved User Based Recovery: " + oEntry.Key);
                    if ((bFido || ItemCryptography.UsesWindowsProtection(ThisItem.Cipher)) && UserListSelected.Count != 0)
                        oDetails.Add("Saved Certificate Based Recovery: " +
                            String.Join(", ", UserListSelected.Select(u => u.Name)));
                }
                oRecoveryNotice.Text = "Emergency Recovery" + Environment.NewLine +
                    String.Join(Environment.NewLine, oDetails);
            }
            catch (Exception oError) when (oError is InvalidOperationException || oError is CryptographicException)
            {
                oDetails.Add(oError.Message);
                oRecoveryNotice.Text = "Emergency Recovery: " + oError.Message;
            }
            oRecoveryNotice.Visibility = oDetails.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        }

        private void oProtectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateProtectionControls();
            if (!bLoading && bEditing) bHasChanges = true;
        }

        private void oChangeFidoKey_Click(object sender, RoutedEventArgs e)
        {
            if (bBusy || !bEditing) return;
            oFidoCredentialId = null;
            bHasChanges = true;
            UpdateProtectionControls();
        }

        private async void oAddPrincipal_Click(object sender, RoutedEventArgs e)
        {
            if (bBusy) return;
            string sAccount = oPrincipalName.Text;
            SetBusy(true, "Resolving Windows account...");
            try
            {
                await Utilities.TryOperationAsync(this, async () =>
                {
                    AddPrincipal(await Task.Run(() => ProtectionPrincipal.Resolve(sAccount)));
                    oPrincipalName.Clear();
                });
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void AddPrincipal(ProtectionPrincipal oPrincipal)
        {
            if (PrincipalList.Any(p => p.Sid == oPrincipal.Sid)) return;
            if (PrincipalList.Count >= PrincipalProtection.MaxPrincipals)
                throw new InvalidOperationException("An item can include up to 100 users or groups.");
            PrincipalList.Add(oPrincipal);
            bHasChanges = true;
        }

        private void oAddCurrentPrincipal_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
                AddPrincipal(new ProtectionPrincipal(CertificateOperations.CurrentUserSid)));
        }

        private void oRemovePrincipal_Click(object sender, RoutedEventArgs e)
        {
            if (!(oPrincipalList.SelectedItem is ProtectionPrincipal oPrincipal)) return;
            PrincipalList.Remove(oPrincipal);
            bHasChanges = true;
        }

        private void oBrowsePrincipals_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                DirectoryPicker oPicker = new DirectoryPicker { Owner = this };
                if (oPicker.ShowDialog() != true) return;
                DirectoryAccount[] oNew = oPicker.SelectedAccounts
                    .Where(a => !PrincipalList.Any(p => p.Sid == a.Sid)).ToArray();
                if (PrincipalList.Count + oNew.Length > PrincipalProtection.MaxPrincipals)
                    throw new InvalidOperationException("An item can include up to 100 users or groups.");
                foreach (DirectoryAccount oAccount in oNew)
                    AddPrincipal(new ProtectionPrincipal(oAccount.Sid, oAccount.Account));
            });
        }

        private void MenuItemWithRadioButtons_Click(object sender, RoutedEventArgs e)
        {
            RibbonMenuItem oMenu = (RibbonMenuItem)sender;
            User oUser = (User)oMenu.DataContext;
            if (CertificateOperations.GetAutomaticCertificates().Any(c => c.SequenceEqual(oUser.Certificate)))
            {
                if (!UserListSelected.Contains(oUser))
                {
                    UserListSelected.Add(oUser);
                    bHasChanges = true;
                }
                oMenu.IsChecked = true;
                return;
            }
            bool bIsInList = UserListSelected.Contains(oUser);
            if (bIsInList) UserListSelected.Remove(oUser);
            else UserListSelected.Add(oUser);
            oMenu.IsChecked = !bIsInList;
            bHasChanges = true;
        }

        private void oRemoveItemButton_Click(object sender, RoutedEventArgs e)
        {
            // confirm removal
            if (ThisItem.ItemId == 0 || MessageBox.Show(this,
                "Are you sure you want to remove this item?", "Removal Confirmation", MessageBoxButton.YesNo,
                MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;

            if (!Utilities.TryOperation(this, () =>
            {
                DatabaseOperations.DeleteItem(ThisItem);
            })) return;
            bCompleted = true;
            Close();
        }

        private bool ConfirmDiscard()
        {
            return !bHasChanges || MessageBox.Show(this, "Discard your unsaved changes?", "Unsaved Changes",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) == MessageBoxResult.Yes;
        }

        private void ClearPlainText()
        {
            bLoading = true;
            oItemData.Clear();
            oRichItemData.Document.Blocks.Clear();
            oRichItemData.Document.Blocks.Add(new Paragraph { Margin = new Thickness(0) });
            oTotpPanel.Clear();
            if (BinaryItemData != null) Array.Clear(BinaryItemData, 0, BinaryItemData.Length);
            BinaryItemData = null;
            bLoading = false;
        }

        private void oRootWindow_Closing(object sender, CancelEventArgs e)
        {
            if (bBusy || !bCompleted && !ConfirmDiscard())
            {
                e.Cancel = true;
                return;
            }
            ClearPlainText();
        }

        private void oLockItemButton_Click(object sender, RoutedEventArgs e)
        {
            if (!ConfirmDiscard()) return;
            LockItem();
        }

        private void LockItem()
        {
            ClearPlainText();
            bLoading = true;
            ThisItem.Label = sStoredLabel;
            ThisItem.ItemType = sStoredItemType;
            ThisItem.ModifiedBy = nStoredModifiedBy;
            DataContext = null;
            DataContext = ThisItem;
            UserListSelected = new ObservableCollection<User>(UserList.Where(u =>
                ThisItem.Instances.Any(i => i.UserId == u.UserId)));
            oItemSharedWith.ItemsSource = UserListSelected;
            oAddCertDropDown.Items.Refresh();
            LoadProtection();
            SetEditingControls(false);
            bHasChanges = false;
            bLoading = false;
        }

        internal void ConcealSecrets()
        {
            if (oPrivacyShield.Visibility == Visibility.Visible || !bEditing && !bBusy) return;

            // Preserve drafts and in-flight operations behind an opaque, disabled view.
            bool bCanLock = !bBusy && !bHasChanges && ThisItem.ItemId != 0;
            oPrivacyMessage.Text = bCanLock
                ? "This saved item was locked. Choose Reveal to return to the editor."
                : bBusy ? "The current operation is finishing. Choose Reveal when it completes."
                : "This editor is concealed. Unsaved edits remain here. Choose Reveal to continue.";
            oPrivacyShield.Visibility = Visibility.Visible;
            ribbon.IsEnabled = false;
            oEditorPanels.IsEnabled = false;
            oEditorPanels.Visibility = Visibility.Collapsed;
            Keyboard.ClearFocus();
            oRevealButton.Focus();
            if (bCanLock) LockItem();
        }

        private void oRevealButton_Click(object sender, RoutedEventArgs e)
        {
            oEditorPanels.Visibility = Visibility.Visible;
            oPrivacyShield.Visibility = Visibility.Collapsed;
            ribbon.IsEnabled = !bBusy;
            oEditorPanels.IsEnabled = !bBusy;
            if (bEditing && bHasChanges) oItemStatus.Text = "Unsaved edits restored. Encrypt & Save to keep them.";
            else if (!bBusy) SetEditingControls(bEditing);
            if (bEditing && ThisItem.ItemType == "richtext") oRichItemData.Focus();
            else if (bEditing) oItemData.Focus();
            else oLoadItemButton.Focus();
        }

        private void oItemTypeChanged(object sender, SelectionChangedEventArgs e)
        {
            if (bLoading || bBusy || !bEditing || oItemTypeSelector.SelectedIndex is not
                (PlainTextTypeIndex or RichTextTypeIndex or TotpTypeIndex or FileTypeIndex))
                return;
            if (oItemTypeSelector.SelectedIndex == FileTypeIndex)
            {
                SetEditingControls(true);
                oUploadAFile_Click(sender, e);
                return;
            }
            string sNewType = oItemTypeSelector.SelectedIndex switch
            {
                RichTextTypeIndex => "richtext",
                TotpTypeIndex => "totp",
                _ => "text"
            };

            // Text-format changes preserve the content while an explicit plain-text conversion removes formatting.
            if (ThisItem.ItemType == "richtext" && sNewType == "text")
            {
                string sText = Utilities.GetRichText(oRichItemData);
                if (sText.Length != 0 && MessageBox.Show(this,
                    "Convert to plain text? Formatting will be removed.", "Convert Secret Text",
                    MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes)
                {
                    bLoading = true;
                    oItemTypeSelector.SelectedIndex = RichTextTypeIndex;
                    bLoading = false;
                    return;
                }
                oItemData.Text = sText;
                oRichItemData.Document.Blocks.Clear();
            }
            else if (ThisItem.ItemType == "text" && sNewType == "richtext")
            {
                oRichItemData.Document.Blocks.Clear();
                oRichItemData.Document.Blocks.Add(new Paragraph(new Run(oItemData.Text))
                {
                    Margin = new Thickness(0)
                });
                oItemData.Clear();
            }
            ThisItem.ItemType = sNewType;
            SetEditingControls(true);
            bHasChanges = true;
        }

        private void oItemChanged(object sender, TextChangedEventArgs e)
        {
            if (!bLoading && bEditing) bHasChanges = true;
        }

        private void oRichItemChanged(object sender, TextChangedEventArgs e)
        {
            if (!bLoading && bEditing) bHasChanges = true;
        }

        private void oRootWindow_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (oPrivacyShield.Visibility == Visibility.Visible)
            {
                if (!oRevealButton.IsKeyboardFocusWithin) e.Handled = true;
                return;
            }
            if (bBusy || Keyboard.Modifiers != ModifierKeys.Control) return;
            if (e.Key == Key.S && oSaveItemButton.IsEnabled) oSaveItemButton_Click(sender, e);
            else if (e.Key == Key.L && oLockItemButton.IsEnabled) oLockItemButton_Click(sender, e);
            else return;
            e.Handled = true;
        }

        private void oGeneratePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            if (bBusy || !bEditing || ThisItem.ItemType is not ("text" or "richtext")) return;
            Utilities.TryOperation(this, () =>
            {
                PasswordGenerator oGenerator = new PasswordGenerator(true) { Owner = this };
                if (oGenerator.ShowDialog() != true) return;
                if (ThisItem.ItemType == "richtext")
                {
                    oRichItemData.Selection.Text = oGenerator.SelectedPassword;
                    oRichItemData.Focus();
                }
                else
                {
                    int nStart = oItemData.SelectionStart;
                    oItemData.SelectedText = oGenerator.SelectedPassword;
                    oItemData.Select(nStart + oGenerator.SelectedPassword.Length, 0);
                    oItemData.Focus();
                }
            });
        }

        private void oUploadAFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog oOpenDialog = new OpenFileDialog { Filter = "All Files (*.*)|*.*", CheckFileExists = true };
            if (oOpenDialog.ShowDialog(this) != true || !ConfirmDiscard()) return;
            Utilities.TryOperation(this, () =>
            {
                byte[] oFileData = Utilities.ReadFile(oOpenDialog.FileName);
                byte[] oCompressed;
                try
                {
                    oCompressed = Utilities.Compress(oFileData);
                }
                finally
                {
                    Array.Clear(oFileData, 0, oFileData.Length);
                }
                ClearPlainText();
                BinaryItemData = oCompressed;
                ThisItem.ItemType = Path.GetExtension(oOpenDialog.FileName);
                SetEditingControls(true);
                bHasChanges = true;
            });
        }

        private void oDownloadPanel_Click(object sender, RoutedEventArgs e)
        {
            if (ThisItem.ItemId == 0 && BinaryItemData == null)
            {
                oUploadAFile_Click(sender, e);
                return;
            }
            Utilities.TryOperation(this, () =>
            {
                // generate the filter field to use based on the stored item type
                string sFilter = "All Files (*.*)|*.*";
                if (Regex.IsMatch(ThisItem.ItemType, @"^\.[a-zA-Z0-9]{1,16}$"))
                    sFilter = String.Format("{0} Files (*{0})|*{0}|", ThisItem.ItemType) + sFilter;

                // ask the user where to store the file
                SaveFileDialog oSaveDialog = new SaveFileDialog
                {
                    Filter = sFilter, AddExtension = true, ValidateNames = true
                };
                if (oSaveDialog.ShowDialog(this) != true) return;

                // write data to file
                byte[] oFileData = Utilities.Decompress(BinaryItemData);
                try
                {
                    File.WriteAllBytes(oSaveDialog.FileName, oFileData);
                }
                finally
                {
                    Array.Clear(oFileData, 0, oFileData.Length);
                }
            });
        }
    }
}
