using Fluent;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Principal;
using System.Threading.Tasks;
using Tulpep.ActiveDirectoryObjectPicker;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;

namespace Crypture
{
    public partial class ItemEditor : RibbonWindow
    {
        public Item ThisItem { get; set; } = new Item();
        public ObservableCollection<User> UserList { get; set; } = new ObservableCollection<User>();
        public ObservableCollection<User> UserListSelected { get; set; } = new ObservableCollection<User>();
        public byte[] BinaryItemData { get; set; }
        private bool bLoading = true;
        private bool bHasChanges;
        private bool bCompleted;
        private bool bBusy;
        private readonly bool bDomainJoined = PrincipalProtection.IsDomainJoined;
        private readonly ObservableCollection<ProtectionPrincipal> PrincipalList =
            new ObservableCollection<ProtectionPrincipal>();
        private string sStoredLabel;
        private string sStoredItemType;
        private long? nStoredModifiedBy;

        public ItemEditor(bool bNewItem = true)
        {
            ThisItem.Label = "My New Item";
            ThisItem.ItemType = "text";
            DataContext = ThisItem;
            InitializeComponent();
            Utilities.EnableClipboardTimeout(oItemData);

            // setup sorting for the drop down list of certs
            oItemSharedWith.Items.IsLiveSorting = true;
            oItemSharedWith.Items.SortDescriptions.Add(
                new SortDescription(oItemSharedWith.DisplayMemberPath, ListSortDirection.Ascending));

            // setup sorting for the shared with list
            oAddCertDropDown.Items.IsLiveSorting = true;
            oAddCertDropDown.Items.SortDescriptions.Add(
                new SortDescription(oAddCertDropDown.DisplayMemberPath, ListSortDirection.Ascending));

            // add in our keys by default
            if (bNewItem) LoadUsers(true);
            oPrincipalList.ItemsSource = PrincipalList;
            oDomainScope.IsEnabled = bDomainJoined;
            oPrincipalScope.SelectedIndex = !bDomainJoined || String.Equals(Environment.UserDomainName,
                Environment.MachineName, StringComparison.OrdinalIgnoreCase) ? 1 : 0;
            if (bNewItem)
            {
                PrincipalList.Add(new ProtectionPrincipal(CertificateOperations.CurrentUserSid));
                oProtectionMode.SelectedIndex = CertificateOperations.GetAutomaticCertificates().Count == 0 ? 0 : 1;
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
            HashSet<string> oPrivateCertificates = CertificateOperations.GetPrivateCertificateData();
            List<byte[]> oAutomatic = CertificateOperations.GetAutomaticCertificates();
            UserListSelected = new ObservableCollection<User>(UserList.Where(u => bNewItem
                ? oPrivateCertificates.Contains(Convert.ToBase64String(u.Certificate)) ||
                    oAutomatic.Any(c => c.SequenceEqual(u.Certificate))
                : ThisItem.Instances.Any(i => i.UserId == u.UserId)));
            oItemSharedWith.ItemsSource = UserListSelected;
            oAddCertDropDown.ItemsSource = UserList;
            if (bNewItem) ThisItem.ModifiedBy = UserListSelected.FirstOrDefault(u =>
                oPrivateCertificates.Contains(Convert.ToBase64String(u.Certificate)))?.UserId;
        }

        public void SetEditingControls(bool bEnabled)
        {
            // toggle what controls are available based on whether item item is decoded
            oAddCertDropDown.IsEnabled = bEnabled;
            oProtectionMode.IsEnabled = bEnabled;
            oPrincipalScope.IsEnabled = bEnabled;
            oPrincipalControls.IsEnabled = bEnabled && bDomainJoined;
            oPrincipalMatch.IsEnabled = bEnabled && bDomainJoined;
            oLoadItemButton.IsEnabled = !bEnabled;
            oSaveItemButton.IsEnabled = bEnabled;
            oItemData.IsEnabled = bEnabled;
            oItemLabel.IsReadOnly = !bEnabled;
            oUploadAFile.IsEnabled = bEnabled;
            oGeneratePasswordButton.IsEnabled = bEnabled && ThisItem.ItemType == "text";
            oRemoveItemButton.IsEnabled = ThisItem.ItemId != 0;
            oLockItemButton.IsEnabled = bEnabled && ThisItem.ItemId != 0;

            // control panel display
            oTextLockImage.Visibility = bEnabled ? Visibility.Collapsed : Visibility.Visible;
            oItemData.Visibility = bEnabled && ThisItem.ItemType == "text" ? Visibility.Visible : Visibility.Collapsed;
            oDownloadPanel.Visibility = bEnabled && ThisItem.ItemType != "text"
                ? Visibility.Visible : Visibility.Collapsed;
            oItemStatus.Text = !bEnabled ? "Locked - decrypt to view or edit this item."
                : ThisItem.ItemId != 0 && ThisItem.Cipher.CipherParams == 0
                ? "Legacy encryption - save this item to add tamper detection." : "Unlocked - content is visible.";
            UpdateProtectionControls();
        }

        private async void oSaveItemButton_Click(object sender, RoutedEventArgs e)
        {
            if (bBusy) return;
            bool bSaved = false;
            SetBusy(true, "Encrypting and saving...");
            try
            {
                bSaved = await Utilities.TryOperationAsync(this, async () =>
                {
                    if (String.IsNullOrWhiteSpace(ThisItem.Label))
                        throw new InvalidOperationException("Enter an item label before saving.");

                    // perform data validation if in text mode and option is set
                    if (ThisItem.ItemType == "text" &&
                        !String.IsNullOrWhiteSpace(Properties.Settings.Default.ItemTextExpressionFilter) &&
                        !Regex.IsMatch(oItemData.Text, Properties.Settings.Default.ItemTextExpressionFilter,
                            RegexOptions.None, TimeSpan.FromSeconds(2)))
                        throw new InvalidOperationException(
                            "The item text provided does not satisfy the content filter.");

                    string sDescriptor = null;
                    if (oProtectionMode.SelectedIndex == 0)
                    {
                        if (CertificateOperations.GetAutomaticCertificates().Count != 0)
                            throw new InvalidOperationException("Required recipient certificates are configured. " +
                                "Use certificate protection or ask the administrator to update that configuration.");
                        if (oPrincipalScope.SelectedIndex == 0 && !String.IsNullOrWhiteSpace(oPrincipalName.Text))
                            throw new InvalidOperationException("Add the entered account to the recipient list, " +
                                "or clear the account field before saving.");
                        sDescriptor = oPrincipalScope.SelectedIndex == 1 ? PrincipalProtection.LocalUserDescriptor
                            : oPrincipalScope.SelectedIndex == 2 ? PrincipalProtection.LocalMachineDescriptor
                            : PrincipalProtection.CreateDescriptor(PrincipalList, oPrincipalMatch.SelectedIndex == 1);
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

                        // verify the selected users
                        foreach (User oUser in UserListSelected)
                        {
                            using (X509Certificate2 oCert = new X509Certificate2(oUser.Certificate))
                            {
                                CertificateKeyProtection.ValidateForEncryption(oCert);
                                if (!CertificateOperations.CheckCertificateStatus(oCert))
                                    throw new InvalidOperationException("The certificate for '" + oUser.Name +
                                        "' is not valid for encryption. Review the sharing list " +
                                        "and certificate settings.");
                            }
                        }

                        // error if there are no selected users
                        if (UserListSelected.Count == 0)
                            throw new InvalidOperationException("Select at least one recipient using Share With.");
                    }
                    List<User> oRecipients = UserListSelected.ToList();
                    byte[] oPlainText = ThisItem.ItemType == "text"
                        ? Encoding.Unicode.GetBytes(oItemData.Text) : BinaryItemData;
                    try
                    {
                        // commit changes to database
                        await Task.Run(() => DatabaseOperations.SaveItem(
                            ThisItem, oPlainText, oRecipients, sDescriptor));
                    }
                    finally
                    {
                        if (ThisItem.ItemType == "text" && oPlainText != null)
                            Array.Clear(oPlainText, 0, oPlainText.Length);
                    }
                });
            }
            finally
            {
                SetBusy(false);
            }
            if (!bSaved) return;

            // close and return to calling dialog
            bCompleted = true;
            Close();
        }

        private X509Certificate2 GetUserKey(IEnumerable<User> SourceUserList)
        {
            // open our local certificate store
            using (X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                oStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection oStoreCertificates = oStore.Certificates;
                try
                {
                    // collate the database certificates to those locally available
                    X509Certificate2Collection oMyCertCollection = new X509Certificate2Collection();
                    foreach (X509Certificate2 oStoreUser in oStoreCertificates)
                    {
                        if (oStoreUser.HasPrivateKey && SourceUserList.Any(u =>
                            u.Certificate.SequenceEqual(oStoreUser.RawData))) oMyCertCollection.Add(oStoreUser);
                    }

                    // error if no valid local certification might be available local certif
                    if (oMyCertCollection.Count == 0)
                        throw new InvalidOperationException("No matching private key " +
                            "was found in your personal certificate store.");

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
        }

        private async void oLoadItemButton_Click(object sender, RoutedEventArgs e)
        {
            if (bBusy) return;
            SetBusy(true, "Checking access and decrypting...");
            try
            {
                await Utilities.TryOperationAsync(this, async () =>
                {
                    byte[] oPlainText;
                    long? nModifier = null;
                    if (ThisItem.Cipher.CipherParams == ItemCryptography.PrincipalFormat)
                        oPlainText = await Task.Run(() => ItemCryptography.Decrypt(ThisItem));
                    else
                    {
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
                            catch (CryptographicException oError) when ((uint)oError.HResult == 0x8010006E ||
                                (uint)oError.HResult == 0x80090036 || (uint)oError.HResult == 0x800704C7)
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
                        // text binary item
                        else BinaryItemData = oPlainText;
                        ThisItem.ModifiedBy = nModifier;
                        SetEditingControls(true);
                    }
                    finally
                    {
                        if (ThisItem.ItemType == "text") Array.Clear(oPlainText, 0, oPlainText.Length);
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
            ribbon.IsEnabled = !bEnabled;
            oEditorPanels.IsEnabled = !bEnabled;
            Cursor = bEnabled ? Cursors.Wait : null;
            if (bEnabled) oItemStatus.Text = sStatus;
            else SetEditingControls(oSaveItemButton.IsEnabled);
        }

        private void LoadProtection()
        {
            bool bWasLoading = bLoading;
            bLoading = true;
            try
            {
                bool bPrincipals = ThisItem.Cipher?.CipherParams == ItemCryptography.PrincipalFormat;
                oProtectionMode.SelectedIndex = bPrincipals ? 0 : 1;
                PrincipalList.Clear();
                if (!bPrincipals) return;
                string sDescriptor = ThisItem.Cipher.ProtectionDescriptor;
                bool bRequireAll;
                foreach (ProtectionPrincipal oPrincipal in PrincipalProtection.ParseDescriptor(
                    sDescriptor, out bRequireAll)) PrincipalList.Add(oPrincipal);
                oPrincipalScope.SelectedIndex = sDescriptor == PrincipalProtection.LocalUserDescriptor ? 1
                    : sDescriptor == PrincipalProtection.LocalMachineDescriptor ? 2 : 0;
                oPrincipalMatch.SelectedIndex = bRequireAll ? 1 : 0;
            }
            finally
            {
                bLoading = bWasLoading;
                UpdateProtectionControls();
            }
        }

        private void UpdateProtectionControls()
        {
            if (oPrincipalPanel == null || oPrincipalHint == null || oCertificatePanel == null) return;
            bool bPrincipals = oProtectionMode.SelectedIndex == 0;
            bool bLocal = oPrincipalScope.SelectedIndex != 0;
            bool bRequiredCertificates = CertificateOperations.GetAutomaticCertificates().Count != 0;
            oRequiredCertificateNotice.Visibility = bRequiredCertificates ? Visibility.Visible : Visibility.Collapsed;
            oPrincipalPanel.Visibility = bPrincipals ? Visibility.Visible : Visibility.Collapsed;
            oCertificatePanel.Visibility = bPrincipals ? Visibility.Collapsed : Visibility.Visible;
            oCertificateSharingGroup.Visibility = bPrincipals ? Visibility.Collapsed : Visibility.Visible;
            oPrincipalTargets.Visibility = bLocal ? Visibility.Collapsed : Visibility.Visible;
            oDomainNotice.Visibility = bDomainJoined ? Visibility.Collapsed : Visibility.Visible;
            oPrincipalHint.Text = oPrincipalScope.SelectedIndex == 2
                ? "Every user on the computer used to encrypt this item can decrypt it " +
                    "if they can read the Vault. This grants access to all local users, " +
                    "not a selected group. Copying it to another computer does not grant access."
                : bLocal ? "Only the Windows profile used to encrypt this item can decrypt it. " +
                    "Copying the Vault does not transfer access."
                : "Domain users and security groups require Active Directory key distribution. " +
                    "Local accounts and groups are not supported in this scope. " +
                    "Include yourself or a recovery group if you need access after saving.";
        }

        private void oProtectionChanged(object sender, SelectionChangedEventArgs e)
        {
            UpdateProtectionControls();
            if (!bLoading && oSaveItemButton != null && oSaveItemButton.IsEnabled) bHasChanges = true;
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
                throw new InvalidOperationException("An item can have up to 100 Windows principals.");
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
                using (DirectoryObjectPickerDialog oPicker = new DirectoryObjectPickerDialog
                {
                    DefaultObjectTypes = ObjectTypes.Users | ObjectTypes.Groups,
                    AllowedObjectTypes = ObjectTypes.Users | ObjectTypes.Groups | ObjectTypes.Computers |
                        ObjectTypes.ServiceAccounts | ObjectTypes.WellKnownPrincipals | ObjectTypes.BuiltInGroups,
                    DefaultLocations = Locations.JoinedDomain,
                    AllowedLocations = Locations.JoinedDomain | Locations.EnterpriseDomain |
                        Locations.GlobalCatalog | Locations.ExternalDomain,
                    MultiSelect = true
                })
                {
                    oPicker.AttributesToFetch.Add("objectSid");
                    if (oPicker.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
                    foreach (DirectoryObject oObject in oPicker.SelectedObjects)
                    {
                        if (!(oObject.FetchedAttributes[0] is byte[] oSid))
                            throw new InvalidOperationException(
                                "The selected object has no Windows security identifier.");
                        AddPrincipal(new ProtectionPrincipal(new SecurityIdentifier(oSid, 0).Value));
                    }
                }
            });
        }

        private void MenuItemWithRadioButtons_Click(object sender, RoutedEventArgs e)
        {
            Fluent.MenuItem oMenu = (Fluent.MenuItem)sender;
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
                using (CryptureEntities oContent = new CryptureEntities())
                {
                    Item oStored = oContent.Items.Find(ThisItem.ItemId);
                    if (oStored != null) oContent.Items.Remove(oStored);
                    oContent.SaveChanges();
                }
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

        private void oItemChanged(object sender, TextChangedEventArgs e)
        {
            if (!bLoading && oSaveItemButton != null && oSaveItemButton.IsEnabled) bHasChanges = true;
        }

        private void oRootWindow_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (bBusy || Keyboard.Modifiers != ModifierKeys.Control) return;
            if (e.Key == Key.S && oSaveItemButton.IsEnabled) oSaveItemButton_Click(sender, e);
            else if (e.Key == Key.L && oLockItemButton.IsEnabled) oLockItemButton_Click(sender, e);
            else return;
            e.Handled = true;
        }

        private void oGeneratePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            if (bBusy || !oSaveItemButton.IsEnabled || ThisItem.ItemType != "text") return;
            Utilities.TryOperation(this, () =>
            {
                PasswordGenerator oGenerator = new PasswordGenerator(true) { Owner = this };
                if (oGenerator.ShowDialog() != true) return;
                int nStart = oItemData.SelectionStart;
                oItemData.SelectedText = oGenerator.SelectedPassword;
                oItemData.Select(nStart + oGenerator.SelectedPassword.Length, 0);
                oItemData.Focus();
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
