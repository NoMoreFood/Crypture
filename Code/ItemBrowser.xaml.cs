using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Collections.ObjectModel;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using System.DirectoryServices;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Ribbon;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;

namespace Crypture
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class ItemBrowser : Window
    {
        public ObservableCollection<Item> ItemList { get; set; } = new ObservableCollection<Item>();

        internal static int RecentVaultLimit => new ConfigurationDefaults().Number("RecentVaultLimit", 10, 0, 50);
        private const string SqlRecentPrefix = "sqlserver:";

        private static readonly string sApplicationTitle =
            $"Crypture {typeof(App).Assembly.GetName().Version.ToString(3)}";

        private string sDatabasePath;
        private bool bCanEnrollCertificates = true;
        private bool bNeedsCertificateReview;
        private List<User> CertificateList = new List<User>();
        private HashSet<string> PrivateCertificates = new HashSet<string>();

        internal bool AddCertificate(X509Certificate2 oCert, string sIdentifier, bool bFromDirectory = false)
        {
            CertificateKeyProtection.ValidateForEncryption(oCert);
            if (!CertificateUsageFilter.Read().Matches(oCert))
                throw new InvalidOperationException("This certificate is excluded by the certificate usage filters " +
                    "in Crypture.exe.config.");
            if (!CertificateOperations.CheckCertificateStatus(oCert, true))
                throw new InvalidOperationException("Select a valid RSA, ECDH, or ML-KEM encryption certificate. " +
                    "Review the certificate validation settings and selection filters in Crypture.exe.config.");
            using (CryptureEntities oContent = new CryptureEntities())
            {
                User oExisting = oContent.Users.ToList().FirstOrDefault(u =>
                    u.Certificate.AsSpan().SequenceEqual(oCert.RawData));
                if (oExisting != null && (CryptureEntities.Storage is not SqlServerVaultStorage ||
                    oExisting.Sid != null))
                {
                    MessageBox.Show(this,
                         "The selected certificate is already in the Vault.",
                         "Certificate In Vault", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    return false;
                }

                if (CryptureEntities.Storage is SqlServerVaultStorage oSqlServer)
                {
                    if (bFromDirectory)
                        SqlServerCertificateEnrollment.EnrollFromDirectory(oSqlServer, oCert, sIdentifier,
                            oExisting?.UserId);
                    else SqlServerCertificateEnrollment.EnrollOwn(oSqlServer, oCert, oExisting?.UserId);
                    oRefreshItemButton_Click();
                    return true;
                }

                bool bAmOwner = CertificateOperations.GetPrivateCertificateData().Contains(
                    Convert.ToBase64String(oCert.RawData)) && MessageBox.Show(this,
                    "Are you the owner of the selected certificate?",
                    "Ownership Confirmation",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

                string sOwnerSid = bAmOwner || sIdentifier != CertificateOperations.CurrentUserSid
                    ? sIdentifier : null;
                User oUser = new User()
                {
                    Certificate = oCert.GetRawCertData(),
                    Sid = sOwnerSid
                };
                oContent.Users.Add(oUser);
                oContent.SaveChanges();
                oRefreshItemButton_Click();
            }

            return true;
        }

        public ItemBrowser()
        {
            // display splash screen and set to automatically close after constructor returns
            SplashScreen oScreen = new SplashScreen(Assembly.GetExecutingAssembly(), "Images/Save.png");
            oScreen.Show(true);

            // initialize xaml form display
            InitializeComponent();
            Title = sApplicationTitle;
            ConfigurationDefaults oDefaults = new ConfigurationDefaults();
            oHideAccessible.IsChecked = oDefaults.Flag("HideMissingCertificateKeys", false);
            ribbon.IsMinimized = oDefaults.Flag("RibbonMinimized", false);
            oSqlServerButton.Visibility = oDefaults.Flag("HideSqlServerOption", false)
                ? Visibility.Collapsed : Visibility.Visible;
            oAddFromAdButton.IsEnabled = PrincipalProtection.IsDomainJoined;
            RefreshRecentVaults();

            string[] sArgs = Environment.GetCommandLineArgs();
            if (sArgs.Length > 1) LoadDatabase(sArgs[1]);

            // show certificate generator based on settings file
            bool bCertificates = Properties.Settings.Default.EnableCertificateProtection;
            oCertificatesTab.Visibility = bCertificates ? Visibility.Visible : Visibility.Collapsed;
            oProtectedItemScopeRibbonGroupBox.Visibility = oCertificatesTab.Visibility;
            oCertificateToolsGroupBox.Visibility = bCertificates && Properties.Settings.Default.ShowCertificateTools
                ? Visibility.Visible : Visibility.Collapsed;
        }

        private void oRemoveItemUser_Click(object sender, RoutedEventArgs e)
        {
            // get the selected object based on what button was pressed
            object oObject = (sender == oRemoveCertButton) ?
                oCertDataGrid.SelectedItem : oItemDataGrid.SelectedItem;

            // prevent removal of automatic certificate
            if (oObject is User)
            {
                if (CertificateOperations.GetAutomaticCertificates().Where(u => 
                    StructuralComparisons.StructuralEqualityComparer.Equals(u, ((User) oObject).Certificate)).Count() > 0)
                {
                    MessageBox.Show(this, "Removal of automatic certificate is prohibited.",
                        "Removal Prohibited", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    return;
                }
            }

            // confirm removal
            if (oObject == null || MessageBox.Show(this,
                    "Are you sure you want to remove '" + ((oObject is User) ?
                    ((User)oObject).Name : ((Item)oObject).Label) + "'?",
                    "Removal Confirmation",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            {
                return;
            }

            // remove select item or user
            Utilities.TryOperation(this, () =>
            {
                if (oObject is User oUser) DatabaseOperations.RemoveCertificate(oUser.UserId);
                else DatabaseOperations.DeleteItem(((Item)oObject).ItemId);
                oRefreshItemButton_Click();
            });
        }

        private void oAddFromFileButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                OpenFileDialog oOpenDialog = new OpenFileDialog
                {
                    Filter = "Certificate Files (*.cer)|*.cer|All Files (*.*)|*.*", CheckFileExists = true
                };
                if (oOpenDialog.ShowDialog(this) != true) return;
                if (X509Certificate2.GetCertContentType(oOpenDialog.FileName) != X509ContentType.Cert)
                    throw new InvalidOperationException("Select a public certificate (.cer). " +
                        "Import private keys using Windows.");
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificateFromFile(oOpenDialog.FileName))
                    AddCertificate(oCert, CertificateOperations.CurrentUserSid);
            });
        }

        private void oAddFromStoreButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                CertificateUsageFilter oUsageFilter = CertificateUsageFilter.Read();

                // Open the user and computer personal certificate stores.
                X509Certificate2Collection oCertificates = CertificateOperations.GetPersonalCertificates();
                try
                {
                    // Filter eligible encryption certificates before opening the selector.
                    X509Certificate2Collection oCollection = new X509Certificate2Collection();
                    foreach (X509Certificate2 oCert in oCertificates)
                        if (oUsageFilter.Matches(oCert) &&
                            CertificateOperations.CheckCertificateStatus(oCert, true))
                            oCollection.Add(oCert);
                    if (oCollection.Count == 0)
                        throw new InvalidOperationException("No certificates match the usage filters and " +
                            "certificate validation settings.");

                    // ask the user which certificate to publish
                    oCollection = X509Certificate2UI.SelectFromCollection(oCollection,
                        "Select Certificate", "Select Certificate To Add",
                        X509SelectionFlag.SingleSelection, new WindowInteropHelper(this).Handle);

                    // commit the certificate to the database
                    foreach (X509Certificate2 oCert in oCollection)
                        AddCertificate(oCert, CertificateOperations.CurrentUserSid);
                }
                finally
                {
                    foreach (X509Certificate2 oCert in oCertificates) oCert.Dispose();
                }
            });
        }

        private void oAddFromAdButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                CertificateUsageFilter oUsageFilter = CertificateUsageFilter.Read();
                DirectoryPicker oPicker = new DirectoryPicker(true) { Owner = this };

                // show dialog and return if cancelled
                if (oPicker.ShowDialog() != true) return;
                foreach (DirectoryAccount oAccount in oPicker.SelectedAccounts)
                {
                    // skip if no certificate information was found
                    if (oAccount.Certificates.Length == 0)
                    {
                        MessageBox.Show(this, "There was no certificate associated with '" + oAccount.Name + "'.",
                            "No Certificate Information Found", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                        continue;
                    }

                    // Filter eligible encryption certificates before opening the selector.
                    X509Certificate2Collection oCollection = new X509Certificate2Collection();
                    try
                    {
                        foreach (byte[] oCertData in oAccount.Certificates)
                        {
                            using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oCertData))
                                if (oUsageFilter.Matches(oCert) &&
                                    CertificateOperations.CheckCertificateStatus(oCert, true))
                                    oCollection.Add(new X509Certificate2(oCert));
                        }
                        if (oCollection.Count == 0) continue;

                        // ask the user which certificate to publish
                        X509Certificate2Collection oSelected = oCollection.Count == 1 ? oCollection :
                            X509Certificate2UI.SelectFromCollection(oCollection, "Select Certificate",
                                "Select Certificate To Add", X509SelectionFlag.SingleSelection,
                                new WindowInteropHelper(this).Handle);
                        if (oSelected.Count == 0) continue;

                        // add the certificate to the store
                        AddCertificate(oSelected[0], oAccount.Sid, true);
                    }
                    finally
                    {
                        foreach (X509Certificate2 oCert in oCollection) oCert.Dispose();
                    }
                }
            });
        }

        private void oMarkEscrowButton_Click(object sender, RoutedEventArgs e)
        {
            if (oCertDataGrid.SelectedItem is not User oUser ||
                CryptureEntities.Storage is not SqlServerVaultStorage oStorage) return;
            if (oUser.IsEscrow)
            {
                MessageBox.Show(this, "This certificate is already designated for emergency recovery.",
                    "Escrow Certificate", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (MessageBox.Show(this, "Use this AD-published certificate as the Vault's escrow identity? " +
                "New saves will include it automatically. Existing items keep their saved recovery identity " +
                "until they are decrypted and saved again.", "Designate Escrow Certificate",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            Utilities.TryOperation(this, () =>
            {
                SqlServerCertificateEnrollment.MarkEscrow(oStorage, oUser);
                oRefreshItemButton_Click();
            });
        }

        private void oThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ComboBox oSelector = (ComboBox)sender;
            if (!oSelector.IsLoaded || !(oSelector.SelectedItem is ComboBoxItem oTheme)) return;
            Properties.Settings.Default.ThemeMode = (string)oTheme.Tag;
            App.ApplyThemePreference();
            Utilities.TryOperation(this, () => Properties.Settings.Default.Save());
        }

        private void Ribbon_SelectedTabChanged(object sender, SelectionChangedEventArgs e)
        {
            if (oItemDataGrid == null || oCertDataGrid == null) return;
            if (ribbonTabHome.IsSelected || oViewTab.IsSelected)
            {
                oItemDataGrid.Visibility = Visibility.Visible;
                oCertDataGrid.Visibility = Visibility.Hidden;
            }
            if (oCertificatesTab.IsSelected)
            {
                oItemDataGrid.Visibility = Visibility.Hidden;
                oCertDataGrid.Visibility = Visibility.Visible;
            }
            if (oAdvancedTab.IsSelected)
            {
                oItemDataGrid.Visibility = Visibility.Hidden;
                oCertDataGrid.Visibility = Visibility.Hidden;
            }
            ApplyFilter();
        }

        private void oViewCertButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                // sanity check
                if (oCertDataGrid.SelectedItem == null) return;

                // display the selected certificate
                User oUser = (User)oCertDataGrid.SelectedItem;
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oUser.Certificate))
                {
                    X509Certificate2UI.DisplayCertificate(oCert);
                }
            });
        }

        private void oCertDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (ItemsControl.ContainerFromElement(oCertDataGrid, e.OriginalSource as DependencyObject) is DataGridRow)
                oViewCertButton_Click(sender, e);
        }

        private void oViewItemButton_Click(object sender, RoutedEventArgs e)
        {
            Item oItem = oItemDataGrid.SelectedItem as Item;
            if (oItem == null || e is MouseButtonEventArgs &&
                !(ItemsControl.ContainerFromElement(oItemDataGrid, e.OriginalSource as DependencyObject) is DataGridRow))
                return;
            Utilities.TryOperation(this, () =>
            {
                ItemEditor oViewer = new ItemEditor(oItem) { Owner = this };
                oViewer.ShowDialog();
                oRefreshItemButton_Click();
            });
        }

        private void oAddItemButton_Click(object sender, RoutedEventArgs e)
        {
            if (!Properties.Settings.Default.EnableDpapiNgProtection &&
                !Properties.Settings.Default.EnableCertificateProtection) return;
            Utilities.TryOperation(this, () =>
            {
                ItemEditor oViewer = new ItemEditor { Owner = this };
                oViewer.ShowDialog();
                oRefreshItemButton_Click();
            });
        }

        private void oRefreshItemButton_Click(object sender = null, RoutedEventArgs e = null)
        {
            if (String.IsNullOrEmpty(sDatabasePath)) return;
            Utilities.TryOperation(this, RefreshData);
        }

        private void RefreshData()
        {
            if (CryptureEntities.Storage is SqlServerVaultStorage oSqlStorage) oSqlStorage.RefreshEscrow();
            List<Item> oItems = null;
            List<User> oUsers = null;
            HashSet<string> oPrivate = CertificateOperations.GetPrivateCertificateData();
            using (CryptureEntities oContent = new CryptureEntities())
            {
                // Keep item rows, recipients, and protection metadata in one read snapshot during concurrent saves.
                CryptureEntities.Storage.ReadSnapshot(oContent, () =>
                {
                    oItems = oContent.Items.Include(i => i.User).Include(i => i.Instances)
                        .ThenInclude(j => j.User).ToList();
                    oUsers = oContent.Users.ToList();
                    var oProtection = oContent.Ciphers.Select(c => new
                    {
                        c.ItemId, c.CipherParams, c.ProtectionDescriptor, c.EscrowLabel
                    }).ToDictionary(c => c.ItemId);
                    foreach (Item oItem in oItems)
                    {
                        if (!oProtection.TryGetValue(oItem.ItemId, out var oPolicy)) continue;
                        oItem.Cipher = new Cipher
                        {
                            CipherParams = oPolicy.CipherParams, ProtectionDescriptor = oPolicy.ProtectionDescriptor,
                            EscrowLabel = oPolicy.EscrowLabel
                        };
                    }
                });
            }
            ItemList = new ObservableCollection<Item>(oItems.OrderBy(i => i.Label));
            CertificateList = oUsers.OrderBy(u => u.Name).ToList();
            bNeedsCertificateReview = CryptureEntities.Storage.IsSqlServer &&
                CertificateList.Any(u => u.Sid == null);
            PrivateCertificates = oPrivate;
            ApplyFilter();
        }

        private void ApplyFilter()
        {
            if (oSearchTextBox == null || oItemDataGrid == null ||
                oCertDataGrid == null || oCountStatus == null) return;
            long? nSelectedItem = (oItemDataGrid.SelectedItem as Item)?.ItemId;
            long? nSelectedUser = (oCertDataGrid.SelectedItem as User)?.UserId;
            string sSearch = oSearchTextBox.Text.Trim();
            List<Item> oItems = ItemList.Where(i =>
                (i.Label.IndexOf(sSearch, StringComparison.CurrentCultureIgnoreCase) >= 0 ||
                    i.ModifiedByDisplay.IndexOf(sSearch, StringComparison.CurrentCultureIgnoreCase) >= 0 ||
                    i.ProtectionDisplay.IndexOf(sSearch, StringComparison.CurrentCultureIgnoreCase) >= 0 ||
                    i.ItemTypeDisplay.IndexOf(sSearch, StringComparison.CurrentCultureIgnoreCase) >= 0 ||
                    (i.Cipher?.ProtectionDescriptor?.IndexOf(sSearch, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0) &&
                (oHideAccessible.IsChecked != true || ItemCryptography.UsesWindowsProtection(i.Cipher) ||
                    i.Cipher?.CipherParams == ItemCryptography.RecoveryFormat ||
                    i.Instances.Any(j =>
                    PrivateCertificates.Contains(Convert.ToBase64String(j.User.Certificate))))).ToList();
            List<User> oUsers = CertificateList.Where(u =>
                u.Name.IndexOf(sSearch, StringComparison.CurrentCultureIgnoreCase) >= 0 ||
                (u.Sid?.IndexOf(sSearch, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0).ToList();
            oItemDataGrid.ItemsSource = oItems;
            oCertDataGrid.ItemsSource = oUsers;
            oItemDataGrid.SelectedItem = oItems.FirstOrDefault(i => i.ItemId == nSelectedItem);
            oCertDataGrid.SelectedItem = oUsers.FirstOrDefault(u => u.UserId == nSelectedUser);
            bool bCertificates = oCertificatesTab.IsSelected;
            int nCount = bCertificates ? oUsers.Count : oItems.Count;
            oCountStatus.Text = bCertificates ? nCount + " certificates" : nCount + " of " + ItemList.Count + " items";
            oEmptyState.Text = String.IsNullOrEmpty(sDatabasePath) ? "Create or load a Vault to get started."
                : sSearch.Length != 0 ? "No matches. Try another search."
                : bCertificates ? bCanEnrollCertificates
                    ? "Add a certificate from your personal store to get started."
                    : "Ask the Vault owner to enroll a verified certificate."
                : bNeedsCertificateReview
                    ? "Some items may be hidden until the Vault owner verifies certificate affiliations."
                : "No items to show. Add an item or adjust the accessibility filter.";
            oEmptyState.Visibility = nCount == 0 && !oAdvancedTab.IsSelected
                ? Visibility.Visible : Visibility.Collapsed;
        }

        private void oSearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplyFilter();
        }

        private void oHideAccessible_Click(object sender, RoutedEventArgs e)
        {
            ApplyFilter();
        }

        private void oGeneratePasswordButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () => new PasswordGenerator { Owner = this }.ShowDialog());
        }

        private void oGenerateCertButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                CertWizard oWiz = new CertWizard { Owner = this };
                oWiz.ShowDialog();
            });
        }

        private void oNewDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                // ask the user where to store the file
                SaveFileDialog oSaveDialog = new SaveFileDialog
                {
                    Title = "Create Vault",
                    Filter = "Crypture Vault File (*.cryptdb)|*.cryptdb|All Files (*.*)|*.*",
                    DefaultExt = ".cryptdb", AddExtension = true, ValidateNames = true, OverwritePrompt = false
                };
                if (oSaveDialog.ShowDialog(this) != true) return;

                // Create the selected file and open the new Vault.
                SqliteVaultStorage oStorage = new SqliteVaultStorage(Path.GetFullPath(oSaveDialog.FileName));
                oStorage.Create();
                if (LoadVault(oStorage, false)) oAddItemButton_Click(sender, e);
            });
        }

        private static void AddAutomaticCertificates()
        {
            // SQL Server certificates require explicit owner enrollment and cannot be inserted from local settings.
            if (CryptureEntities.Storage.IsSqlServer) return;
            using (CryptureEntities oContent = new CryptureEntities())
            {
                List<User> oUsers = oContent.Users.ToList();
                // cycle through mandatory certificates to add
                foreach (byte[] bCertData in CertificateOperations.GetAutomaticCertificates())
                {
                    // skip certificates already in database
                    if (oUsers.Any(u => u.Certificate.SequenceEqual(bCertData))) continue;
                    using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(bCertData))
                        CertificateKeyProtection.ValidateForEncryption(oCert);
                    // create new item to add
                    User oUser = new User { Certificate = bCertData };
                    oContent.Users.Add(oUser);
                    oUsers.Add(oUser);
                }
                oContent.SaveChanges();
            }
        }

        private bool LoadDatabase(string sDatabase, bool bEnableControls = true) =>
            LoadVault(new SqliteVaultStorage(Path.GetFullPath(sDatabase)), false, bEnableControls);

        private bool LoadVault(IVaultStorage oStorage, bool bCreate, bool bEnableControls = true)
        {
            const int SchemaProbeRows = 1;
            IVaultStorage oPreviousStorage = CryptureEntities.Storage;
            string sPreviousPath = sDatabasePath;
            try
            {
                if (bCreate) oStorage.Create();
                else oStorage.Validate();
                CryptureEntities.Storage = oStorage;
                using (CryptureEntities oContent = new CryptureEntities())
                {
                    oContent.Items.Take(SchemaProbeRows).Load();
                    oContent.Users.Take(SchemaProbeRows).Load();
                    oContent.Ciphers.Take(SchemaProbeRows).Load();
                    oContent.Instances.Take(SchemaProbeRows).Load();
                }
                AddAutomaticCertificates();
                sDatabasePath = oStorage.DisplayName;
                RefreshData();
                oProtectedItemActionRibbonGroupBox.IsEnabled = bEnableControls;
                oAddItemButton.IsEnabled = bEnableControls && (Properties.Settings.Default.EnableDpapiNgProtection ||
                    Properties.Settings.Default.EnableCertificateProtection);
                oProtectedItemScopeRibbonGroupBox.IsEnabled = bEnableControls;
                oCertificatesTab.IsEnabled = bEnableControls;
                oClaimCertButton.Visibility = oStorage.IsSqlServer ? Visibility.Collapsed : Visibility.Visible;
                oAffiliationColumn.Visibility = oStorage.IsSqlServer ? Visibility.Visible : Visibility.Collapsed;
                bool bCanEnroll = oStorage is not SqlServerVaultStorage oSqlEnrollment ||
                    oSqlEnrollment.CanEnrollCertificates();
                bCanEnrollCertificates = bCanEnroll;
                oAddCertificateGroup.Visibility = bCanEnroll ? Visibility.Visible : Visibility.Collapsed;
                oAddFromStoreButton.IsEnabled = bCanEnroll;
                oAddFromFileButton.IsEnabled = bCanEnroll;
                oAddFromAdButton.IsEnabled = bCanEnroll && PrincipalProtection.IsDomainJoined;
                oMarkEscrowButton.Visibility = oStorage.IsSqlServer && bCanEnroll &&
                    PrincipalProtection.IsDomainJoined
                    ? Visibility.Visible : Visibility.Collapsed;
                oAdvancedTab.IsEnabled = bEnableControls;

                // Offer server-side backup only to accounts permitted to perform it.
                bool bCanBackup = oStorage is not SqlServerVaultStorage oSqlBackup || oSqlBackup.CanBackup();
                oBackupDatabaseButton.Visibility = bCanBackup ? Visibility.Visible : Visibility.Collapsed;
                oBackupDatabaseButton.IsEnabled = bEnableControls;
                oBackupDatabaseButton.ToolTip = oStorage.IsSqlServer
                    ? "Create a backup on the SQL Server host." : "Create a consistent copy of the encrypted Vault.";
                oCompactDatabaseButton.Visibility = oStorage.SupportsCompact ? Visibility.Visible : Visibility.Collapsed;
                oSearchTextBox.IsEnabled = bEnableControls;
                oDatabaseStatus.Text = oStorage.DisplayName;
                Title = sApplicationTitle + " - " + (oStorage.IsSqlServer
                    ? oStorage.DisplayName : Path.GetFileName(oStorage.DisplayName));
                if (oStorage is SqlServerVaultStorage oSqlServer)
                    RememberRecentEntry(SqlRecentPrefix + oSqlServer.RecentConnection);
                else RememberRecentVault(oStorage.DisplayName);
                if (oStorage is SqlServerVaultStorage { UpgradedOnOpen: true } &&
                    bNeedsCertificateReview)
                    Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() =>
                        MessageBox.Show(this, "Certificate affiliations need verification. Open Certificates " +
                            "and add each unverified certificate from Active Directory or your personal " +
                            "store. Encrypted items remain stored and become accessible as their " +
                            "certificates are verified.", "Verify Certificate Affiliations",
                            MessageBoxButton.OK, MessageBoxImage.Information)));
                return true;
            }
            catch (Exception eError)
            {
                CryptureEntities.Storage = oPreviousStorage;
                sDatabasePath = sPreviousPath;
                Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() =>
                {
                    MessageBox.Show(this, "The Vault could not be opened: " +
                        Environment.NewLine + Environment.NewLine + eError.GetBaseException().Message,
                        "Vault Connection Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }));
                return false;
            }
        }

        private void oSqlServerButton_Click(object sender, RoutedEventArgs e)
        {
            SqlServerVaultDialog oDialog = new SqlServerVaultDialog { Owner = this };
            if (oDialog.ShowDialog() != true) return;
            OpenSqlVault(oDialog.Storage, oDialog.CreateDatabase);
        }

        private async void OpenSqlVault(SqlServerVaultStorage oStorage, bool bCreate)
        {
            // Paint connection feedback before opening a remote database.
            string sPreviousStatus = oDatabaseStatus.Text;
            Cursor oPreviousCursor = Mouse.OverrideCursor;
            oDatabaseStatus.Text = bCreate ? "Creating SQL Server Vault..." : "Connecting to SQL Server...";
            Mouse.OverrideCursor = Cursors.Wait;
            await Dispatcher.Yield(DispatcherPriority.Background);
            bool bLoaded = false;
            try
            {
                bLoaded = LoadVault(oStorage, bCreate);
                if (!bLoaded) oDatabaseStatus.Text = sPreviousStatus;
            }
            finally { Mouse.OverrideCursor = oPreviousCursor; }
            if (bLoaded && bCreate) oAddItemButton_Click(this, null);
        }

        private void oLoadDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            // ask the user where to store the file
            OpenFileDialog oSaveDialog = new OpenFileDialog()
            {
                Title = "Open Vault",
                Filter = "Crypture Vault File (*.cryptdb)|*.cryptdb|All Files (*.*)|*.*",
                CheckFileExists = true
            };
            if (!oSaveDialog.ShowDialog(this).Value) return;
            LoadDatabase(oSaveDialog.FileName);
        }

        internal void RememberRecentVault(string sPath) => RememberRecentEntry(Path.GetFullPath(sPath));

        private void RememberRecentEntry(string sEntry)
        {
            // Keep the last Vault even when recent history is disabled.
            Properties.Settings.Default.LastVault = sEntry;
            StringCollection oRecent = new StringCollection();
            oRecent.AddRange(new[] { sEntry }.Concat(Properties.Settings.Default.RecentVaults?.Cast<string>() ?? [])
                .Where(p => !String.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(RecentVaultLimit).ToArray());
            Properties.Settings.Default.RecentVaults = oRecent;
            RefreshRecentVaults();
            SaveRecentVaults();
        }

        private void RefreshRecentVaults()
        {
            // Keep menu labels literal so underscores in Vault filenames are not treated as access keys.
            oLoadDatabaseButton.Items.Clear();
            string[] oPaths = (Properties.Settings.Default.RecentVaults?.Cast<string>() ?? [])
                .Where(p => !String.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(RecentVaultLimit).ToArray();
            for (int nIndex = 0; nIndex < oPaths.Length; nIndex++)
            {
                string sPath = oPaths[nIndex];
                string sLabel = Path.GetFileName(sPath);
                string sTooltip = sPath;
                if (sPath.StartsWith(SqlRecentPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        SqlServerVaultStorage oSqlServer = new SqlServerVaultStorage(sPath[SqlRecentPrefix.Length..]);
                        sLabel = "SQL: " + oSqlServer.DisplayName;
                        sTooltip = oSqlServer.DisplayName;
                    }
                    catch (ArgumentException) { sLabel = "SQL Server Vault"; sTooltip = "Invalid recent connection"; }
                }
                RibbonMenuItem oEntry = new RibbonMenuItem
                {
                    Header = new TextBlock { Text = (nIndex + 1) + ". " + sLabel },
                    ToolTip = sTooltip, Tag = sPath, KeyTip = (nIndex + 1).ToString()
                };
                oEntry.Click += oRecentVault_Click;
                oLoadDatabaseButton.Items.Add(oEntry);
            }
            if (oPaths.Length == 0)
                oLoadDatabaseButton.Items.Add(new RibbonMenuItem { Header = "No Recent Vaults", IsEnabled = false });
            oLoadDatabaseButton.Items.Add(new RibbonSeparator());
            RibbonMenuItem oClear = new RibbonMenuItem { Header = "_Clear Recent Vaults", IsEnabled = oPaths.Length > 0 };
            oClear.Click += oClearRecentVaults_Click;
            oLoadDatabaseButton.Items.Add(oClear);
        }

        private void SaveRecentVaults()
        {
            // Preference persistence must not undo an otherwise successful Vault load.
            try
            {
                Properties.Settings.Default.Save();
            }
            catch (Exception oError) when (oError is ConfigurationErrorsException || oError is IOException ||
                oError is UnauthorizedAccessException)
            {
                oDatabaseStatus.ToolTip = "Recent Vaults could not be saved: " + oError.Message;
            }
        }

        private void oLoadDatabaseButton_DropDownOpened(object sender, EventArgs e)
        {
            RefreshRecentVaults();
        }

        private void oRecentVault_Click(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            oLoadDatabaseButton.IsDropDownOpen = false;
            OpenRecentVault((string)((RibbonMenuItem)sender).Tag);
        }

        private void OpenRecentVault(string sEntry)
        {
            if (!sEntry.StartsWith(SqlRecentPrefix, StringComparison.OrdinalIgnoreCase))
            {
                LoadDatabase(sEntry);
                return;
            }
            string sConnection = sEntry[SqlRecentPrefix.Length..];
            try
            {
                SqlServerVaultStorage oStorage = new SqlServerVaultStorage(sConnection);
                OpenSqlVault(oStorage, false);
            }
            catch (ArgumentException oError)
            {
                MessageBox.Show(this, oError.Message, "Invalid Recent Vault",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void oClearRecentVaults_Click(object sender, RoutedEventArgs e)
        {
            e.Handled = true;
            oLoadDatabaseButton.IsDropDownOpen = false;
            Properties.Settings.Default.RecentVaults = new StringCollection();
            RefreshRecentVaults();
            SaveRecentVaults();
        }

        private void oClaimCertButton_Click(object sender, RoutedEventArgs e)
        {
            // sanity check
            User oUser = oCertDataGrid.SelectedItem as User;
            if (oUser == null) return;
            Utilities.TryOperation(this, () =>
            {
                if (!CertificateOperations.GetPrivateCertificateData()
                    .Contains(Convert.ToBase64String(oUser.Certificate)))
                    throw new InvalidOperationException("Import the matching private key " +
                        "into your personal store before claiming it.");

                // ask for concurrence concur
                if (MessageBox.Show(this, "Associate the selected certificate with your Windows account?",
                    "Confirm Ownership Change Request", MessageBoxButton.YesNo,
                    MessageBoxImage.Question) != MessageBoxResult.Yes) return;

                // update the ownership on the selected certificate
                using (CryptureEntities oContent = new CryptureEntities())
                {
                    User oStored = oContent.Users.Find(oUser.UserId);
                    if (oStored == null)
                        throw new InvalidOperationException("This certificate has been removed. Refresh the list.");
                    oStored.Sid = CertificateOperations.CurrentUserSid;
                    oContent.SaveChanges();
                }
                oRefreshItemButton_Click();
            });
        }

        private void oAboutButton_Click(object sender, RoutedEventArgs e)
        {
            AboutBox oAboutBox = new AboutBox();
            oAboutBox.Owner = this;
            oAboutBox.ShowDialog();
        }

        private void oHealthCheckButton_Click(object sender, RoutedEventArgs e)
        {
            if (String.IsNullOrEmpty(sDatabasePath)) return;
            Utilities.TryOperation(this, () => new VaultHealthWindow(CryptureEntities.Storage)
                { Owner = this }.ShowDialog());
        }

        private void oCompactDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                CryptureEntities.Storage.Compact();
                MessageBox.Show(this, "Compact operation complete.",
                    "Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            });
        }

        private void oBackupDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            if (String.IsNullOrEmpty(sDatabasePath)) return;
            Utilities.TryOperation(this, () =>
            {
                if (CryptureEntities.Storage is SqlServerVaultStorage oSqlServer)
                {
                    SqlServerBackupDialog oSqlDialog = new SqlServerBackupDialog(oSqlServer.DatabaseName)
                        { Owner = this };
                    if (oSqlDialog.ShowDialog() != true) return;
                    oSqlServer.Backup(oSqlDialog.BackupPath);
                    MessageBox.Show(this, "SQL Server Vault backup created on the server. " +
                        "Keep certificate private keys backed up separately.",
                        "Backup Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                SaveFileDialog oDialog = new SaveFileDialog
                {
                    Title = "Back Up Vault",
                    Filter = "Crypture Vault File (*.cryptdb)|*.cryptdb",
                    FileName = Path.GetFileNameWithoutExtension(sDatabasePath) + "-backup-" +
                        DateTime.Now.ToString("yyyyMMdd-HHmmss"),
                    DefaultExt = ".cryptdb", AddExtension = true, OverwritePrompt = false
                };
                if (oDialog.ShowDialog(this) != true) return;
                DatabaseOperations.BackupDatabase(sDatabasePath, oDialog.FileName);
                MessageBox.Show(this, "Encrypted Vault backup created. " +
                    "Keep your certificate private keys backed up separately.",
                    "Backup Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            });
        }

        private void oItemBrowser_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.F)
            {
                oSearchTextBox.Focus();
                oSearchTextBox.SelectAll();
            }
            else if (e.Key == Key.F5 && !String.IsNullOrEmpty(sDatabasePath)) oRefreshItemButton_Click();
            else if (e.Key == Key.Enter && Keyboard.Modifiers == ModifierKeys.None)
            {
                if (oItemDataGrid.IsKeyboardFocusWithin) oViewItemButton_Click(sender, e);
                else if (oCertDataGrid.IsKeyboardFocusWithin) oViewCertButton_Click(sender, e);
                else return;
            }
            else return;
            e.Handled = true;
        }

        private void oItemBrowser_Closing(object sender, CancelEventArgs e)
        {
            Utilities.TryOperation(this, () => Properties.Settings.Default.Save());
        }

        private void oItemBrowser_Loaded(object sender, RoutedEventArgs e)
        {
            // A command-line Vault takes precedence over the last successful connection.
            if (String.IsNullOrEmpty(sDatabasePath) && Environment.GetCommandLineArgs().Length == 1)
            {
                string sLastVault = Properties.Settings.Default.LastVault;
                if (String.IsNullOrWhiteSpace(sLastVault))
                    sLastVault = Properties.Settings.Default.RecentVaults?.Cast<string>()
                        .FirstOrDefault(p => !String.IsNullOrWhiteSpace(p));
                if (sLastVault?.StartsWith(SqlRecentPrefix, StringComparison.OrdinalIgnoreCase) == true)
                    OpenRecentVault(sLastVault);
                else if (!String.IsNullOrWhiteSpace(sLastVault)) LoadDatabase(sLastVault);
            }

            if (!string.IsNullOrWhiteSpace(Properties.Settings.Default.StartupMessageText))
            {
                Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(delegate ()
                {
                    MessageBox.Show(this, Properties.Settings.Default.StartupMessageText,
                        "Welcome To Crypture", MessageBoxButton.OK,
                        MessageBoxImage.Information, MessageBoxResult.OK);
                }));
            }
        }
    }
}
