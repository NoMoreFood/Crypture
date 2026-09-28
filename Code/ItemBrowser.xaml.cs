using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.Entity;
using System.Data.SQLite;
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
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Threading;
using Tulpep.ActiveDirectoryObjectPicker;

namespace Crypture
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class ItemBrowser : Fluent.RibbonWindow
    {
        public ObservableCollection<Item> ItemList { get; set; } = new ObservableCollection<Item>();

        private string sDatabasePath;
        private List<User> CertificateList = new List<User>();
        private HashSet<string> PrivateCertificates = new HashSet<string>();

        internal bool AddCertificate(X509Certificate2 oCert, string sIdentifier)
        {
            CertificateKeyProtection.ValidateForEncryption(oCert);
            if (!CertificateOperations.CheckCertificateStatus(oCert))
                throw new InvalidOperationException("Select a valid RSA, ECDH, or ML-KEM encryption certificate. " +
                    "Review the certificate validation settings if you use a self-signed certificate.");
            using (CryptureEntities oContent = new CryptureEntities())
            {
                if (oContent.Users.Where(u => u.Certificate == oCert.RawData).Count() > 0)
                {
                    MessageBox.Show(this,
                         "The selected certificate is already in the Vault.",
                         "Certificate In Vault", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    return false;
                }

                bool bAmOwner = CertificateOperations.GetPrivateCertificateData().Contains(
                    Convert.ToBase64String(oCert.RawData)) && MessageBox.Show(this,
                    "Are you the owner of the selected certificate?",
                    "Ownership Confirmation",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

                User oUser = new User()
                {
                    Certificate = oCert.GetRawCertData(),
                    Sid = bAmOwner || sIdentifier != CertificateOperations.CurrentUserSid ? sIdentifier : null
                };
                oContent.Users.Add(oUser);
                oContent.SaveChanges();
                oRefreshItemButton_Click();
            }

            return true;
        }

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        public ItemBrowser()
        {
            // display splash screen and set to automatically close after constructor returns
            SplashScreen oScreen = new SplashScreen(Assembly.GetExecutingAssembly(), "Images/Save.png");
            oScreen.Show(true);

            // initialize xaml form display
            InitializeComponent();
            oAddFromAdButton.IsEnabled = PrincipalProtection.IsDomainJoined;

            string[] sArgs = Environment.GetCommandLineArgs();
            if (sArgs.Length > 1) LoadDatabase(sArgs[1]);

            // load in cleaner library
            string sBaseDirectory = Path.GetDirectoryName(Assembly.GetEntryAssembly().Location);
            string sArchSetting = (Environment.Is64BitProcess) ? "x64" : "x86";
            string sLibPath = Path.Combine(new string[] { sBaseDirectory, sArchSetting, "Crypture-WrapperEnabler.dll" });
            if (File.Exists(sLibPath))
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                LoadLibrary(sLibPath);
            }

            // show certificate generator based on settings file
            oCertificateToolsGroupBox.Visibility = (Properties.Settings.Default.ShowCertificateTools) ?
                Visibility.Visible : Visibility.Collapsed;
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
                else using (CryptureEntities oContent = new CryptureEntities())
                {
                    oContent.Entry(oObject).State = EntityState.Deleted;
                    oContent.SaveChanges();
                }
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
                using (X509Certificate2 oCert = new X509Certificate2(oOpenDialog.FileName))
                    AddCertificate(oCert, CertificateOperations.CurrentUserSid);
            });
        }

        private void oAddFromStoreButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                // open the locate personal certificate store
                using (X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    oStore.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection oCertificates = oStore.Certificates;
                    try
                    {
                        // downselect to only display rsa certs
                        X509Certificate2Collection oCollection = new X509Certificate2Collection();
                        foreach (X509Certificate2 oCert in oCertificates)
                            if (CertificateOperations.CheckCertificateStatus(oCert)) oCollection.Add(oCert);

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
                }
            });
        }

        private void oAddFromAdButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                using (DirectoryObjectPickerDialog oPicker = new DirectoryObjectPickerDialog()
                {
                    DefaultObjectTypes = ObjectTypes.Users,
                    AllowedObjectTypes = ObjectTypes.Users,
                    MultiSelect = true,
                    DefaultLocations = Locations.GlobalCatalog,
                    AllowedLocations = Locations.All
                })
                {
                    oPicker.AttributesToFetch.Add("userCertificate");
                    oPicker.AttributesToFetch.Add("objectSid");

                    // show dialog and return if cancelled
                    if (oPicker.ShowDialog() != System.Windows.Forms.DialogResult.OK)
                    {
                        return;
                    }

                    foreach (DirectoryObject oSelected in oPicker.SelectedObjects)
                    {
                        // skip if no certificate information was found
                        if (oSelected.FetchedAttributes[0] == null)
                        {
                            MessageBox.Show(this,
                                "There was no certificate associated with '" + oSelected.Name + "'.",
                                "No Certificate Information Found",
                                MessageBoxButton.OK, MessageBoxImage.Exclamation);
                            continue;
                        }

                        // if the user has more than one certificate, then we need to wrap the structure as a
                        // single element in an object array;
                        object oAdCertAttribute = oSelected.FetchedAttributes[0];
                        if (oAdCertAttribute is object[])
                        {
                            // downselect to only display rsa certs
                            X509Certificate2Collection oCollection = new X509Certificate2Collection();
                            try
                            {
                                foreach (byte[] oCertData in (object[])oAdCertAttribute)
                                {
                                    using (X509Certificate2 oCert = new X509Certificate2(oCertData))
                                        if (CertificateOperations.CheckCertificateStatus(oCert))
                                            oCollection.Add(new X509Certificate2(oCert));
                                }

                                // ask the user which certificate to publish
                                X509Certificate2Collection oSelectedCertificates = X509Certificate2UI.SelectFromCollection(
                                    oCollection, "Select Certificate", "Select Certificate To Add",
                                    X509SelectionFlag.SingleSelection, new WindowInteropHelper(this).Handle);
                                if (oSelectedCertificates.Count == 0) continue;
                                oAdCertAttribute = oSelectedCertificates[0].RawData;
                            }
                            finally
                            {
                                foreach (X509Certificate2 oCert in oCollection) oCert.Dispose();
                            }
                        }

                        // add the certificate to the store
                        SecurityIdentifier oSid = new SecurityIdentifier((byte[])oSelected.FetchedAttributes[1], 0);
                        using (X509Certificate2 oCert = new X509Certificate2((byte[])oAdCertAttribute))
                        {
                            AddCertificate(oCert, oSid.ToString());
                        }
                    }
                }
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
                using (X509Certificate2 oCert = new X509Certificate2(oUser.Certificate))
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
            List<Item> oItems;
            List<User> oUsers;
            HashSet<string> oPrivate = CertificateOperations.GetPrivateCertificateData();
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oItems = oContent.Items.Include(i => i.User).Include(i => i.Instances.Select(j => j.User)).ToList();
                oUsers = oContent.Users.ToList();
                var oProtection = oContent.Ciphers.Select(c => new
                {
                    c.ItemId, c.CipherParams, c.ProtectionDescriptor
                }).ToDictionary(c => c.ItemId);
                foreach (Item oItem in oItems)
                {
                    if (!oProtection.TryGetValue(oItem.ItemId, out var oPolicy)) continue;
                    oItem.Cipher = new Cipher
                    {
                        CipherParams = oPolicy.CipherParams, ProtectionDescriptor = oPolicy.ProtectionDescriptor
                    };
                }
            }
            ItemList = new ObservableCollection<Item>(oItems.OrderBy(i => i.Label));
            CertificateList = oUsers.OrderBy(u => u.Name).ToList();
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
                    (i.Cipher?.ProtectionDescriptor?.IndexOf(sSearch, StringComparison.OrdinalIgnoreCase) ?? -1) >= 0) &&
                (oHideAccessible.IsChecked != true || i.Cipher?.CipherParams == ItemCryptography.PrincipalFormat ||
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
                : bCertificates ? "Add a certificate from your personal store to get started."
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

                // extract the sql file to use for initialization
                string sExecutionText;
                using (StreamReader oReader = new StreamReader(Application.GetResourceStream(
                    new Uri("pack://application:,,,/Crypture;component/Data/SQLite.sql", UriKind.Absolute)).Stream))
                    sExecutionText = oReader.ReadToEnd();

                // create the new database and run the file
                DatabaseOperations.CreateDatabase(oSaveDialog.FileName, sExecutionText);
                if (LoadDatabase(oSaveDialog.FileName)) oAddItemButton_Click(sender, e);
            });
        }

        private static void AddAutomaticCertificates()
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                List<User> oUsers = oContent.Users.ToList();
                // cycle through mandatory certificates to add
                foreach (byte[] bCertData in CertificateOperations.GetAutomaticCertificates())
                {
                    // skip certificates already in database
                    if (oUsers.Any(u => u.Certificate.SequenceEqual(bCertData))) continue;
                    using (X509Certificate2 oCert = new X509Certificate2(bCertData))
                        CertificateKeyProtection.ValidateForEncryption(oCert);
                    // create new item to add
                    User oUser = new User { Certificate = bCertData, Sid = null };
                    oContent.Users.Add(oUser);
                    oUsers.Add(oUser);
                }
                oContent.SaveChanges();
            }
        }

        private bool LoadDatabase(string sDatabase, bool bEnableControls = true)
        {
            string sPreviousConnection = CryptureEntities.ConnectionString;
            string sPreviousPath = sDatabasePath;
            try
            {
                sDatabase = Path.GetFullPath(sDatabase);
                DatabaseOperations.EnsureProtectionSchema(sDatabase);
                // set our instance to use this new connection
                CryptureEntities.DatabasePath = sDatabase;
                using (CryptureEntities oContent = new CryptureEntities())
                {
                    oContent.Items.Take(1).Load();
                    oContent.Users.Take(1).Load();
                    oContent.Ciphers.Take(1).Load();
                    oContent.Instances.Take(1).Load();
                }
                AddAutomaticCertificates();
                sDatabasePath = sDatabase;
                RefreshData();
                oProtectedItemActionRibbonGroupBox.IsEnabled = bEnableControls;
                oProtectedItemScopeRibbonGroupBox.IsEnabled = bEnableControls;
                oCertificatesTab.IsEnabled = bEnableControls;
                oAdvancedTab.IsEnabled = bEnableControls;
                oBackupDatabaseButton.IsEnabled = bEnableControls;
                oSearchTextBox.IsEnabled = bEnableControls;
                oDatabaseStatus.Text = sDatabase;
                Title = "Crypture - " + Path.GetFileName(sDatabase);
                return true;
            }
            catch (Exception eError)
            {
                CryptureEntities.ConnectionString = sPreviousConnection;
                sDatabasePath = sPreviousPath;
                // this method can be called during the startup routine so launch at a
                // lower dispatcher priority to make sure that the window is available
                Dispatcher.BeginInvoke(DispatcherPriority.ContextIdle, new Action(() =>
                {
                    MessageBox.Show(this, "An error occurred during Vault loading: " +
                        Environment.NewLine + Environment.NewLine + eError.GetBaseException().Message,
                        "Error During Vault Loading", MessageBoxButton.OK, MessageBoxImage.Error);
                }));
                return false;
            }
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
            Utilities.TryOperation(this, () => new VaultHealthWindow(sDatabasePath) { Owner = this }.ShowDialog());
        }

        private void oCompactDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                using (CryptureEntities oContent = new CryptureEntities())
                {
                    oContent.Database.ExecuteSqlCommand(TransactionalBehavior.DoNotEnsureTransaction, "VACUUM;");
                }

                MessageBox.Show(this, "Compact operation complete.",
                    "Operation Complete", MessageBoxButton.OK, MessageBoxImage.Information);
            });
        }

        private void oBackupDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            if (String.IsNullOrEmpty(sDatabasePath)) return;
            Utilities.TryOperation(this, () =>
            {
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
            else if (e.Key == Key.Enter && oItemDataGrid.IsKeyboardFocusWithin) oViewItemButton_Click(sender, e);
            else return;
            e.Handled = true;
        }

        private void oItemBrowser_Closing(object sender, CancelEventArgs e)
        {
            Utilities.TryOperation(this, () => Properties.Settings.Default.Save());
        }

        private void oItemBrowser_Loaded(object sender, RoutedEventArgs e)
        {
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