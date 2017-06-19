using Microsoft.Win32;
using System;
using System.Collections.ObjectModel;
using System.Data.Entity;
using System.Data.SQLite;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using Tulpep.ActiveDirectoryObjectPicker;

namespace Crypture
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class ItemBrowser : Fluent.RibbonWindow
    {
        public ObservableCollection<Item> ItemList { get; set; } = new ObservableCollection<Item>();

        internal static bool CheckCertificateStatus(X509Certificate2 oCert, bool bAllowSelfSigned, bool bDoRevocationCheck)
        {
            using (X509Chain oChain = new X509Chain())
            {
                oChain.ChainPolicy.RevocationMode = (bDoRevocationCheck) ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
                oChain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

                // build the chain based on the specified policy
                oChain.Build(oCert);

                // check for self signed
                if (bAllowSelfSigned && oChain.ChainElements.Count == 1)
                {
                    return true;
                }

                // check for a valid certificate
                foreach (X509ChainStatus oStatus in oChain.ChainStatus)
                {
                    if (oStatus.Status != X509ChainStatusFlags.NoError) return false;
                }
            }

            // all checks successful -- looks good
            return true;
        }

        internal bool AddCertificate(X509Certificate2 oCert, string sIdentifier)
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                if (oContent.Users.Where(u => u.Certificate == oCert.RawData).Count() > 0)
                {
                    MessageBox.Show(this,
                         "The selected certificate is already in the database.",
                         "Certificate In Database", MessageBoxButton.OK, MessageBoxImage.Exclamation);
                    return false;
                }

                bool bAmOwner = MessageBox.Show(this,
                    "Are you the owner of the selected certificate?",
                    "Ownership Confirmation",
                    MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes;

                User oUser = new User()
                {
                    Certificate = oCert.GetRawCertData(),
                    Sid = (bAmOwner) ? sIdentifier : null
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

            // if the user has passed a database then load that otherwise load a temporary database
            // to assembly caching while the splash screen is up
            string[] sArgs = Environment.GetCommandLineArgs();
            bool bIsTempDatabase = (sArgs.Length <= 1);
            string sTempDatabase = (bIsTempDatabase) ? Path.GetTempFileName() : sArgs[1];

            // force an entity lookup to force all dependant assemblies to load
            LoadDatabase(sTempDatabase, !bIsTempDatabase);

            // cleanup temporarily database
            if (bIsTempDatabase)
            {
                SQLiteConnection.ClearAllPools();
                File.Delete(sTempDatabase);
            }
        }

        private void oRemoveItemUser_Click(object sender, RoutedEventArgs e)
        {
            // get the selected object based on what button was pressed
            object oObject = (sender == oRemoveCertButton) ?
                oCertDataGrid.SelectedItem : oItemDataGrid.SelectedItem;

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
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oContent.Entry(oObject).State = EntityState.Deleted;
                oContent.SaveChanges();
                oRefreshItemButton_Click();
            }
        }

        private void oAddFromFileButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog oOpenDialog = new OpenFileDialog()
            {
                Filter = "Certificate Files (*.cer)|*.cer|All Files (*.*)|*.*",
                CheckFileExists = true
            };
            if (oOpenDialog.ShowDialog(this).Value)
            {
                using (X509Certificate2 oCert = new X509Certificate2())
                {
                    oCert.Import(oOpenDialog.FileName);
                    AddCertificate(oCert, WindowsIdentity.GetCurrent().User.Value);
                }
            }
        }

        private void oAddFromStoreButton_Click(object sender, RoutedEventArgs e)
        {
            // open the locate personal certificate store
            using (X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                oStore.Open(OpenFlags.ReadOnly);

                // downselect to only display rsa certs
                X509Certificate2Collection oCollection = new X509Certificate2Collection();
                foreach (X509Certificate2 oCert in oStore.Certificates)
                {
                    if (oCert.GetRSAPublicKey() != null && CheckCertificateStatus(oCert,
                        oAllowSelfSignedCheckBox.IsChecked.Value, oDoRevocationCheckBox.IsChecked.Value)) oCollection.Add(oCert);
                }

                // ask the user which certificate to publish
                oCollection = X509Certificate2UI.SelectFromCollection(oCollection,
                    "Select Certificate", "Select Certificate To Add",
                    X509SelectionFlag.SingleSelection, new WindowInteropHelper(this).Handle);

                // commit the certificate to the database
                foreach (X509Certificate2 oCert in oCollection)
                {
                    AddCertificate(oCert, WindowsIdentity.GetCurrent().User.Value);
                }
            }
        }

        private void oAddFromAdButton_Click(object sender, RoutedEventArgs e)
        {
            DirectoryObjectPickerDialog oPicker = new DirectoryObjectPickerDialog()
            {
                DefaultObjectTypes = ObjectTypes.Users,
                AllowedObjectTypes = ObjectTypes.Users,
                MultiSelect = true,
                DefaultLocations = Locations.GlobalCatalog,
                AllowedLocations = Locations.All
            };
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
                    foreach (byte[] oCertData in (object[])oAdCertAttribute)
                    {
                        oCollection.Add(new X509Certificate2(oCertData));
                    }

                    // ask the user which certificate to publish
                    oCollection = X509Certificate2UI.SelectFromCollection(oCollection,
                        "Select Certificate", "Select Certificate To Add",
                        X509SelectionFlag.SingleSelection, new WindowInteropHelper(this).Handle);
                    if (oCollection.Count == 0) continue;
                    oAdCertAttribute = oCollection[0].RawData;
                }

                // add the certificate to the store
                SecurityIdentifier oSid = new SecurityIdentifier((byte[])oSelected.FetchedAttributes[1], 0);
                using (X509Certificate2 oCert = new X509Certificate2((byte[])oAdCertAttribute))
                {
                    AddCertificate(oCert, oSid.ToString());
                }
            }
        }

        private void Ribbon_SelectedTabChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ribbonTabHome.IsSelected)
            {
                oItemDataGrid.Visibility = Visibility.Visible;
                oCertDataGrid.Visibility = Visibility.Hidden;
            }
            if (oCertificatesTab.IsSelected)
            {
                oItemDataGrid.Visibility = Visibility.Hidden;
                oCertDataGrid.Visibility = Visibility.Visible;
            }
        }

        private void oViewCertButton_Click(object sender, RoutedEventArgs e)
        {
            // sanity check
            if (oCertDataGrid.SelectedItem == null) return;

            // display the selected certificate
            User oUser = (User)oCertDataGrid.SelectedItem;
            using (X509Certificate2 oCert = new X509Certificate2(oUser.Certificate))
            {
                X509Certificate2UI.DisplayCertificate(oCert);
            }
        }

        private void oCertDataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            oViewCertButton_Click(sender, e);
        }

        private void oViewItemButton_Click(object sender, RoutedEventArgs e)
        {
            Item oItem = (Item)oItemDataGrid.SelectedItem;
            ItemEditor oViewer = new ItemEditor(oItem);
            oViewer.ShowDialog();
        }

        private void oAddItemButton_Click(object sender, RoutedEventArgs e)
        {
            ItemEditor oViewer = new ItemEditor();
            oViewer.ShowDialog();
            oRefreshItemButton_Click();
        }

        private void oRefreshItemButton_Click(object sender = null, RoutedEventArgs e = null)
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oItemDataGrid.ItemsSource = oContent.Items.ToList<Item>().OrderBy(i => i.Label);
                oCertDataGrid.ItemsSource = oContent.Users.ToList<User>().OrderBy(u => u.Name);

                // if the option to only show my items is enable, then downselect the list to only
                // include items that have an instance for this currently logged in user
                if (oHideAccessible.IsChecked.Value)
                {
                    oItemDataGrid.ItemsSource = oContent.Items.ToList<Item>().OrderBy(i => i.Label).
                        Where(i => i.Instances.ToList().Where(u => u.User.IsOwnedByCurrentUser).Count() > 0);
                }
            }
        }

        private void oGenerateCertButton_Click(object sender, RoutedEventArgs e)
        {
            CertWizard oWiz = new CertWizard();
            oWiz.ShowDialog();
        }

        private void oNewDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // ask the user where to store the file
                SaveFileDialog oSaveDialog = new SaveFileDialog()
                {
                    Filter = "Crypture Database File (*.db)|*.db|All Files (*.*)|*.*",
                    AddExtension = true,
                    ValidateNames = true
                };
                if (!oSaveDialog.ShowDialog(this).Value) return;

                // extract the sql file to use for initialization
                string sExecutionText = "";
                using (StreamReader oReader = new StreamReader(Application.GetResourceStream((
                    new Uri("pack://application:,,,/Crypture;component/Data/SQLite.sql", UriKind.Absolute))).Stream))
                {
                    sExecutionText = oReader.ReadToEnd();
                }

                // create the new database and run the file
                CryptureEntities.DatabasePath = oSaveDialog.FileName;
                SQLiteConnection.CreateFile(oSaveDialog.FileName);
                using (CryptureEntities oContent = new CryptureEntities())
                {
                    oContent.Database.ExecuteSqlCommand(sExecutionText);
                }

                // set our instance to use this new connection
                CryptureEntities.DatabasePath = oSaveDialog.FileName;
                oProtectedItemActionRibbonGroupBox.IsEnabled = true;
                oProtectedItemScopeRibbonGroupBox.IsEnabled = true;
                oCertificatesTab.IsEnabled = true;
            }
            catch (Exception eError)
            {
                MessageBox.Show(this,
                    "An error occurred during database creation: " +
                    Environment.NewLine + Environment.NewLine + eError.Message,
                    "Error During Database Creation", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void LoadDatabase(string sDatabase, bool bEnableControls = true)
        {
            try
            {
                // set our instance to use this new connection
                CryptureEntities.DatabasePath = sDatabase;
                oRefreshItemButton_Click();
                oProtectedItemActionRibbonGroupBox.IsEnabled = bEnableControls;
                oProtectedItemScopeRibbonGroupBox.IsEnabled = bEnableControls;
                oCertificatesTab.IsEnabled = bEnableControls;
                oAdvancedTab.IsEnabled = bEnableControls;
            }
            catch (Exception eError)
            {
                if (bEnableControls)
                {
                    MessageBox.Show(this,
                        "An error occurred during database loading: " +
                        Environment.NewLine + Environment.NewLine + eError.Message,
                        "Error During Database Creation", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void oLoadDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            // ask the user where to store the file
            OpenFileDialog oSaveDialog = new OpenFileDialog()
            {
                Filter = "Crypture Database File (*.db)|*.db|All Files (*.*)|*.*",
                CheckFileExists = true
            };
            if (!oSaveDialog.ShowDialog(this).Value) return;
            LoadDatabase(oSaveDialog.FileName);
        }

        private void oClaimCertButton_Click(object sender, RoutedEventArgs e)
        {
            // sanity check
            User oUser = (User)oCertDataGrid.SelectedItem;
            if (oUser == null) return;

            // check if currently owned
            string sCurrentOwnership = "";
            if (oUser != null)
            {
                DirectoryEntry oEntry = new DirectoryEntry("LDAP://<SID=" + oUser.Sid + ">");
                if (oEntry != null && oEntry.Properties["UserPrincipalName"].Value != null)
                {
                    sCurrentOwnership = Environment.NewLine +
                        "The certificate is currently associated with '" +
                        oEntry.Properties["UserPrincipalName"].Value.ToString() + "'.";
                }
            }

            // ask for concurrence concur
            if (MessageBox.Show(this,
                "Are you sure you want to take ownership of the selected certificated?"
                + sCurrentOwnership, "Confirm Ownership Change Request",
                MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            // update the ownership on the selected certificate
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oContent.Entry(oUser).State = EntityState.Unchanged;
                oUser.Sid = WindowsIdentity.GetCurrent().User.Value;
                oContent.SaveChanges();
            }
        }

        private void oAboutButton_Click(object sender, RoutedEventArgs e)
        {
            AboutBox oAboutBox = new AboutBox();
            oAboutBox.Owner = this;
            oAboutBox.ShowDialog();
        }

        private void oCompactDatabaseButton_Click(object sender, RoutedEventArgs e)
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oContent.Database.ExecuteSqlCommand(TransactionalBehavior.DoNotEnsureTransaction, "VACUUM;");
            }
        }
    }
}