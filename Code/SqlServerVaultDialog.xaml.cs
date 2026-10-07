using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using Microsoft.Data.SqlClient;

namespace Crypture
{
    public partial class SqlServerVaultDialog : ThemedWindow
    {
        internal SqlServerVaultStorage Storage { get; private set; }
        internal bool CreateDatabase { get; private set; }
        private SqlServerEscrowChoice oEscrowChoice;

        public SqlServerVaultDialog(string sRecentConnection = null)
        {
            InitializeComponent();
            ConfigurationDefaults oDefaults = new ConfigurationDefaults();
            oServer.Text = oDefaults.Text("SqlServerDefaultServer", "");
            oDatabase.Text = oDefaults.Text("SqlServerDefaultDatabase", "");
            oTrustCertificate.IsChecked = oDefaults.Flag("SqlServerTrustServerCertificate", false);
            oCreateDatabase.Checked += oCreateDatabase_Changed;
            oCreateDatabase.Unchecked += oCreateDatabase_Changed;
            if (sRecentConnection == null) return;
            SqlConnectionStringBuilder oRecent = new SqlConnectionStringBuilder(sRecentConnection);
            oServer.Text = oRecent.DataSource;
            oDatabase.Text = oRecent.InitialCatalog;
            oTrustCertificate.IsChecked = oRecent.TrustServerCertificate;
        }

        private void oCreateDatabase_Changed(object sender, RoutedEventArgs e)
        {
            oEscrowPanel.Visibility = oCreateDatabase.IsChecked == true
                ? Visibility.Visible : Visibility.Collapsed;
            oConnect.Content = oCreateDatabase.IsChecked == true ? "Create" : "Connect";
        }

        private void oEscrowType_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (oEscrowSelection == null) return;
            oEscrowChoice = null;
            oEscrowSelection.Text = "Choose an escrow identity.";
        }

        private void oChooseEscrow_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                if (!PrincipalProtection.IsDomainJoined)
                    throw new InvalidOperationException("Escrow selection requires an Active Directory domain.");
                bool bCertificate = oEscrowType.SelectedIndex == 0;
                DirectoryPicker oPicker = new DirectoryPicker(bCertificate, 1) { Owner = this };
                if (oPicker.ShowDialog() != true || oPicker.SelectedAccounts.Count == 0) return;
                DirectoryAccount oAccount = oPicker.SelectedAccounts[0];
                if (!bCertificate)
                {
                    if (oAccount.Type is not ("User" or "Security Group"))
                        throw new InvalidOperationException("Choose an Active Directory user or security group.");
                    DirectorySearchResult oVerified = ForestDirectory.Search(oAccount.Sid, false,
                        CancellationToken.None, true);
                    if (oVerified.Truncated || oVerified.Accounts.Count != 1 ||
                        oVerified.Accounts[0].Sid != oAccount.Sid)
                        throw new InvalidOperationException("The selected Windows identity could not be verified.");
                    string sLabel = "Windows: " + oAccount.Account + " (" + oAccount.Sid + ")";
                    oEscrowChoice = SqlServerEscrowChoice.ForPrincipal(oAccount.Sid, sLabel);
                }
                else
                {
                    CertificateUsageFilter oFilter = CertificateUsageFilter.Read();
                    X509Certificate2Collection oEligible = new X509Certificate2Collection();
                    try
                    {
                        foreach (byte[] oData in oAccount.Certificates)
                        {
                            using X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oData);
                            if (oFilter.Matches(oCert) && CertificateOperations.CheckCertificateStatus(oCert, true))
                                oEligible.Add(new X509Certificate2(oCert));
                        }
                        if (oEligible.Count == 0)
                            throw new InvalidOperationException("This user has no eligible encryption certificate.");
                        X509Certificate2Collection oSelected = oEligible.Count == 1 ? oEligible :
                            X509Certificate2UI.SelectFromCollection(oEligible, "Escrow Certificate",
                                "Choose the emergency recovery certificate", X509SelectionFlag.SingleSelection,
                                new WindowInteropHelper(this).Handle);
                        if (oSelected.Count == 0) return;
                        X509Certificate2 oCertificate = oSelected[0];
                        SqlServerCertificateEnrollment.VerifyDirectoryBinding(oCertificate.RawData, oAccount.Sid);
                        string sLabel = "Certificate: " + oCertificate.GetNameInfo(X509NameType.SimpleName, false) +
                            " (" + oAccount.Account + ", " + oAccount.Sid + ")";
                        oEscrowChoice = SqlServerEscrowChoice.ForCertificate(oCertificate.RawData,
                            oAccount.Sid, sLabel);
                    }
                    finally
                    {
                        foreach (X509Certificate2 oCert in oEligible) oCert.Dispose();
                    }
                }
                oEscrowSelection.Text = oEscrowChoice.Label;
            });
        }

        private void oConnect_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                const int ConnectionTimeoutSeconds = 10;
                if (String.IsNullOrWhiteSpace(oServer.Text) || String.IsNullOrWhiteSpace(oDatabase.Text))
                    throw new InvalidOperationException("Enter a server and database name.");
                if (oCreateDatabase.IsChecked == true && oEscrowChoice == null)
                    throw new InvalidOperationException("Choose an escrow certificate or Windows user/group.");
                // Use the signed-in Windows account for every SQL Server connection.
                SqlConnectionStringBuilder oBuilder = new SqlConnectionStringBuilder
                {
                    DataSource = oServer.Text.Trim(), InitialCatalog = oDatabase.Text.Trim(),
                    IntegratedSecurity = true,
                    Encrypt = SqlConnectionEncryptOption.Mandatory,
                    TrustServerCertificate = oTrustCertificate.IsChecked == true,
                    ConnectTimeout = ConnectionTimeoutSeconds, ApplicationName = "Crypture", Pooling = false
                };
                Storage = new SqlServerVaultStorage(oBuilder.ConnectionString);
                CreateDatabase = oCreateDatabase.IsChecked == true;
                Storage.EscrowChoice = CreateDatabase ? oEscrowChoice : null;
                DialogResult = true;
            });
        }
    }
}
