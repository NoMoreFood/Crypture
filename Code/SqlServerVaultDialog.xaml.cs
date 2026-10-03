using System;
using System.Windows;
using Microsoft.Data.SqlClient;

namespace Crypture
{
    public partial class SqlServerVaultDialog : Window
    {
        internal SqlServerVaultStorage Storage { get; private set; }
        internal bool CreateDatabase { get; private set; }

        public SqlServerVaultDialog(string sRecentConnection = null)
        {
            InitializeComponent();
            ConfigurationDefaults oDefaults = new ConfigurationDefaults();
            oServer.Text = oDefaults.Text("SqlServerDefaultServer", "");
            oDatabase.Text = oDefaults.Text("SqlServerDefaultDatabase", "");
            oTrustCertificate.IsChecked = oDefaults.Flag("SqlServerTrustServerCertificate", false);
            if (sRecentConnection == null) return;
            SqlConnectionStringBuilder oRecent = new SqlConnectionStringBuilder(sRecentConnection);
            oServer.Text = oRecent.DataSource;
            oDatabase.Text = oRecent.InitialCatalog;
            oTrustCertificate.IsChecked = oRecent.TrustServerCertificate;
        }

        private void oConnect_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                const int ConnectionTimeoutSeconds = 10;
                if (String.IsNullOrWhiteSpace(oServer.Text) || String.IsNullOrWhiteSpace(oDatabase.Text))
                    throw new InvalidOperationException("Enter a server and database name.");
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
                DialogResult = true;
            });
        }
    }
}
