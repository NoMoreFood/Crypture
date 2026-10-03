using System;
using System.Windows;
using System.Windows.Controls;
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
            oAuthentication.SelectedIndex = oDefaults.Text("SqlServerAuthentication", "Windows") == "SqlLogin" ? 1 : 0;
            oTrustCertificate.IsChecked = oDefaults.Flag("SqlServerTrustServerCertificate", false);
            if (sRecentConnection == null) return;
            SqlConnectionStringBuilder oRecent = new SqlConnectionStringBuilder(sRecentConnection);
            oServer.Text = oRecent.DataSource;
            oDatabase.Text = oRecent.InitialCatalog;
            oAuthentication.SelectedIndex = oRecent.IntegratedSecurity ? 0 : 1;
            oUserName.Text = oRecent.UserID;
            oTrustCertificate.IsChecked = oRecent.TrustServerCertificate;
        }

        private void oAuthentication_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (oUserName == null || oPassword == null) return;
            bool bSqlLogin = oAuthentication.SelectedIndex == 1;
            oUserName.IsEnabled = bSqlLogin;
            oPassword.IsEnabled = bSqlLogin;
        }

        private void oConnect_Click(object sender, RoutedEventArgs e)
        {
            Utilities.TryOperation(this, () =>
            {
                if (String.IsNullOrWhiteSpace(oServer.Text) || String.IsNullOrWhiteSpace(oDatabase.Text))
                    throw new InvalidOperationException("Enter a server and database name.");
                if (oAuthentication.SelectedIndex == 1 &&
                    (String.IsNullOrWhiteSpace(oUserName.Text) || oPassword.Password.Length == 0))
                    throw new InvalidOperationException("Enter the SQL Server user name and password.");

                // Keep connection settings local to this session; the password is never saved in app preferences.
                SqlConnectionStringBuilder oBuilder = new SqlConnectionStringBuilder
                {
                    DataSource = oServer.Text.Trim(), InitialCatalog = oDatabase.Text.Trim(),
                    IntegratedSecurity = oAuthentication.SelectedIndex == 0,
                    Encrypt = SqlConnectionEncryptOption.Mandatory,
                    TrustServerCertificate = oTrustCertificate.IsChecked == true,
                    ConnectTimeout = 10, ApplicationName = "Crypture", Pooling = false
                };
                if (!oBuilder.IntegratedSecurity)
                {
                    oBuilder.UserID = oUserName.Text.Trim();
                    oBuilder.Password = oPassword.Password;
                }
                Storage = new SqlServerVaultStorage(oBuilder.ConnectionString);
                CreateDatabase = oCreateDatabase.IsChecked == true;
                oPassword.Clear();
                DialogResult = true;
            });
        }
    }
}
