using System;
using System.Windows;

namespace Crypture
{
    public partial class SqlServerBackupDialog : Window
    {
        internal string BackupPath { get; private set; }

        internal SqlServerBackupDialog(string sDatabase)
        {
            InitializeComponent();
            oBackupPath.Text = sDatabase + "-backup-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".bak";
        }

        private void oBackup_Click(object sender, RoutedEventArgs e)
        {
            if (String.IsNullOrWhiteSpace(oBackupPath.Text))
            {
                MessageBox.Show(this, "Enter a backup path or filename.", "Backup Path Required",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            BackupPath = oBackupPath.Text.Trim();
            DialogResult = true;
        }
    }
}
