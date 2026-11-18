using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using SQLitePCL;
using System.IO;
using System.Threading;
using System.Linq;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;

namespace Crypture
{
    internal static class DatabaseOperations
    {
        // Shown when a save or removal loses a race with another Vault user.
        internal const string ChangedBeforeSave = "This item changed or was removed by another user. " +
            "Your edits have been kept open. Copy them before reopening the item.";
        internal const string ChangedBeforeRemoval = "This item changed or was removed by another user. " +
            "Refresh the list before removing it.";

        internal static void DeleteItem(Item oItem)
        {
            if (CryptureEntities.Storage is SqlServerVaultStorage oSqlServer)
            {
                SqlServerItemOperations.Delete(oSqlServer, oItem);
                return;
            }
            using CryptureEntities oContent = new CryptureEntities();

            // Hold the SQLite writer lock while checking the displayed revision and deleting it.
            using var oTransaction = oContent.Database.BeginTransaction();
            Item oStored = oContent.Items.Find(oItem.ItemId);
            if (oStored == null || oStored.ModifiedDate != oItem.ModifiedDate)
                throw new InvalidOperationException(ChangedBeforeRemoval);
            oContent.Items.Remove(oStored);
            oContent.SaveChanges();
            oTransaction.Commit();
        }

        internal static void SaveItem(Item oItem, byte[] oPlainText, IEnumerable<User> oRecipients,
            string sProtectionDescriptor = null, FidoKeyAccess oFidoKey = null)
        {
            IVaultStorage oStorage = CryptureEntities.Storage;
            if (oFidoKey != null && oStorage.IsSqlServer)
                throw new InvalidOperationException("FIDO2 encryption is available for file Vaults. " +
                    "SQL Server Vaults require Windows or certificate recipients.");
            ContentEncryptionSuite nContentSuite = ItemCryptography.ReadContentEncryptionSuite();
            RecoveryPolicy oRecovery = RecoveryPolicy.ReadForStorage(oStorage, true);
            List<User> oUsers = sProtectionDescriptor == null
                ? (oRecipients ?? Enumerable.Empty<User>()).ToList() : new List<User>();
            User oRecoveryUser = null, oRecoveryOnly = null;

            // Prepare all recipient and recovery envelopes before taking the Vault's write lock.
            if (oRecovery.Certificate != null)
            {
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oRecovery.Certificate))
                    if (!CertificateOperations.CheckCertificateStatus(oCert))
                        throw new InvalidOperationException("The emergency recovery certificate is not valid for " +
                            "encryption. Check its expiry, trust, and certificate validation settings.");
                using CryptureEntities oDirectory = new CryptureEntities(oStorage);
                IQueryable<User> oDirectoryUsers = oStorage.IsSqlServer
                    ? oDirectory.Users.Where(u => u.IsEscrow) : oDirectory.Users;
                oRecoveryUser = oDirectoryUsers.FirstOrDefault(u => u.Certificate == oRecovery.Certificate);
                if (oRecoveryUser == null && oStorage.IsSqlServer)
                    throw new InvalidOperationException("The SQL Server recovery certificate must be " +
                        "enrolled by the Vault owner and designated as escrow for its verified " +
                        "Active Directory identity before saving.");
                oRecoveryUser ??= new User { Certificate = oRecovery.Certificate };
                if (oUsers.RemoveAll(u => u.Certificate.SequenceEqual(oRecovery.Certificate)) == 0)
                    oRecoveryOnly = oRecoveryUser;
                oUsers.Add(oRecoveryUser);
            }
            Item oEncrypted = new Item { Label = oItem.Label, ItemType = oItem.ItemType };
            ItemCryptography.Encrypt(oEncrypted, oPlainText, oUsers,
                sProtectionDescriptor, oRecovery.Descriptor, nContentSuite, oFidoKey, oRecoveryOnly);
            if (oStorage is SqlServerVaultStorage oSqlServer)
            {
                // SQL Server saves encrypted rows through a recipient-checked procedure.
                SqlServerItemOperations.Save(oSqlServer, oItem, oEncrypted);
                return;
            }
            using (CryptureEntities oContent = new CryptureEntities(oStorage))
            using (var oTransaction = oContent.Database.BeginTransaction())
            {
                // Resolve the recovery row atomically; its signature binds the certificate, not the row ID.
                if (oRecoveryUser != null)
                {
                    User oStoredRecovery = oContent.Users.FirstOrDefault(u => u.Certificate == oRecovery.Certificate);
                    if (oStoredRecovery == null)
                    {
                        oStoredRecovery = new User { Certificate = oRecovery.Certificate };
                        oContent.Users.Add(oStoredRecovery);
                        oContent.SaveChanges();
                    }
                    foreach (Instance oInstance in oEncrypted.Instances.Where(i => i.User == oRecoveryUser))
                        oInstance.UserId = oStoredRecovery.UserId;
                }
                Item oStored = null;
                if (oItem.ItemId != 0)
                {
                    oStored = oContent.Items.Include(i => i.Cipher).Include(i => i.Instances).AsSplitQuery()
                        .SingleOrDefault(i => i.ItemId == oItem.ItemId);
                    if (oStored == null || oStored.ModifiedDate != oItem.ModifiedDate ||
                        oStored.Cipher == null || oItem.Cipher == null ||
                        oStored.Cipher.CipherParams != oItem.Cipher.CipherParams ||
                        oStored.Cipher.ContentSuite != oItem.Cipher.ContentSuite ||
                        !oStored.Cipher.AuthenticationTag.AsSpan().SequenceEqual(oItem.Cipher.AuthenticationTag) ||
                        oStored.Cipher.ProtectionDescriptor != oItem.Cipher.ProtectionDescriptor ||
                        !oStored.Cipher.CipherVector.SequenceEqual(oItem.Cipher.CipherVector) ||
                        !oStored.Cipher.CipherText.SequenceEqual(oItem.Cipher.CipherText))
                        throw new InvalidOperationException(ChangedBeforeSave);
                }
                else
                {
                    oStored = new Item { CreatedDate = DateTime.UtcNow };
                    oContent.Items.Add(oStored);
                }

                oStored.Label = oItem.Label;
                oStored.ItemType = oItem.ItemType;
                oStored.ModifiedDate = DateTime.UtcNow;
                oStored.ModifiedBy = sProtectionDescriptor == null && oFidoKey == null ? oItem.ModifiedBy : null;
                using (WindowsIdentity oIdentity = WindowsIdentity.GetCurrent())
                    oStored.ModifiedByIdentity = oIdentity.Name;
                if (oStored.Cipher == null) oStored.Cipher = new Cipher();
                oStored.Cipher.CipherText = oEncrypted.Cipher.CipherText;
                oStored.Cipher.CipherVector = oEncrypted.Cipher.CipherVector;
                oStored.Cipher.CipherParams = oEncrypted.Cipher.CipherParams;
                oStored.Cipher.ContentSuite = oEncrypted.Cipher.ContentSuite;
                oStored.Cipher.AuthenticationTag = oEncrypted.Cipher.AuthenticationTag;
                oStored.Cipher.ProtectionDescriptor = oEncrypted.Cipher.ProtectionDescriptor;
                oStored.Cipher.ProtectedKey = oEncrypted.Cipher.ProtectedKey;
                oStored.Cipher.Signature = oEncrypted.Cipher.Signature;
                oContent.Instances.RemoveRange(oStored.Instances.ToList());
                oStored.Instances.Clear();
                foreach (Instance oInstance in oEncrypted.Instances)
                {
                    // Save recipients by key; their certificate entities belong to the caller.
                    oInstance.User = null;
                    oStored.Instances.Add(oInstance);
                }
                try { oContent.SaveChanges(); }
                catch (DbUpdateConcurrencyException)
                {
                    throw new InvalidOperationException(ChangedBeforeSave);
                }
                oTransaction.Commit();
            }
        }

        internal static void RemoveCertificate(long nUserId)
        {
            RecoveryPolicy oRecovery = RecoveryPolicy.ReadForStorage(CryptureEntities.Storage);
            using CryptureEntities oContent = new CryptureEntities();

            // SQL Server checks remaining recipients in its own procedure; SQLite holds the writer lock here.
            using var oTransaction = CryptureEntities.Storage.IsSqlServer ? null : oContent.Database.BeginTransaction();
            User oUser = oContent.Users.Find(nUserId);
            if (oUser == null) return;
            if (oRecovery.Certificate != null && oUser.Certificate.SequenceEqual(oRecovery.Certificate))
                throw new InvalidOperationException(
                    "The configured emergency recovery certificate cannot be removed.");
            if (CryptureEntities.Storage is SqlServerVaultStorage oSqlServer)
            {
                SqlServerItemOperations.RemoveCertificate(oSqlServer, nUserId);
                return;
            }
            if (oContent.Items.Any(i => i.Instances.Any(j => j.UserId == nUserId) &&
                !i.Instances.Any(j => j.UserId != nUserId) && (i.Cipher == null ||
                i.Cipher.CipherParams != ItemCryptography.FidoFormat &&
                (i.Cipher.CipherParams != ItemCryptography.RecoveryFormat ||
                    i.Cipher.ProtectionDescriptor == null))))
                throw new InvalidOperationException("This certificate is the only recipient " +
                    "for one or more items. Share those items with another certificate before removing it.");
            oContent.Users.Remove(oUser);
            oContent.SaveChanges();
            oTransaction.Commit();
        }

        internal static void CreateDatabase(string sPath, string sSchema)
        {
            using (FileStream oFile = new FileStream(sPath, FileMode.CreateNew, FileAccess.Write)) { }
            try
            {
                using (SqliteConnection oConnection = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = sPath, ForeignKeys = true, Mode = SqliteOpenMode.ReadWrite, Pooling = false
                }.ConnectionString))
                {
                    oConnection.Open();
                    using (SqliteTransaction oTransaction = oConnection.BeginTransaction())
                    using (SqliteCommand oCommand = new SqliteCommand(sSchema, oConnection, oTransaction))
                    {
                        oCommand.ExecuteNonQuery();
                        oTransaction.Commit();
                    }
                }
            }
            catch
            {
                File.Delete(sPath);
                throw;
            }
        }

        internal static void BackupDatabase(string sSource, string sDestination,
            CancellationToken oCancellation = default)
        {
            oCancellation.ThrowIfCancellationRequested();
            if (File.Exists(sDestination))
                throw new IOException("Choose a new backup filename so an existing Vault is not overwritten.");

            string sTemporary = sDestination + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (SqliteConnection oSource = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = sSource, Mode = SqliteOpenMode.ReadOnly, Pooling = false
                }.ConnectionString))
                using (SqliteConnection oDestination = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = sTemporary, Pooling = false
                }.ConnectionString))
                {
                    oSource.Open();
                    oDestination.Open();

                    // Pin a single read snapshot while allowing cancellation during lock waits and copying.
                    using SqliteTransaction oSnapshot = oSource.BeginTransaction(deferred: true);
                    const int LockRetryMilliseconds = 100;
                    const int PagesPerBatch = 256;
                    long nStarted = Environment.TickCount64;
                    int nResult;
                    while (true)
                    {
                        oCancellation.ThrowIfCancellationRequested();
                        nResult = raw.sqlite3_exec(oSource.Handle, "SELECT 1 FROM sqlite_schema LIMIT 1");
                        if (nResult is not (raw.SQLITE_BUSY or raw.SQLITE_LOCKED) ||
                            Environment.TickCount64 - nStarted >= oSource.DefaultTimeout * 1000L) break;
                        oCancellation.WaitHandle.WaitOne(LockRetryMilliseconds);
                    }
                    oCancellation.ThrowIfCancellationRequested();
                    SqliteException.ThrowExceptionForRC(nResult, oSource.Handle);

                    using (var oBackup = raw.sqlite3_backup_init(oDestination.Handle, "main", oSource.Handle, "main"))
                    {
                        if (oBackup.IsInvalid)
                            SqliteException.ThrowExceptionForRC(raw.sqlite3_errcode(oDestination.Handle),
                                oDestination.Handle);
                        do
                        {
                            oCancellation.ThrowIfCancellationRequested();
                            nResult = raw.sqlite3_backup_step(oBackup, PagesPerBatch);
                        } while (nResult == raw.SQLITE_OK);
                        SqliteException.ThrowExceptionForRC(nResult, oDestination.Handle);
                    }
                    oSnapshot.Commit();
                }
                oCancellation.ThrowIfCancellationRequested();
                File.Move(sTemporary, sDestination);
            }
            finally
            {
                if (File.Exists(sTemporary)) File.Delete(sTemporary);
            }
        }
    }
}
