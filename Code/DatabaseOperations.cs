using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.Data.SqlClient;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;

namespace Crypture
{
    internal static class DatabaseOperations
    {
        internal const string PasswordOptionsSchema =
            "CREATE TABLE IF NOT EXISTS [PasswordGeneratorSettings] (" +
            "    [Id] integer PRIMARY KEY CHECK ([Id] = 1)," +
            "    [MinimumLength] integer NOT NULL CHECK ([MinimumLength] BETWEEN 1 AND 1024)," +
            "    [MaximumLength] integer NOT NULL CHECK ([MaximumLength] BETWEEN [MinimumLength] AND 1024)," +
            "    [IncludeUppercase] integer NOT NULL CHECK ([IncludeUppercase] IN (0, 1))," +
            "    [IncludeLowercase] integer NOT NULL CHECK ([IncludeLowercase] IN (0, 1))," +
            "    [IncludeDigits] integer NOT NULL CHECK ([IncludeDigits] IN (0, 1))," +
            "    [IncludeSymbols] integer NOT NULL CHECK ([IncludeSymbols] IN (0, 1))," +
            "    [SymbolCharacters] nvarchar NOT NULL," +
            "    [ExcludedCharacters] nvarchar NOT NULL," +
            "    [ExcludeSimilar] integer NOT NULL CHECK ([ExcludeSimilar] IN (0, 1))," +
            "    [RequireEachType] integer NOT NULL CHECK ([RequireEachType] IN (0, 1))" +
            ");";

        internal static Item LoadItem(long nItemId)
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                Item oItem = oContent.Items.Include(i => i.User).Include(i => i.Cipher)
                    .Include(i => i.Instances).ThenInclude(j => j.User).SingleOrDefault(i => i.ItemId == nItemId);
                if (oItem == null) throw new InvalidOperationException("This item has been removed. Refresh the list.");
                return oItem;
            }
        }

        internal static void DeleteItem(long nItemId)
        {
            if (CryptureEntities.Storage is SqlServerVaultStorage oSqlServer)
            {
                SqlServerItemOperations.Delete(oSqlServer, nItemId);
                return;
            }
            using CryptureEntities oContent = new CryptureEntities();
            Item oStored = oContent.Items.Find(nItemId);
            if (oStored == null) return;
            oContent.Items.Remove(oStored);
            oContent.SaveChanges();
        }

        internal static void SaveItem(Item oItem, byte[] oPlainText, IEnumerable<User> oRecipients,
            string sProtectionDescriptor = null)
        {
            ContentEncryptionSuite nContentSuite = ItemCryptography.ReadContentEncryptionSuite();
            RecoveryPolicy oRecovery = RecoveryPolicy.Read();
            List<User> oUsers = sProtectionDescriptor == null
                ? (oRecipients ?? Enumerable.Empty<User>()).ToList() : new List<User>();
            if (oRecovery.Certificate != null)
            {
                using (X509Certificate2 oCert = X509CertificateLoader.LoadCertificate(oRecovery.Certificate))
                    if (!CertificateOperations.CheckCertificateStatus(oCert))
                        throw new InvalidOperationException("The emergency recovery certificate is not valid for " +
                            "encryption. Check its expiry, trust, and certificate validation settings.");
            }
            if (CryptureEntities.Storage is SqlServerVaultStorage oSqlServer)
            {
                // SQL Server saves encrypted rows through a recipient-checked procedure.
                if (oRecovery.Certificate != null)
                {
                    using CryptureEntities oDirectory = new CryptureEntities();
                    User oRecoveryUser = oDirectory.Users.ToList().FirstOrDefault(u =>
                        u.Certificate.SequenceEqual(oRecovery.Certificate));
                    if (oRecoveryUser == null)
                    {
                        oRecoveryUser = new User { Certificate = oRecovery.Certificate,
                            Sid = CertificateOperations.CurrentUserSid };
                        oDirectory.Users.Add(oRecoveryUser);
                        oDirectory.SaveChanges();
                    }
                    if (!oUsers.Any(u => u.UserId == oRecoveryUser.UserId)) oUsers.Add(oRecoveryUser);
                }
                Item oSqlEncrypted = new Item { Label = oItem.Label, ItemType = oItem.ItemType };
                ItemCryptography.Encrypt(oSqlEncrypted, oPlainText, oUsers,
                    sProtectionDescriptor, oRecovery.Descriptor, nContentSuite);
                SqlServerItemOperations.Save(oSqlServer, oItem, oSqlEncrypted);
                return;
            }
            Item oEncrypted = new Item { Label = oItem.Label, ItemType = oItem.ItemType };
            using (CryptureEntities oContent = new CryptureEntities())
            using (var oTransaction = oContent.Database.BeginTransaction())
            {
                // Enforce recovery at the save boundary, including callers outside the editor.
                if (oRecovery.Certificate != null)
                {
                    User oRecoveryUser = oContent.Users.ToList().FirstOrDefault(u =>
                        u.Certificate.SequenceEqual(oRecovery.Certificate));
                    if (oRecoveryUser == null)
                    {
                        oRecoveryUser = new User { Certificate = oRecovery.Certificate };
                        oContent.Users.Add(oRecoveryUser);
                        oContent.SaveChanges();
                    }
                    if (!oUsers.Any(u => u.UserId == oRecoveryUser.UserId)) oUsers.Add(oRecoveryUser);
                }
                ItemCryptography.Encrypt(oEncrypted, oPlainText, oUsers,
                    sProtectionDescriptor, oRecovery.Descriptor, nContentSuite);
                Item oStored = null;
                if (oItem.ItemId != 0)
                {
                    oStored = oContent.Items.Include(i => i.Cipher).Include(i => i.Instances)
                        .SingleOrDefault(i => i.ItemId == oItem.ItemId);
                    if (oStored == null || oStored.ModifiedDate != oItem.ModifiedDate ||
                        CryptureEntities.Storage.IsSqlServer &&
                        !(oStored.RowVersion ?? []).SequenceEqual(oItem.RowVersion ?? []) ||
                        oStored.Cipher == null || oItem.Cipher == null ||
                        oStored.Cipher.CipherParams != oItem.Cipher.CipherParams ||
                        oStored.Cipher.ContentSuite != oItem.Cipher.ContentSuite ||
                        !oStored.Cipher.AuthenticationTag.AsSpan().SequenceEqual(oItem.Cipher.AuthenticationTag) ||
                        oStored.Cipher.ProtectionDescriptor != oItem.Cipher.ProtectionDescriptor ||
                        !oStored.Cipher.CipherVector.SequenceEqual(oItem.Cipher.CipherVector) ||
                        !oStored.Cipher.CipherText.SequenceEqual(oItem.Cipher.CipherText))
                        throw new InvalidOperationException("This item changed or was removed by another user. " +
                            "Your edits have been kept open. Copy them before reopening the item.");
                }
                else
                {
                    oStored = new Item { CreatedDate = DateTime.Now };
                    oContent.Items.Add(oStored);
                }

                oStored.Label = oItem.Label;
                oStored.ItemType = oItem.ItemType;
                oStored.ModifiedDate = DateTime.Now;
                oStored.ModifiedBy = sProtectionDescriptor == null ? oItem.ModifiedBy : null;
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
                foreach (Instance oInstance in oEncrypted.Instances) oStored.Instances.Add(oInstance);
                try { oContent.SaveChanges(); }
                catch (DbUpdateConcurrencyException)
                {
                    throw new InvalidOperationException("This item changed or was removed by another user. " +
                        "Your edits have been kept open. Copy them before reopening the item.");
                }
                oTransaction.Commit();
            }
        }

        internal static void EnsureProtectionSchema(string sPath)
        {
            // Each schema descriptor starts with its table name.
            const int TableNameIndex = 0;
            using (SqliteConnection oConnection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = sPath, ForeignKeys = true, Mode = SqliteOpenMode.ReadWrite, Pooling = false
            }.ConnectionString))
            {
                oConnection.Open();
                using (SqliteTransaction oTransaction = oConnection.BeginTransaction())
                {
                    Dictionary<string, HashSet<string>> oColumns = new Dictionary<string, HashSet<string>>();
                    foreach (string[] oTable in new[]
                    {
                        new[] { "Item", "ItemId", "ItemType", "Label", "ModifiedDate", "ModifiedBy", "CreatedDate" },
                        new[] { "Cipher", "ItemId", "CipherText", "CipherVector", "CipherParams" },
                        new[] { "Instance", "InstanceId", "ItemId", "UserId", "CipherKey", "CipherParams", "Signature" },
                        new[] { "User", "UserId", "Certificate", "Sid" }
                    })
                    {
                        const int FirstRequiredColumnIndex = 1;
                        string sTable = oTable[TableNameIndex];
                        HashSet<string> oNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        using (SqliteCommand oCommand = new SqliteCommand(
                            "PRAGMA table_info([" + sTable + "])", oConnection, oTransaction))
                        using (SqliteDataReader oReader = oCommand.ExecuteReader())
                            while (oReader.Read()) oNames.Add(oReader.GetString(oReader.GetOrdinal("name")));
                        if (oTable.Skip(FirstRequiredColumnIndex).Any(c => !oNames.Contains(c)))
                            throw new InvalidDataException("This is not a supported Crypture Vault.");
                        oColumns.Add(sTable, oNames);
                    }
                    foreach (string[] oColumn in new[]
                    {
                        new[] { "Item", "ModifiedByIdentity", "nvarchar" },
                        new[] { "Cipher", "ProtectionDescriptor", "nvarchar" },
                        new[] { "Cipher", "ProtectedKey", "blob" },
                        new[] { "Cipher", "ContentSuite", "integer" },
                        new[] { "Cipher", "AuthenticationTag", "blob" },
                        new[] { "Cipher", "Signature", "blob" }
                    })
                    {
                        // Upgrade entries contain a table, column name, and SQL type.
                        const int ColumnNameIndex = 1;
                        const int ColumnTypeIndex = 2;
                        if (oColumns[oColumn[TableNameIndex]].Contains(oColumn[ColumnNameIndex])) continue;
                        using (SqliteCommand oCommand = new SqliteCommand("ALTER TABLE [" + oColumn[TableNameIndex] +
                            "] ADD COLUMN [" + oColumn[ColumnNameIndex] + "] " +
                            oColumn[ColumnTypeIndex] + " NULL", oConnection, oTransaction))
                            oCommand.ExecuteNonQuery();
                    }
                    using (SqliteCommand oCommand = new SqliteCommand(
                        PasswordOptionsSchema, oConnection, oTransaction)) oCommand.ExecuteNonQuery();
                    oTransaction.Commit();
                }
            }
        }

        internal static PasswordOptions LoadPasswordOptions()
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                PasswordOptions oOptions = oContent.Database.SqlQueryRaw<PasswordOptions>(
                    "SELECT MinimumLength, MaximumLength, IncludeUppercase, IncludeLowercase, IncludeDigits, " +
                    "IncludeSymbols, SymbolCharacters, ExcludedCharacters, ExcludeSimilar, RequireEachType " +
                    "FROM PasswordGeneratorSettings WHERE Id = 1").SingleOrDefault() ?? PasswordOptions.ReadDefaults();
                oOptions.GetCharacterGroups();
                return oOptions;
            }
        }

        internal static void SavePasswordOptions(PasswordOptions oOptions)
        {
            oOptions.GetCharacterGroups();
            if (CryptureEntities.Storage.IsSqlServer)
            {
                // Update the one settings row atomically across SQL Server clients.
                using SqlConnection oConnection = new SqlConnection(CryptureEntities.Storage.ConnectionString);
                oConnection.Open();
                using SqlTransaction oTransaction = oConnection.BeginTransaction(IsolationLevel.Serializable);
                using SqlCommand oCommand = new SqlCommand("UPDATE [dbo].[PasswordGeneratorSettings] SET " +
                    "MinimumLength=@min, MaximumLength=@max, IncludeUppercase=@upper, IncludeLowercase=@lower, " +
                    "IncludeDigits=@digits, IncludeSymbols=@symbols, SymbolCharacters=@characters, " +
                    "ExcludedCharacters=@excluded, ExcludeSimilar=@similar, RequireEachType=@each WHERE Id=1",
                    oConnection, oTransaction);
                oCommand.Parameters.AddWithValue("@min", oOptions.MinimumLength);
                oCommand.Parameters.AddWithValue("@max", oOptions.MaximumLength);
                oCommand.Parameters.AddWithValue("@upper", oOptions.IncludeUppercase);
                oCommand.Parameters.AddWithValue("@lower", oOptions.IncludeLowercase);
                oCommand.Parameters.AddWithValue("@digits", oOptions.IncludeDigits);
                oCommand.Parameters.AddWithValue("@symbols", oOptions.IncludeSymbols);
                oCommand.Parameters.AddWithValue("@characters", oOptions.SymbolCharacters);
                oCommand.Parameters.AddWithValue("@excluded", oOptions.ExcludedCharacters);
                oCommand.Parameters.AddWithValue("@similar", oOptions.ExcludeSimilar);
                oCommand.Parameters.AddWithValue("@each", oOptions.RequireEachType);
                if (oCommand.ExecuteNonQuery() == 0)
                {
                    oCommand.CommandText = "INSERT INTO [dbo].[PasswordGeneratorSettings] (Id, MinimumLength, " +
                        "MaximumLength, IncludeUppercase, IncludeLowercase, IncludeDigits, IncludeSymbols, " +
                        "SymbolCharacters, ExcludedCharacters, ExcludeSimilar, RequireEachType) VALUES " +
                        "(1, @min, @max, @upper, @lower, @digits, @symbols, @characters, @excluded, @similar, @each)";
                    oCommand.ExecuteNonQuery();
                }
                oTransaction.Commit();
                return;
            }
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oContent.Database.ExecuteSqlRaw(
                    "INSERT OR REPLACE INTO PasswordGeneratorSettings (Id, MinimumLength, MaximumLength, " +
                    "IncludeUppercase, IncludeLowercase, IncludeDigits, IncludeSymbols, SymbolCharacters, " +
                    "ExcludedCharacters, ExcludeSimilar, RequireEachType) " +
                    "VALUES (1, @min, @max, @upper, @lower, @digits, @symbols, " +
                    "@characters, @excluded, @similar, @each)",
                    new SqliteParameter("@min", oOptions.MinimumLength),
                    new SqliteParameter("@max", oOptions.MaximumLength),
                    new SqliteParameter("@upper", oOptions.IncludeUppercase ? 1 : 0),
                    new SqliteParameter("@lower", oOptions.IncludeLowercase ? 1 : 0),
                    new SqliteParameter("@digits", oOptions.IncludeDigits ? 1 : 0),
                    new SqliteParameter("@symbols", oOptions.IncludeSymbols ? 1 : 0),
                    new SqliteParameter("@characters", oOptions.SymbolCharacters),
                    new SqliteParameter("@excluded", oOptions.ExcludedCharacters),
                    new SqliteParameter("@similar", oOptions.ExcludeSimilar ? 1 : 0),
                    new SqliteParameter("@each", oOptions.RequireEachType ? 1 : 0));
            }
        }

        internal static void RemoveCertificate(long nUserId)
        {
            RecoveryPolicy oRecovery = RecoveryPolicy.Read();
            if (CryptureEntities.Storage is SqlServerVaultStorage oSqlServer)
            {
                using CryptureEntities oDirectory = new CryptureEntities();
                User oCertificate = oDirectory.Users.Find(nUserId);
                if (oCertificate == null) return;
                if (oRecovery.Certificate != null && oCertificate.Certificate.SequenceEqual(oRecovery.Certificate))
                    throw new InvalidOperationException(
                        "The configured emergency recovery certificate cannot be removed.");
                SqlServerItemOperations.RemoveCertificate(oSqlServer, nUserId);
                return;
            }
            using (CryptureEntities oContent = new CryptureEntities())
            using (var oTransaction = CryptureEntities.Storage.IsSqlServer
                ? oContent.Database.BeginTransaction(IsolationLevel.Serializable)
                : oContent.Database.BeginTransaction())
            {
                if (oContent.Items.Any(i => i.Instances.Any(j => j.UserId == nUserId) &&
                    !i.Instances.Any(j => j.UserId != nUserId) && (i.Cipher == null ||
                    i.Cipher.CipherParams != ItemCryptography.RecoveryFormat || i.Cipher.ProtectionDescriptor == null)))
                    throw new InvalidOperationException("This certificate is the only recipient " +
                        "for one or more items. Share those items with another certificate before removing it.");

                User oUser = oContent.Users.Find(nUserId);
                if (oUser == null) return;
                if (oRecovery.Certificate != null && oUser.Certificate.SequenceEqual(oRecovery.Certificate))
                    throw new InvalidOperationException(
                        "The configured emergency recovery certificate cannot be removed.");
                if (CryptureEntities.Storage.IsSqlServer)
                    oContent.Items.Where(i => i.ModifiedBy == nUserId)
                        .ExecuteUpdate(s => s.SetProperty(i => i.ModifiedBy, (long?)null));
                oContent.Users.Remove(oUser);
                oContent.SaveChanges();
                oTransaction.Commit();
            }
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

        internal static void BackupDatabase(string sSource, string sDestination)
        {
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

                    // Acquire the read snapshot through a command so normal lock waiting applies to the backup.
                    using (SqliteTransaction oTransaction = oSource.BeginTransaction(deferred: true))
                    using (SqliteCommand oCommand = new SqliteCommand(
                        "SELECT COUNT(*) FROM sqlite_schema", oSource, oTransaction))
                    {
                        oCommand.ExecuteScalar();
                        oSource.BackupDatabase(oDestination);
                        oTransaction.Commit();
                    }
                }
                File.Move(sTemporary, sDestination);
            }
            finally
            {
                if (File.Exists(sTemporary)) File.Delete(sTemporary);
            }
        }
    }
}
