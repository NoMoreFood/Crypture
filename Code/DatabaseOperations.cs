using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Security.Principal;

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
                    .Include(i => i.Instances.Select(j => j.User)).SingleOrDefault(i => i.ItemId == nItemId);
                if (oItem == null) throw new InvalidOperationException("This item has been removed. Refresh the list.");
                return oItem;
            }
        }

        internal static void SaveItem(Item oItem, byte[] oPlainText, IEnumerable<User> oRecipients,
            string sProtectionDescriptor = null)
        {
            Item oEncrypted = new Item { Label = oItem.Label, ItemType = oItem.ItemType };
            ItemCryptography.Encrypt(oEncrypted, oPlainText, oRecipients, sProtectionDescriptor);
            using (CryptureEntities oContent = new CryptureEntities())
            using (DbContextTransaction oTransaction = oContent.Database.BeginTransaction())
            {
                Item oStored = null;
                if (oItem.ItemId != 0)
                {
                    oStored = oContent.Items.Include(i => i.Cipher).Include(i => i.Instances)
                        .SingleOrDefault(i => i.ItemId == oItem.ItemId);
                    if (oStored == null || oStored.ModifiedDate != oItem.ModifiedDate ||
                        oStored.Cipher == null || oItem.Cipher == null ||
                        oStored.Cipher.CipherParams != oItem.Cipher.CipherParams ||
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
                oStored.Cipher.ProtectionDescriptor = oEncrypted.Cipher.ProtectionDescriptor;
                oStored.Cipher.ProtectedKey = oEncrypted.Cipher.ProtectedKey;
                oStored.Cipher.Signature = oEncrypted.Cipher.Signature;
                oContent.Instances.RemoveRange(oStored.Instances.ToList());
                oStored.Instances.Clear();
                foreach (Instance oInstance in oEncrypted.Instances) oStored.Instances.Add(oInstance);
                oContent.SaveChanges();
                oTransaction.Commit();
            }
        }

        internal static void EnsureProtectionSchema(string sPath)
        {
            using (SQLiteConnection oConnection = new SQLiteConnection(new SQLiteConnectionStringBuilder
            {
                DataSource = sPath, ForeignKeys = true, FailIfMissing = true, Pooling = false
            }.ConnectionString))
            {
                oConnection.Open();
                using (SQLiteTransaction oTransaction = oConnection.BeginTransaction())
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
                        string sTable = oTable[0];
                        HashSet<string> oNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        using (SQLiteCommand oCommand = new SQLiteCommand(
                            "PRAGMA table_info([" + sTable + "])", oConnection, oTransaction))
                        using (SQLiteDataReader oReader = oCommand.ExecuteReader())
                            while (oReader.Read()) oNames.Add(oReader.GetString(1));
                        if (oTable.Skip(1).Any(c => !oNames.Contains(c)))
                            throw new InvalidDataException("This is not a supported Crypture Vault.");
                        oColumns.Add(sTable, oNames);
                    }
                    foreach (string[] oColumn in new[]
                    {
                        new[] { "Item", "ModifiedByIdentity", "nvarchar" },
                        new[] { "Cipher", "ProtectionDescriptor", "nvarchar" },
                        new[] { "Cipher", "ProtectedKey", "blob" },
                        new[] { "Cipher", "Signature", "blob" }
                    })
                    {
                        if (oColumns[oColumn[0]].Contains(oColumn[1])) continue;
                        using (SQLiteCommand oCommand = new SQLiteCommand("ALTER TABLE [" + oColumn[0] +
                            "] ADD COLUMN [" + oColumn[1] + "] " + oColumn[2] + " NULL", oConnection, oTransaction))
                            oCommand.ExecuteNonQuery();
                    }
                    using (SQLiteCommand oCommand = new SQLiteCommand(
                        PasswordOptionsSchema, oConnection, oTransaction)) oCommand.ExecuteNonQuery();
                    oTransaction.Commit();
                }
            }
        }

        internal static PasswordOptions LoadPasswordOptions()
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                PasswordOptions oOptions = oContent.Database.SqlQuery<PasswordOptions>(
                    "SELECT MinimumLength, MaximumLength, IncludeUppercase, IncludeLowercase, IncludeDigits, " +
                    "IncludeSymbols, SymbolCharacters, ExcludedCharacters, ExcludeSimilar, RequireEachType " +
                    "FROM PasswordGeneratorSettings WHERE Id = 1").SingleOrDefault() ?? new PasswordOptions();
                oOptions.GetCharacterGroups();
                return oOptions;
            }
        }

        internal static void SavePasswordOptions(PasswordOptions oOptions)
        {
            oOptions.GetCharacterGroups();
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oContent.Database.ExecuteSqlCommand(
                    "INSERT OR REPLACE INTO PasswordGeneratorSettings (Id, MinimumLength, MaximumLength, " +
                    "IncludeUppercase, IncludeLowercase, IncludeDigits, IncludeSymbols, SymbolCharacters, " +
                    "ExcludedCharacters, ExcludeSimilar, RequireEachType) " +
                    "VALUES (1, @min, @max, @upper, @lower, @digits, @symbols, " +
                    "@characters, @excluded, @similar, @each)",
                    new SQLiteParameter("@min", oOptions.MinimumLength),
                    new SQLiteParameter("@max", oOptions.MaximumLength),
                    new SQLiteParameter("@upper", oOptions.IncludeUppercase ? 1 : 0),
                    new SQLiteParameter("@lower", oOptions.IncludeLowercase ? 1 : 0),
                    new SQLiteParameter("@digits", oOptions.IncludeDigits ? 1 : 0),
                    new SQLiteParameter("@symbols", oOptions.IncludeSymbols ? 1 : 0),
                    new SQLiteParameter("@characters", oOptions.SymbolCharacters),
                    new SQLiteParameter("@excluded", oOptions.ExcludedCharacters),
                    new SQLiteParameter("@similar", oOptions.ExcludeSimilar ? 1 : 0),
                    new SQLiteParameter("@each", oOptions.RequireEachType ? 1 : 0));
            }
        }

        internal static void RemoveCertificate(long nUserId)
        {
            using (CryptureEntities oContent = new CryptureEntities())
            using (DbContextTransaction oTransaction = oContent.Database.BeginTransaction())
            {
                if (oContent.Items.Any(i => i.Instances.Any(j => j.UserId == nUserId) &&
                    !i.Instances.Any(j => j.UserId != nUserId)))
                    throw new InvalidOperationException("This certificate is the only recipient " +
                        "for one or more items. Share those items with another certificate before removing it.");

                User oUser = oContent.Users.Find(nUserId);
                if (oUser == null) return;
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
                using (SQLiteConnection oConnection = new SQLiteConnection(new SQLiteConnectionStringBuilder
                {
                    DataSource = sPath, ForeignKeys = true, FailIfMissing = true, Pooling = false
                }.ConnectionString))
                {
                    oConnection.Open();
                    using (SQLiteTransaction oTransaction = oConnection.BeginTransaction())
                    using (SQLiteCommand oCommand = new SQLiteCommand(sSchema, oConnection, oTransaction))
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
                using (SQLiteConnection oSource = new SQLiteConnection(new SQLiteConnectionStringBuilder
                {
                    DataSource = sSource, FailIfMissing = true, ReadOnly = true, Pooling = false
                }.ConnectionString))
                using (SQLiteConnection oDestination = new SQLiteConnection(new SQLiteConnectionStringBuilder
                {
                    DataSource = sTemporary, Pooling = false
                }.ConnectionString))
                {
                    oSource.Open();
                    oDestination.Open();
                    oSource.BackupDatabase(oDestination, "main", "main", -1, null, 0);
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
