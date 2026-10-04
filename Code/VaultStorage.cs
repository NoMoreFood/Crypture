using System;
using System.Data;
using System.Data.Common;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Crypture
{
    internal interface IVaultStorage
    {
        string ConnectionString { get; }
        string DisplayName { get; }
        bool IsSqlServer { get; }
        bool SupportsCompact { get; }
        void Configure(DbContextOptionsBuilder oOptions);
        void Create();
        void Validate();
        void ReadSnapshot(CryptureEntities oContent, Action oRead);
        DbConnection OpenHealthConnection();
        DbTransaction BeginHealthSnapshot(DbConnection oConnection);
        void Backup(string sDestination);
        void Compact();
    }

    internal sealed class SqliteVaultStorage : IVaultStorage
    {
        private readonly string sPath;

        internal SqliteVaultStorage(string sDatabasePath)
        {
            sPath = sDatabasePath;
            ConnectionString = String.IsNullOrEmpty(sDatabasePath) ? "" : new SqliteConnectionStringBuilder
            {
                DataSource = sDatabasePath, Mode = SqliteOpenMode.ReadWrite, ForeignKeys = true, Pooling = false
            }.ConnectionString;
        }

        private SqliteVaultStorage(string sConnection, bool bRaw)
        {
            ConnectionString = sConnection;
            sPath = String.IsNullOrEmpty(sConnection) ? "" : new SqliteConnectionStringBuilder(sConnection).DataSource;
        }

        internal static SqliteVaultStorage FromConnectionString(string sConnection) =>
            new SqliteVaultStorage(sConnection, true);

        public string ConnectionString { get; }
        public string DisplayName => sPath;
        public bool IsSqlServer => false;
        public bool SupportsCompact => true;

        public void Configure(DbContextOptionsBuilder oOptions) => oOptions.UseSqlite(ConnectionString);

        public void Create()
        {
            using StreamReader oReader = new StreamReader(typeof(SqliteVaultStorage).Assembly
                .GetManifestResourceStream("Crypture.SqliteSchema"));
            DatabaseOperations.CreateDatabase(sPath, oReader.ReadToEnd());
        }

        public void Validate() => DatabaseOperations.EnsureProtectionSchema(sPath);

        public void ReadSnapshot(CryptureEntities oContent, Action oRead)
        {
            // Deferred SQLite reads keep one version without taking a writer lock before the first query.
            oContent.Database.OpenConnection();
            using SqliteTransaction oTransaction = ((SqliteConnection)oContent.Database.GetDbConnection())
                .BeginTransaction(deferred: true);
            using var oSnapshot = oContent.Database.UseTransaction(oTransaction);
            oRead();
            oSnapshot.Commit();
        }

        public DbConnection OpenHealthConnection() => new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = sPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false
        }.ConnectionString);

        public DbTransaction BeginHealthSnapshot(DbConnection oConnection) =>
            ((SqliteConnection)oConnection).BeginTransaction(deferred: true);

        public void Backup(string sDestination) => DatabaseOperations.BackupDatabase(sPath, sDestination);

        public void Compact()
        {
            using CryptureEntities oContent = new CryptureEntities();
            oContent.Database.ExecuteSqlRaw("VACUUM;");
        }
    }

    internal sealed class SqlServerVaultStorage : IVaultStorage
    {
        private readonly SqlConnectionStringBuilder oBuilder;

        internal SqlServerVaultStorage(string sConnection)
        {
            oBuilder = new SqlConnectionStringBuilder(sConnection) { PersistSecurityInfo = false, Pooling = false };
            if (String.IsNullOrWhiteSpace(oBuilder.DataSource) || String.IsNullOrWhiteSpace(oBuilder.InitialCatalog))
                throw new ArgumentException("Enter a SQL Server name and database name.");
            if (!oBuilder.IntegratedSecurity || oBuilder.UserID.Length != 0 || oBuilder.Password.Length != 0)
                throw new ArgumentException("SQL Server Vaults require Windows integrated authentication.");
            ConnectionString = oBuilder.ConnectionString;
        }

        public string ConnectionString { get; }
        public string DisplayName => oBuilder.InitialCatalog + " @ " + oBuilder.DataSource;
        public bool IsSqlServer => true;
        public bool SupportsCompact => false;
        internal string DatabaseName => oBuilder.InitialCatalog;
        internal string RecentConnection => ConnectionString;
        internal SqlServerEscrowChoice EscrowChoice { get; set; }
        internal SqlServerEscrowPolicy Escrow { get; private set; }

        public void Configure(DbContextOptionsBuilder oOptions) => oOptions.UseSqlServer(ConnectionString);

        public void Create()
        {
            if (EscrowChoice == null)
                throw new InvalidOperationException("Choose an escrow certificate or Windows user/group " +
                    "before creating a SQL Server Vault.");
            // Create only a new database; never initialize an unrelated existing database.
            SqlConnectionStringBuilder oMaster = new SqlConnectionStringBuilder(ConnectionString)
            {
                InitialCatalog = "master"
            };
            using SqlConnection oConnection = new SqlConnection(oMaster.ConnectionString);
            oConnection.Open();
            using (SqlCommand oCheck = new SqlCommand("SELECT DB_ID(@name)", oConnection))
            {
                oCheck.Parameters.AddWithValue("@name", DatabaseName);
                if (oCheck.ExecuteScalar() != DBNull.Value)
                    throw new IOException("The SQL Server database already exists. Choose a new database name.");
            }
            string sQuotedName = "[" + DatabaseName.Replace("]", "]]", StringComparison.Ordinal) + "]";
            using (SqlCommand oCreate = new SqlCommand("CREATE DATABASE " + sQuotedName, oConnection))
                oCreate.ExecuteNonQuery();
            try
            {
                // Provision the domain's Users group with the limited Vault role.
                string sDomainUsers = GetDomainUsersName();
                string sQuotedLogin = sDomainUsers == null ? null :
                    "[" + sDomainUsers.Replace("]", "]]", StringComparison.Ordinal) + "]";
                if (sDomainUsers != null)
                {
                    using SqlCommand oLogin = new SqlCommand(
                        "IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE [name] = @name) " +
                        "EXEC(N'CREATE LOGIN " + sQuotedLogin.Replace("'", "''", StringComparison.Ordinal) +
                        " FROM WINDOWS')", oConnection);
                    oLogin.Parameters.AddWithValue("@name", sDomainUsers);
                    oLogin.ExecuteNonQuery();
                }
                using SqlConnection oVault = new SqlConnection(ConnectionString);
                oVault.Open();
                using SqlTransaction oTransaction = oVault.BeginTransaction();
                using StreamReader oReader = new StreamReader(typeof(SqlServerVaultStorage).Assembly
                    .GetManifestResourceStream("Crypture.SqlServerSchema"));
                using SqlCommand oSchema = new SqlCommand(oReader.ReadToEnd(), oVault, oTransaction);
                oSchema.ExecuteNonQuery();
                ExecuteBatches(oVault, oTransaction, "Crypture.SqlServerSecurity");
                ExecuteBatches(oVault, oTransaction, "Crypture.SqlServerEnrollment");
                ExecuteBatches(oVault, oTransaction, "Crypture.SqlServerEscrow");
                if (EscrowChoice.Certificate != null)
                {
                    using SqlCommand oEnroll = new SqlCommand("[dbo].[EnrollCertificate]", oVault, oTransaction)
                        { CommandType = CommandType.StoredProcedure };
                    oEnroll.Parameters.Add("@certificate", SqlDbType.VarBinary, -1).Value = EscrowChoice.Certificate;
                    oEnroll.Parameters.Add("@sid", SqlDbType.NVarChar, 450).Value = EscrowChoice.Sid;
                    SqlParameter oUserId = oEnroll.Parameters.Add("@userId", SqlDbType.BigInt);
                    oUserId.Direction = ParameterDirection.Output;
                    oEnroll.ExecuteNonQuery();
                    using SqlCommand oEscrow = new SqlCommand("[dbo].[MarkEscrowCertificate]", oVault, oTransaction)
                        { CommandType = CommandType.StoredProcedure };
                    oEscrow.Parameters.Add("@userId", SqlDbType.BigInt).Value = oUserId.Value;
                    oEscrow.Parameters.Add("@label", SqlDbType.NVarChar, 450).Value = EscrowChoice.Label;
                    oEscrow.ExecuteNonQuery();
                }
                else
                {
                    using SqlCommand oEscrow = new SqlCommand("[dbo].[SetVaultEscrowPrincipal]", oVault,
                        oTransaction) { CommandType = CommandType.StoredProcedure };
                    oEscrow.Parameters.Add("@sid", SqlDbType.NVarChar, 450).Value = EscrowChoice.Sid;
                    oEscrow.Parameters.Add("@label", SqlDbType.NVarChar, 450).Value = EscrowChoice.Label;
                    oEscrow.ExecuteNonQuery();
                }
                if (sQuotedLogin != null)
                    using (SqlCommand oGrant = new SqlCommand("CREATE USER " + sQuotedLogin + " FOR LOGIN " +
                        sQuotedLogin + "; ALTER ROLE [crypture_domain] ADD MEMBER " + sQuotedLogin, oVault,
                        oTransaction)) oGrant.ExecuteNonQuery();
                oTransaction.Commit();
                RefreshEscrow();
            }
            catch
            {
                using SqlCommand oDrop = new SqlCommand("DROP DATABASE " + sQuotedName, oConnection);
                oDrop.ExecuteNonQuery();
                throw;
            }
        }

        public void Validate()
        {
            const int VaultMarkerId = 1;
            const int SupportedSchemaVersion = 6;

            // The marker prevents opening an arbitrary database with similarly named tables as a Vault.
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand(
                "SELECT [SchemaVersion] FROM [dbo].[CryptureVault] WHERE [Id] = @id", oConnection);
            oCommand.Parameters.AddWithValue("@id", VaultMarkerId);
            if (oCommand.ExecuteScalar() is not int nVersion || nVersion != SupportedSchemaVersion)
                throw new InvalidDataException("This is not a supported Crypture SQL Server Vault.");
            RefreshEscrow();
        }

        internal SqlServerEscrowPolicy RefreshEscrow()
        {
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand(
                "SELECT v.[EscrowCertificateUserId], u.[Certificate], v.[EscrowDescriptor], " +
                "v.[EscrowLabel] FROM [dbo].[CryptureVault] AS v LEFT JOIN [dbo].[User] AS u " +
                "ON u.[UserId] = v.[EscrowCertificateUserId] WHERE v.[Id] = 1", oConnection);
            using SqlDataReader oReader = oCommand.ExecuteReader();
            if (!oReader.Read()) throw new InvalidDataException("This is not a supported Crypture SQL Server Vault.");
            Escrow = oReader.IsDBNull(3) ? null : new SqlServerEscrowPolicy(
                oReader.IsDBNull(0) ? null : oReader.GetInt64(0),
                oReader.IsDBNull(1) ? null : (byte[])oReader[1],
                oReader.IsDBNull(2) ? null : oReader.GetString(2), oReader.GetString(3));
            return Escrow;
        }

        private static void ExecuteBatches(SqlConnection oConnection, SqlTransaction oTransaction,
            string sResource)
        {
            using StreamReader oReader = new StreamReader(typeof(SqlServerVaultStorage).Assembly
                .GetManifestResourceStream(sResource));
            foreach (string sBatch in Regex.Split(oReader.ReadToEnd(), @"(?im)^[ \t]*GO[ \t]*\r?$"))
            {
                if (String.IsNullOrWhiteSpace(sBatch)) continue;
                using SqlCommand oCommand = new SqlCommand(sBatch, oConnection, oTransaction);
                oCommand.ExecuteNonQuery();
            }
        }

        private static string GetDomainUsersName()
        {
            using WindowsIdentity oIdentity = WindowsIdentity.GetCurrent();
            SecurityIdentifier oDomain = oIdentity.User?.AccountDomainSid;
            if (!PrincipalProtection.IsDomainJoined || oDomain == null) return null;
            return new SecurityIdentifier(oDomain.Value + "-513").Translate(typeof(NTAccount)).Value;
        }

        public void ReadSnapshot(CryptureEntities oContent, Action oRead)
        {
            using var oTransaction = oContent.Database.BeginTransaction(IsolationLevel.Serializable);
            oRead();
            oTransaction.Commit();
        }

        public DbConnection OpenHealthConnection() => new SqlConnection(ConnectionString);

        public DbTransaction BeginHealthSnapshot(DbConnection oConnection) =>
            oConnection.BeginTransaction(IsolationLevel.Serializable);

        public void Backup(string sDestination)
        {
            // SQL Server writes this path on the server, using the server service account.
            string sQuotedName = "[" + DatabaseName.Replace("]", "]]", StringComparison.Ordinal) + "]";
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand("BACKUP DATABASE " + sQuotedName +
                " TO DISK = @destination WITH COPY_ONLY, CHECKSUM", oConnection) { CommandTimeout = 0 };
            oCommand.Parameters.AddWithValue("@destination", sDestination);
            oCommand.ExecuteNonQuery();
        }

        internal bool CanBackup()
        {
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand(
                "SELECT HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'BACKUP DATABASE')", oConnection);
            return oCommand.ExecuteScalar() is int nPermission && nPermission == 1;
        }

        internal bool CanEnrollCertificates()
        {
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand(
                "SELECT CASE WHEN IS_ROLEMEMBER(N'db_owner') = 1 OR " +
                "IS_SRVROLEMEMBER(N'sysadmin') = 1 THEN 1 ELSE 0 END", oConnection);
            return oCommand.ExecuteScalar() is int nPermission && nPermission == 1;
        }

        public void Compact() => throw new NotSupportedException("SQL Server manages database maintenance separately.");
    }
}
