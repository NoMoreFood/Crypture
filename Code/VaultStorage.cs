using System;
using System.Data;
using System.Data.Common;
using System.IO;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
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
        DbConnection OpenHealthConnection();
        DbTransaction BeginHealthSnapshot(DbConnection oConnection);
        void Compact();
        Task CreateAsync(CancellationToken oCancellation);
        Task ValidateAsync(CancellationToken oCancellation);
        Task ReadSnapshotAsync(CryptureEntities oContent, Func<Task> oRead, CancellationToken oCancellation);
        Task BackupAsync(string sDestination, CancellationToken oCancellation);
        Task<(bool CanEnroll, bool CanBackup)> ReadPermissionsAsync(CancellationToken oCancellation) =>
            Task.FromResult((true, true));
    }

    internal sealed class SqliteVaultStorage : IVaultStorage
    {
        private readonly string sPath;

        internal SqliteVaultStorage(string sDatabasePath) : this(sDatabasePath,
            String.IsNullOrEmpty(sDatabasePath) ? "" : new SqliteConnectionStringBuilder
            {
                DataSource = sDatabasePath, Mode = SqliteOpenMode.ReadWrite, ForeignKeys = true, Pooling = false
            }.ConnectionString)
        {
        }

        private SqliteVaultStorage(string sDatabasePath, string sConnection)
        {
            sPath = sDatabasePath;
            ConnectionString = sConnection;
        }

        internal static SqliteVaultStorage FromConnectionString(string sConnection) => new SqliteVaultStorage(
            String.IsNullOrEmpty(sConnection) ? "" : new SqliteConnectionStringBuilder(sConnection).DataSource,
            sConnection);

        public string ConnectionString { get; }
        public string DisplayName => sPath;
        public bool IsSqlServer => false;
        public bool SupportsCompact => true;

        public void Configure(DbContextOptionsBuilder oOptions) => oOptions.UseSqlite(ConnectionString);

        // File Vault work is synchronous; run it on the thread pool to keep callers responsive.
        public Task CreateAsync(CancellationToken oCancellation) => Task.Run(Create, oCancellation);
        public Task ValidateAsync(CancellationToken oCancellation) => Task.Run(Validate, oCancellation);
        public Task ReadSnapshotAsync(CryptureEntities oContent, Func<Task> oRead, CancellationToken oCancellation) =>
            Task.Run(() => ReadSnapshot(oContent, () => oRead().GetAwaiter().GetResult()), oCancellation);
        public Task BackupAsync(string sDestination, CancellationToken oCancellation) =>
            Task.Run(() => Backup(sDestination), oCancellation);

        internal void Create()
        {
            using StreamReader oReader = new StreamReader(typeof(SqliteVaultStorage).Assembly
                .GetManifestResourceStream("Crypture.SqliteSchema"));
            DatabaseOperations.CreateDatabase(sPath, oReader.ReadToEnd());
        }

        internal void Validate()
        {
            // Check the complete schema in a read snapshot without changing the Vault.
            using SqliteConnection oConnection = (SqliteConnection)OpenHealthConnection();
            oConnection.Open();
            using SqliteTransaction oTransaction = oConnection.BeginTransaction(deferred: true);
            using SqliteCommand oCommand = new SqliteCommand(
                "SELECT i.[ItemId], i.[ItemType], i.[Label], i.[ModifiedDate], i.[ModifiedBy], " +
                "i.[ModifiedByIdentity], i.[CreatedDate], c.[ItemId], c.[CipherText], c.[CipherVector], " +
                "c.[CipherParams], c.[ContentSuite], c.[AuthenticationTag], c.[ProtectionDescriptor], " +
                "c.[ProtectedKey], c.[Signature], r.[InstanceId], r.[ItemId], r.[UserId], r.[CipherKey], " +
                "r.[CipherParams], r.[Signature], u.[UserId], u.[Certificate], u.[Sid] " +
                "FROM [Item] i, [Cipher] c, [Instance] r, [User] u LIMIT 0;",
                oConnection, oTransaction);
            try { oCommand.ExecuteNonQuery(); }
            catch (SqliteException oError) when (oError.SqliteErrorCode == 1)
            {
                throw new InvalidDataException("This is not a supported Crypture Vault.", oError);
            }
            oTransaction.Commit();
        }

        internal void ReadSnapshot(CryptureEntities oContent, Action oRead)
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

        internal void Backup(string sDestination) => DatabaseOperations.BackupDatabase(sPath, sDestination);

        public void Compact()
        {
            using CryptureEntities oContent = new CryptureEntities(this);
            oContent.Database.ExecuteSqlRaw("VACUUM;");
        }
    }

    internal sealed class SqlServerVaultStorage : IVaultStorage
    {
        private const int VaultMarkerId = 1;
        private readonly SqlConnectionStringBuilder oBuilder;

        internal SqlServerVaultStorage(string sConnection)
        {
            oBuilder = new SqlConnectionStringBuilder(sConnection) { PersistSecurityInfo = false };
            if (String.IsNullOrWhiteSpace(oBuilder.DataSource) || String.IsNullOrWhiteSpace(oBuilder.InitialCatalog))
                throw new ArgumentException("Enter a SQL Server name and database name.");
            if (!oBuilder.IntegratedSecurity || oBuilder.UserID.Length != 0 || oBuilder.Password.Length != 0)
                throw new ArgumentException("SQL Server Vaults require Windows integrated authentication.");

            // Recipient certificates travel over this connection, so never accept an unencrypted one.
            if (oBuilder.Encrypt.Equals(SqlConnectionEncryptOption.Optional))
                oBuilder.Encrypt = SqlConnectionEncryptOption.Mandatory;
            ConnectionString = oBuilder.ConnectionString;
        }

        public string ConnectionString { get; }
        public string DisplayName => oBuilder.InitialCatalog + " @ " + oBuilder.DataSource;
        public bool IsSqlServer => true;
        public bool SupportsCompact => false;
        internal string DatabaseName => oBuilder.InitialCatalog;
        internal SqlServerEscrowChoice EscrowChoice { get; set; }
        internal bool GrantDomainUsers { get; set; } = true;
        internal SqlServerEscrowPolicy Escrow { get; private set; }

        public void Configure(DbContextOptionsBuilder oOptions) => oOptions.UseSqlServer(ConnectionString);

        public async Task CreateAsync(CancellationToken oCancellation)
        {
            if (EscrowChoice == null)
                throw new InvalidOperationException("Choose an escrow certificate or Windows user/group " +
                    "before creating a SQL Server Vault.");
            // Create only a new database; never initialize an unrelated existing database.
            SqlConnectionStringBuilder oMaster = new SqlConnectionStringBuilder(ConnectionString)
            {
                InitialCatalog = "master", Pooling = false
            };
            using SqlConnection oConnection = new SqlConnection(oMaster.ConnectionString);
            await oConnection.OpenAsync(oCancellation).ConfigureAwait(false);
            using (SqlCommand oCheck = new SqlCommand("SELECT DB_ID(@name)", oConnection))
            {
                oCheck.Parameters.AddWithValue("@name", DatabaseName);
                if (await oCheck.ExecuteScalarAsync(oCancellation).ConfigureAwait(false) != DBNull.Value)
                    throw new IOException("The SQL Server database already exists. Choose a new database name.");
            }
            string sQuotedName = "[" + DatabaseName.Replace("]", "]]", StringComparison.Ordinal) + "]";
            string sQuotedLogin = null;
            bool bLoginCreated = false;
            oCancellation.ThrowIfCancellationRequested();

            // Confirm creation before cancellation can clean up the newly owned database.
            using (SqlCommand oCreate = new SqlCommand("CREATE DATABASE " + sQuotedName, oConnection))
                await oCreate.ExecuteNonQueryAsync(CancellationToken.None).ConfigureAwait(false);
            try
            {
                // Provision the domain's Users group with the limited Vault role when the creator chose to.
                string sDomainUsers = GrantDomainUsers
                    ? await Task.Run(GetDomainUsersName, oCancellation).ConfigureAwait(false) : null;
                if (sDomainUsers != null)
                {
                    sQuotedLogin = "[" + sDomainUsers.Replace("]", "]]", StringComparison.Ordinal) + "]";
                    using SqlCommand oExists = new SqlCommand(
                        "SELECT 1 FROM sys.server_principals WHERE [name] = @name", oConnection);
                    oExists.Parameters.AddWithValue("@name", sDomainUsers);
                    if (await oExists.ExecuteScalarAsync(oCancellation).ConfigureAwait(false) == null)
                    {
                        using SqlCommand oLogin = new SqlCommand(
                            "CREATE LOGIN " + sQuotedLogin + " FROM WINDOWS", oConnection);
                        await oLogin.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
                        bLoginCreated = true;
                    }
                }
                // Provision without pooling so failed creation can drop the newly owned database.
                using SqlConnection oVault = new SqlConnection(new SqlConnectionStringBuilder(ConnectionString)
                    { Pooling = false }.ConnectionString);
                await oVault.OpenAsync(oCancellation).ConfigureAwait(false);
                using SqlTransaction oTransaction = (SqlTransaction)await oVault.BeginTransactionAsync(oCancellation)
                    .ConfigureAwait(false);
                using StreamReader oReader = new StreamReader(typeof(SqlServerVaultStorage).Assembly
                    .GetManifestResourceStream("Crypture.SqlServerSchema"));
                using SqlCommand oSchema = new SqlCommand(oReader.ReadToEnd(), oVault, oTransaction);
                await oSchema.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
                foreach (string sResource in new[] { "Crypture.SqlServerSecurity",
                    "Crypture.SqlServerEnrollment", "Crypture.SqlServerEscrow" })
                    await ExecuteBatchesAsync(oVault, oTransaction, sResource, oCancellation).ConfigureAwait(false);
                if (EscrowChoice.Certificate != null)
                {
                    using SqlCommand oEnroll = SqlServerCertificateEnrollment.EnrollCommand(oVault, oTransaction,
                        EscrowChoice.Certificate, EscrowChoice.Sid);
                    await oEnroll.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
                    using SqlCommand oEscrow = SqlServerCertificateEnrollment.EscrowCommand(oVault, oTransaction,
                        (long)oEnroll.Parameters["@userId"].Value, EscrowChoice.Label);
                    await oEscrow.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
                }
                else
                {
                    using SqlCommand oEscrow = SqlServerItemOperations.Procedure(oVault,
                        "[dbo].[SetVaultEscrowPrincipal]", oTransaction);
                    oEscrow.Parameters.Add("@sid", SqlDbType.NVarChar, 450).Value = EscrowChoice.Sid;
                    oEscrow.Parameters.Add("@label", SqlDbType.NVarChar, 450).Value = EscrowChoice.Label;
                    await oEscrow.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
                }
                if (sQuotedLogin != null)
                    using (SqlCommand oGrant = new SqlCommand("CREATE USER " + sQuotedLogin + " FOR LOGIN " +
                        sQuotedLogin + "; ALTER ROLE [crypture_domain] ADD MEMBER " + sQuotedLogin, oVault,
                        oTransaction)) await oGrant.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
                await oTransaction.CommitAsync(oCancellation).ConfigureAwait(false);
                await RefreshEscrowAsync(oCancellation, oVault).ConfigureAwait(false);
            }
            catch
            {
                // Remove only what this attempt created, leaving a login that already existed in place.
                using SqlCommand oDrop = new SqlCommand("DROP DATABASE " + sQuotedName +
                    (bLoginCreated ? "; DROP LOGIN " + sQuotedLogin : ""), oConnection);
                await oDrop.ExecuteNonQueryAsync(CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        }

        public async Task ValidateAsync(CancellationToken oCancellation)
        {
            const int SupportedSchemaVersion = 9;

            // The marker prevents opening an arbitrary database with similarly named tables as a Vault.
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            await oConnection.OpenAsync(oCancellation).ConfigureAwait(false);
            using SqlCommand oCommand = new SqlCommand(
                "SELECT [SchemaVersion] FROM [dbo].[CryptureVault] WHERE [Id] = @id", oConnection);
            oCommand.Parameters.AddWithValue("@id", VaultMarkerId);
            if (await oCommand.ExecuteScalarAsync(oCancellation).ConfigureAwait(false) is not int nVersion ||
                nVersion != SupportedSchemaVersion)
                throw new InvalidDataException("This is not a supported Crypture SQL Server Vault.");
            await RefreshEscrowAsync(oCancellation, oConnection).ConfigureAwait(false);
        }

        internal SqlServerEscrowPolicy RefreshEscrow() =>
            RefreshEscrowAsync(CancellationToken.None).GetAwaiter().GetResult();

        internal async Task<SqlServerEscrowPolicy> RefreshEscrowAsync(CancellationToken oCancellation,
            SqlConnection oOpenConnection = null)
        {
            // Reuse the caller's open connection when one is available to avoid another login.
            using SqlConnection oOwned = oOpenConnection == null ? new SqlConnection(ConnectionString) : null;
            if (oOwned != null) await oOwned.OpenAsync(oCancellation).ConfigureAwait(false);
            using SqlCommand oCommand = new SqlCommand(
                "SELECT v.[EscrowCertificateUserId], u.[Certificate], v.[EscrowDescriptor], " +
                "v.[EscrowLabel] FROM [dbo].[CryptureVault] AS v LEFT JOIN [dbo].[User] AS u " +
                "ON u.[UserId] = v.[EscrowCertificateUserId] WHERE v.[Id] = @id", oOpenConnection ?? oOwned);
            oCommand.Parameters.AddWithValue("@id", VaultMarkerId);
            using SqlDataReader oReader = await oCommand.ExecuteReaderAsync(oCancellation).ConfigureAwait(false);
            if (!await oReader.ReadAsync(oCancellation).ConfigureAwait(false))
                throw new InvalidDataException("This is not a supported Crypture SQL Server Vault.");
            Escrow = oReader.IsDBNull(3) ? null : new SqlServerEscrowPolicy(
                oReader.IsDBNull(0) ? null : oReader.GetInt64(0),
                oReader.IsDBNull(1) ? null : (byte[])oReader[1],
                oReader.IsDBNull(2) ? null : oReader.GetString(2), oReader.GetString(3));
            return Escrow;
        }

        private static async Task ExecuteBatchesAsync(SqlConnection oConnection, SqlTransaction oTransaction,
            string sResource, CancellationToken oCancellation)
        {
            using StreamReader oReader = new StreamReader(typeof(SqlServerVaultStorage).Assembly
                .GetManifestResourceStream(sResource));
            foreach (string sBatch in Regex.Split(oReader.ReadToEnd(), @"(?im)^[ \t]*GO[ \t]*\r?$"))
            {
                if (String.IsNullOrWhiteSpace(sBatch)) continue;
                using SqlCommand oCommand = new SqlCommand(sBatch, oConnection, oTransaction);
                await oCommand.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
            }
        }

        private static string GetDomainUsersName()
        {
            using WindowsIdentity oIdentity = WindowsIdentity.GetCurrent();
            SecurityIdentifier oDomain = oIdentity.User?.AccountDomainSid;
            if (!PrincipalProtection.IsDomainJoined || oDomain == null) return null;
            return new SecurityIdentifier(oDomain.Value + "-513").Translate(typeof(NTAccount)).Value;
        }

        public async Task ReadSnapshotAsync(CryptureEntities oContent, Func<Task> oRead,
            CancellationToken oCancellation)
        {
            await using var oTransaction = await oContent.Database.BeginTransactionAsync(
                IsolationLevel.Serializable, oCancellation).ConfigureAwait(false);
            await oRead().ConfigureAwait(false);
            await oTransaction.CommitAsync(oCancellation).ConfigureAwait(false);
        }

        public DbConnection OpenHealthConnection() => new SqlConnection(ConnectionString);

        public DbTransaction BeginHealthSnapshot(DbConnection oConnection) =>
            oConnection.BeginTransaction(IsolationLevel.Serializable);

        public async Task BackupAsync(string sDestination, CancellationToken oCancellation)
        {
            // SQL Server writes this path on the server, using the server service account.
            string sQuotedName = "[" + DatabaseName.Replace("]", "]]", StringComparison.Ordinal) + "]";
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            await oConnection.OpenAsync(oCancellation).ConfigureAwait(false);
            using SqlCommand oCommand = new SqlCommand("BACKUP DATABASE " + sQuotedName +
                " TO DISK = @destination WITH COPY_ONLY, CHECKSUM", oConnection) { CommandTimeout = 0 };
            oCommand.Parameters.AddWithValue("@destination", sDestination);
            await oCommand.ExecuteNonQueryAsync(oCancellation).ConfigureAwait(false);
        }

        public async Task<(bool CanEnroll, bool CanBackup)> ReadPermissionsAsync(CancellationToken oCancellation)
        {
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            await oConnection.OpenAsync(oCancellation).ConfigureAwait(false);
            using SqlCommand oCommand = new SqlCommand(
                "SELECT CASE WHEN IS_ROLEMEMBER(N'db_owner') = 1 OR " +
                "IS_SRVROLEMEMBER(N'sysadmin') = 1 THEN 1 ELSE 0 END, " +
                "HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'BACKUP DATABASE')", oConnection);
            using SqlDataReader oReader = await oCommand.ExecuteReaderAsync(oCancellation).ConfigureAwait(false);
            if (!await oReader.ReadAsync(oCancellation).ConfigureAwait(false))
                throw new InvalidDataException("The Vault permissions could not be read.");
            return (oReader.GetInt32(0) == 1, !oReader.IsDBNull(1) && oReader.GetInt32(1) == 1);
        }

        public void Compact() => throw new NotSupportedException("SQL Server manages database maintenance separately.");
    }
}
