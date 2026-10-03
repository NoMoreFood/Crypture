using System;
using System.Data;
using System.Data.Common;
using System.IO;
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
            ConnectionString = oBuilder.ConnectionString;
        }

        public string ConnectionString { get; }
        public string DisplayName => oBuilder.InitialCatalog + " @ " + oBuilder.DataSource;
        public bool IsSqlServer => true;
        public bool SupportsCompact => false;
        internal string DatabaseName => oBuilder.InitialCatalog;
        internal string RecentConnection
        {
            get
            {
                SqlConnectionStringBuilder oRecent = new SqlConnectionStringBuilder(ConnectionString);
                oRecent.Remove("Password");
                return oRecent.ConnectionString;
            }
        }

        public void Configure(DbContextOptionsBuilder oOptions) => oOptions.UseSqlServer(ConnectionString);

        public void Create()
        {
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
                using SqlConnection oVault = new SqlConnection(ConnectionString);
                oVault.Open();
                using SqlTransaction oTransaction = oVault.BeginTransaction();
                using StreamReader oReader = new StreamReader(typeof(SqlServerVaultStorage).Assembly
                    .GetManifestResourceStream("Crypture.SqlServerSchema"));
                using SqlCommand oSchema = new SqlCommand(oReader.ReadToEnd(), oVault, oTransaction);
                oSchema.ExecuteNonQuery();
                oTransaction.Commit();
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
            const int SupportedSchemaVersion = 1;
            // The marker prevents opening an arbitrary database with similarly named tables as a Vault.
            using SqlConnection oConnection = new SqlConnection(ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand(
                "SELECT [SchemaVersion] FROM [dbo].[CryptureVault] WHERE [Id] = @id", oConnection);
            oCommand.Parameters.AddWithValue("@id", VaultMarkerId);
            if (oCommand.ExecuteScalar() is not int nVersion || nVersion != SupportedSchemaVersion)
                throw new InvalidDataException("This is not a supported Crypture SQL Server Vault.");
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

        public void Compact() => throw new NotSupportedException("SQL Server manages database maintenance separately.");
    }
}
