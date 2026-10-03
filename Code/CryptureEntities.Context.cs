using Microsoft.EntityFrameworkCore;
using System;

namespace Crypture
{
    public partial class CryptureEntities : DbContext
    {
        private readonly IVaultStorage oStorage = Storage;

        public CryptureEntities()
        {
            // Explicit commits apply SQLite's lock waiting even to single-statement saves with RETURNING.
            Database.AutoTransactionBehavior = AutoTransactionBehavior.Always;
        }

        internal static IVaultStorage Storage { get; set; } = SqliteVaultStorage.FromConnectionString("");

        public static string ConnectionString
        {
            get => Storage.ConnectionString;
            set => Storage = SqliteVaultStorage.FromConnectionString(value);
        }

        public static string DatabasePath
        {
            set => Storage = new SqliteVaultStorage(value);
        }

        protected override void OnConfiguring(DbContextOptionsBuilder oOptions)
        {
            if (String.IsNullOrEmpty(oStorage.ConnectionString))
                throw new InvalidOperationException("Open a Vault first.");
            oStorage.Configure(oOptions);
        }

        protected override void OnModelCreating(ModelBuilder oModel)
        {
            // Keep the existing Vault schema and Windows identity/certificate relationships.
            oModel.Entity<User>(oUser =>
            {
                oUser.ToTable("User");
                oUser.HasKey(u => u.UserId);
                oUser.Property(u => u.Certificate).IsRequired();
                if (!oStorage.IsSqlServer) oUser.HasIndex(u => u.Certificate).IsUnique();
            });
            oModel.Entity<Item>(oItem =>
            {
                oItem.ToTable("Item");
                oItem.HasKey(i => i.ItemId);
                oItem.Property(i => i.Label).IsRequired();
                oItem.Property(i => i.ItemType).IsRequired();
                oItem.HasOne(i => i.User).WithMany(u => u.Items).HasForeignKey(i => i.ModifiedBy)
                    .OnDelete(oStorage.IsSqlServer ? DeleteBehavior.ClientSetNull : DeleteBehavior.SetNull);
                oItem.HasOne(i => i.Cipher).WithOne(c => c.Item).HasForeignKey<Cipher>(c => c.ItemId)
                    .OnDelete(DeleteBehavior.Cascade);
                if (oStorage.IsSqlServer) oItem.Property(i => i.RowVersion).IsRowVersion();
                else oItem.Ignore(i => i.RowVersion);
            });
            oModel.Entity<Cipher>(oCipher =>
            {
                if (oStorage.IsSqlServer) oCipher.ToView("AuthorizedCipher");
                else oCipher.ToTable("Cipher");
                oCipher.HasKey(c => c.ItemId);
                oCipher.Property(c => c.ItemId).ValueGeneratedNever();
                oCipher.Property(c => c.CipherText).IsRequired();
                oCipher.Property(c => c.CipherVector).IsRequired();
            });
            oModel.Entity<Instance>(oInstance =>
            {
                if (oStorage.IsSqlServer) oInstance.ToView("AuthorizedInstance");
                else oInstance.ToTable("Instance");
                oInstance.HasKey(i => i.InstanceId);
                oInstance.Property(i => i.CipherKey).IsRequired();
                oInstance.Property(i => i.Signature).IsRequired();
                oInstance.HasOne(i => i.Item).WithMany(i => i.Instances).HasForeignKey(i => i.ItemId)
                    .OnDelete(DeleteBehavior.Cascade);
                oInstance.HasOne(i => i.User).WithMany(u => u.Instances).HasForeignKey(i => i.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
        }

        public DbSet<Instance> Instances { get; set; }
        public DbSet<Item> Items { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<Cipher> Ciphers { get; set; }
    }
}
