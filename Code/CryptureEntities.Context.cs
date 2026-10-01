using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System;

namespace Crypture
{
    public partial class CryptureEntities : DbContext
    {
        public CryptureEntities()
        {
            // Explicit commits apply SQLite's lock waiting even to single-statement saves with RETURNING.
            Database.AutoTransactionBehavior = AutoTransactionBehavior.Always;
        }

        public static string ConnectionString { get; set; } = "";

        public static string DatabasePath
        {
            set => ConnectionString = new SqliteConnectionStringBuilder
            {
                DataSource = value, Mode = SqliteOpenMode.ReadWrite, ForeignKeys = true, Pooling = false
            }.ConnectionString;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder oOptions)
        {
            if (String.IsNullOrEmpty(ConnectionString)) throw new InvalidOperationException("Open a Vault first.");
            oOptions.UseSqlite(ConnectionString);
        }

        protected override void OnModelCreating(ModelBuilder oModel)
        {
            // Keep the existing Vault schema and Windows identity/certificate relationships.
            oModel.Entity<User>(oUser =>
            {
                oUser.ToTable("User");
                oUser.HasKey(u => u.UserId);
                oUser.Property(u => u.Certificate).IsRequired();
                oUser.HasIndex(u => u.Certificate).IsUnique();
            });
            oModel.Entity<Item>(oItem =>
            {
                oItem.ToTable("Item");
                oItem.HasKey(i => i.ItemId);
                oItem.Property(i => i.Label).IsRequired();
                oItem.Property(i => i.ItemType).IsRequired();
                oItem.HasOne(i => i.User).WithMany(u => u.Items).HasForeignKey(i => i.ModifiedBy)
                    .OnDelete(DeleteBehavior.SetNull);
                oItem.HasOne(i => i.Cipher).WithOne(c => c.Item).HasForeignKey<Cipher>(c => c.ItemId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
            oModel.Entity<Cipher>(oCipher =>
            {
                oCipher.ToTable("Cipher");
                oCipher.HasKey(c => c.ItemId);
                oCipher.Property(c => c.ItemId).ValueGeneratedNever();
                oCipher.Property(c => c.CipherText).IsRequired();
                oCipher.Property(c => c.CipherVector).IsRequired();
            });
            oModel.Entity<Instance>(oInstance =>
            {
                oInstance.ToTable("Instance");
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
