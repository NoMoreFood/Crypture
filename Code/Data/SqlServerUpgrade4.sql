-- Existing Vaults retain their encrypted items while the owner chooses a Vault-wide escrow identity.
ALTER TABLE [dbo].[CryptureVault] ADD
    [EscrowCertificateUserId] bigint NULL,
    [EscrowDescriptor] nvarchar(450) NULL,
    [EscrowLabel] nvarchar(450) NULL;
GO
ALTER TABLE [dbo].[CryptureVault] ADD CONSTRAINT [CK_CryptureVault_Escrow] CHECK (
    ([EscrowCertificateUserId] IS NULL AND [EscrowDescriptor] IS NULL AND [EscrowLabel] IS NULL) OR
    ([EscrowCertificateUserId] IS NOT NULL AND [EscrowDescriptor] IS NULL AND [EscrowLabel] IS NOT NULL) OR
    ([EscrowCertificateUserId] IS NULL AND [EscrowDescriptor] IS NOT NULL AND [EscrowLabel] IS NOT NULL));
ALTER TABLE [dbo].[CryptureVault] ADD CONSTRAINT [FK_CryptureVault_EscrowCertificate]
    FOREIGN KEY ([EscrowCertificateUserId]) REFERENCES [dbo].[User] ([UserId]);
ALTER TABLE [dbo].[Cipher] ADD [EscrowLabel] nvarchar(450) NULL;
EXEC sys.sp_refreshview N'dbo.AuthorizedCipher';
UPDATE [dbo].[CryptureVault] SET [SchemaVersion] = 4 WHERE [Id] = 1 AND [SchemaVersion] = 3;
IF @@ROWCOUNT <> 1 THROW 50022, 'The SQL Server Vault schema changed during upgrade.', 1;
