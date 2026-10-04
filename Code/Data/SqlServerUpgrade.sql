-- Unverified affiliations cannot authorize item access until a Vault owner checks their identity.
ALTER TABLE [dbo].[User] ADD [IsEscrow] bit NOT NULL
    CONSTRAINT [DF_User_IsEscrow] DEFAULT 0;
UPDATE [dbo].[User] SET [Sid] = NULL;
REVOKE INSERT ON [dbo].[User] FROM [crypture_domain];
UPDATE [dbo].[CryptureVault] SET [SchemaVersion] = 3 WHERE [Id] = 1 AND [SchemaVersion] = 2;
IF @@ROWCOUNT <> 1 THROW 50021, 'The SQL Server Vault schema changed during upgrade.', 1;
GO
ALTER PROCEDURE [dbo].[RemoveCertificate] @userId bigint
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
    BEGIN TRY
        BEGIN TRANSACTION;
        IF NOT EXISTS (SELECT 1 FROM [dbo].[User]
                       WHERE [UserId] = @userId AND [dbo].[MatchesPrincipal]([Sid]) = 1)
            THROW 50014, 'This certificate is not affiliated with your Windows account.', 1;
        IF EXISTS (SELECT 1 FROM [dbo].[User] WHERE [UserId] = @userId AND [IsEscrow] = 1)
            THROW 50019, 'An escrow certificate cannot be removed from the Vault.', 1;
        IF EXISTS (SELECT 1 FROM [dbo].[Instance] WHERE [UserId] = @userId) OR
           EXISTS (SELECT 1 FROM [dbo].[Item] WHERE [ModifiedBy] = @userId)
            THROW 50015, 'Remove this certificate from its items before deleting it.', 1;
        EXEC [dbo].[RemoveCertificateCore] @userId;
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO
