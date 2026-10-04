-- Vault owners verify a certificate's Windows identity before calling these procedures.
CREATE PROCEDURE [dbo].[EnrollCertificate]
    @certificate varbinary(max), @sid nvarchar(450), @userId bigint OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    IF @certificate IS NULL OR DATALENGTH(@certificate) NOT BETWEEN 1 AND 16384 OR
       [dbo].[SidBytes](@sid) IS NULL
        THROW 50017, 'A valid public certificate and Windows SID are required.', 1;
    INSERT INTO [dbo].[User] ([Certificate], [Sid]) VALUES (@certificate, @sid);
    SET @userId = CONVERT(bigint, SCOPE_IDENTITY());
END;
GO
-- The owner can select one enrolled certificate as the Vault's current recovery identity.
CREATE PROCEDURE [dbo].[MarkEscrowCertificate]
    @userId bigint, @label nvarchar(450) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    BEGIN TRY
        BEGIN TRANSACTION;
        IF @label IS NOT NULL AND (LEN(@label) < 1 OR LEN(@label) > 450)
            THROW 50025, 'A short escrow identity label is required.', 1;
        DECLARE @locked int;
        SELECT @locked = [Id] FROM [dbo].[CryptureVault] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = 1;
        IF NOT EXISTS (SELECT 1 FROM [dbo].[User] WHERE [UserId] = @userId)
            THROW 50018, 'The escrow certificate is not enrolled and verified.', 1;
        UPDATE [dbo].[User] SET [IsEscrow] = 0 WHERE [IsEscrow] = 1;
        UPDATE [dbo].[User] SET [IsEscrow] = 1 WHERE [UserId] = @userId;
        UPDATE [dbo].[CryptureVault] SET [EscrowCertificateUserId] = @userId,
            [EscrowDescriptor] = NULL, [EscrowLabel] = COALESCE(@label,
                (SELECT N'Certificate: ' + [Sid] FROM [dbo].[User] WHERE [UserId] = @userId))
        WHERE [Id] = 1;
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO
-- User and group escrow uses the existing Windows SID descriptor in the saved recovery envelope.
CREATE PROCEDURE [dbo].[SetVaultEscrowPrincipal]
    @sid nvarchar(450), @label nvarchar(450)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    BEGIN TRY
        BEGIN TRANSACTION;
        IF [dbo].[SidBytes](@sid) IS NULL OR @label IS NULL OR LEN(@label) < 1 OR LEN(@label) > 450
            THROW 50025, 'A verified Windows user or group and label are required.', 1;
        DECLARE @locked int;
        SELECT @locked = [Id] FROM [dbo].[CryptureVault] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = 1;
        UPDATE [dbo].[CryptureVault] SET [EscrowCertificateUserId] = NULL,
            [EscrowDescriptor] = N'SID=' + @sid, [EscrowLabel] = @label WHERE [Id] = 1;
        UPDATE [dbo].[User] SET [IsEscrow] = 0 WHERE [IsEscrow] = 1;
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO
