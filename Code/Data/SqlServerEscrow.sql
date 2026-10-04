-- Check the framed recovery envelope, not an unframed byte search, before accepting a Windows escrow SID.
CREATE OR ALTER FUNCTION [dbo].[HasRecoveryDescriptor](
    @envelope varbinary(max), @primary nvarchar(max), @expected nvarchar(450))
RETURNS bit WITH SCHEMABINDING
AS
BEGIN
    DECLARE @length int = DATALENGTH(@envelope), @position int = 9, @index int = 0,
        @descriptorLength int, @keyLength int, @descriptor nvarchar(max), @found bit = 0;
    IF @length IS NULL OR @length < 17 OR @length > 2225184 OR
       [dbo].[ReadEnvelopeInt32](@envelope, 1) <> 1 RETURN 0;
    DECLARE @count int = [dbo].[ReadEnvelopeInt32](@envelope, 5);
    IF @count NOT BETWEEN 1 AND 2 RETURN 0;
    WHILE @index < @count
    BEGIN
        SET @descriptorLength = [dbo].[ReadEnvelopeInt32](@envelope, @position);
        SET @position = @position + 4;
        IF @descriptorLength IS NULL OR @descriptorLength < 1 OR @descriptorLength > 64000 OR
           @position + @descriptorLength - 1 > @length RETURN 0;
        SET @descriptor = CONVERT(nvarchar(max),
            CONVERT(varchar(max), SUBSTRING(@envelope, @position, @descriptorLength)));
        IF @index = 0 AND @primary IS NOT NULL AND @descriptor <> @primary RETURN 0;
        IF @descriptor = @expected SET @found = 1;
        SET @position = @position + @descriptorLength;
        SET @keyLength = [dbo].[ReadEnvelopeInt32](@envelope, @position);
        SET @position = @position + 4;
        IF @keyLength IS NULL OR @keyLength < 1 OR @keyLength > 1048576 OR
           @position + @keyLength - 1 > @length RETURN 0;
        SET @position = @position + @keyLength;
        SET @index = @index + 1;
    END;
    IF @position <> @length + 1 RETURN 0;
    RETURN @found;
END;
GO
-- The current Vault policy and the item label are read under the SaveItem transaction.
CREATE OR ALTER PROCEDURE [dbo].[SaveItemCore]
    @itemId bigint OUTPUT, @expectedRowVersion binary(8), @label nvarchar(max), @itemType nvarchar(max),
    @modifiedBy bigint, @cipherText varbinary(max), @cipherVector varbinary(max),
    @cipherParams bigint, @contentSuite bigint, @authenticationTag varbinary(max),
    @protectionDescriptor nvarchar(max), @protectedKey varbinary(max), @signature varbinary(max),
    @recipients [dbo].[EncryptedRecipient] READONLY
WITH EXECUTE AS 'crypture_writer'
AS
BEGIN
    SET NOCOUNT ON;
    IF @itemId = 0
    BEGIN
        INSERT INTO [dbo].[Item] ([Label], [ItemType], [ModifiedBy], [ModifiedByIdentity])
        VALUES (@label, @itemType, @modifiedBy, ORIGINAL_LOGIN());
        SET @itemId = CONVERT(bigint, SCOPE_IDENTITY());
    END
    ELSE
    BEGIN
        UPDATE [dbo].[Item] SET [Label] = @label, [ItemType] = @itemType,
            [ModifiedBy] = @modifiedBy, [ModifiedByIdentity] = ORIGINAL_LOGIN(),
            [ModifiedDate] = SYSDATETIME()
        WHERE [ItemId] = @itemId AND [RowVersion] = @expectedRowVersion;
        IF @@ROWCOUNT <> 1 THROW 50010, 'This item changed or was removed by another user.', 1;
        DELETE FROM [dbo].[Instance] WHERE [ItemId] = @itemId;
        DELETE FROM [dbo].[Cipher] WHERE [ItemId] = @itemId;
    END;
    INSERT INTO [dbo].[Cipher] ([ItemId], [CipherText], [CipherVector], [CipherParams],
        [ContentSuite], [AuthenticationTag], [ProtectionDescriptor], [ProtectedKey], [Signature], [EscrowLabel])
    SELECT @itemId, @cipherText, @cipherVector, @cipherParams, @contentSuite,
        @authenticationTag, @protectionDescriptor, @protectedKey, @signature, [EscrowLabel]
    FROM [dbo].[CryptureVault] WHERE [Id] = 1;
    INSERT INTO [dbo].[Instance] ([ItemId], [UserId], [CipherKey], [CipherParams], [Signature])
    SELECT @itemId, [UserId], [CipherKey], [CipherParams], [Signature] FROM @recipients;
END;
GO
CREATE OR ALTER PROCEDURE [dbo].[SaveItem]
    @itemId bigint OUTPUT, @expectedRowVersion binary(8), @label nvarchar(max), @itemType nvarchar(max),
    @modifiedBy bigint, @cipherText varbinary(max), @cipherVector varbinary(max),
    @cipherParams bigint, @contentSuite bigint, @authenticationTag varbinary(max),
    @protectionDescriptor nvarchar(max), @protectedKey varbinary(max), @signature varbinary(max),
    @recipients [dbo].[EncryptedRecipient] READONLY
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
    BEGIN TRY
        BEGIN TRANSACTION;
        IF @itemId <> 0 AND NOT EXISTS (SELECT 1 FROM [dbo].[CanReadItem](@itemId))
            THROW 50011, 'You are not a recipient of this item.', 1;
        IF NOT EXISTS (
            SELECT 1 FROM @recipients AS r
            INNER JOIN [dbo].[User] AS u ON u.[UserId] = r.[UserId]
            WHERE [dbo].[MatchesPrincipal](u.[Sid]) = 1
        ) AND [dbo].[MatchesDescriptor](@protectionDescriptor) = 0 AND
            [dbo].[MatchesRecoveryEnvelope](@protectedKey, @protectionDescriptor) = 0
            THROW 50012, 'Include your Windows account or group in the item recipients.', 1;
        IF @modifiedBy IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM [dbo].[User] WHERE [UserId] = @modifiedBy AND
                [dbo].[MatchesPrincipal]([Sid]) = 1
        ) THROW 50016, 'The modifying certificate must belong to your Windows account or group.', 1;
        IF @protectionDescriptor IS NOT NULL AND LEFT(@protectionDescriptor, 4) <> N'SID='
            THROW 50013, 'SQL Server items require domain users or groups for Windows protection.', 1;
        DECLARE @escrowUserId bigint, @escrowDescriptor nvarchar(450);
        SELECT @escrowUserId = [EscrowCertificateUserId], @escrowDescriptor = [EscrowDescriptor]
        FROM [dbo].[CryptureVault] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = 1;
        IF @escrowUserId IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM @recipients WHERE [UserId] = @escrowUserId)
            THROW 50023, 'Include the Vault escrow certificate in the saved recipients.', 1;
        IF @escrowDescriptor IS NOT NULL AND
            [dbo].[HasRecoveryDescriptor](@protectedKey, @protectionDescriptor, @escrowDescriptor) = 0
            THROW 50024, 'Include the Vault escrow user or group in the recovery envelope.', 1;
        EXEC [dbo].[SaveItemCore] @itemId OUTPUT, @expectedRowVersion, @label, @itemType,
            @modifiedBy, @cipherText, @cipherVector, @cipherParams, @contentSuite,
            @authenticationTag, @protectionDescriptor, @protectedKey, @signature, @recipients;
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO
GRANT EXECUTE ON [dbo].[SaveItem] TO [crypture_domain];
