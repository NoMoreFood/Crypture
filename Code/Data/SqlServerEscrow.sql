-- Validate the framed recovery envelope and optionally require a Windows escrow descriptor.
CREATE FUNCTION [dbo].[HasRecoveryDescriptor](
    @envelope varbinary(max), @primary nvarchar(max), @expected nvarchar(450))
RETURNS bit WITH SCHEMABINDING
AS
BEGIN
    DECLARE @length int = DATALENGTH(@envelope), @position int = 9, @index int = 0,
        @descriptorLength int, @keyLength int, @descriptor nvarchar(max),
        @found bit = CASE WHEN @expected IS NULL THEN 1 ELSE 0 END;
    IF @length IS NULL OR @length < 17 OR @length > 2225184 OR
       ISNULL([dbo].[ReadEnvelopeInt32](@envelope, 1), 0) <> 1 RETURN 0;
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
CREATE PROCEDURE [dbo].[SaveItemCore]
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
CREATE PROCEDURE [dbo].[SaveItem]
    @itemId bigint OUTPUT, @expectedRowVersion binary(8), @label nvarchar(max), @itemType nvarchar(max),
    @modifiedBy bigint, @cipherText varbinary(max), @cipherVector varbinary(max),
    @cipherParams bigint, @contentSuite bigint, @authenticationTag varbinary(max),
    @protectionDescriptor nvarchar(max), @protectedKey varbinary(max), @signature varbinary(max),
    @recipients [dbo].[EncryptedRecipient] READONLY
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    -- Bound encrypted content and metadata before acquiring the item and escrow locks.
    DECLARE @maximumContentBytes int = CASE WHEN @itemType IN (N'text', N'richtext', N'totp')
        THEN 67108864 ELSE 68157440 END;
    IF @label IS NULL OR DATALENGTH(@label) NOT BETWEEN 2 AND 32000 OR
       @itemType IS NULL OR DATALENGTH(@itemType) > 900 OR
       @cipherParams IS NULL OR @cipherParams NOT IN (2, 3, 4) OR
       @contentSuite IS NULL OR @contentSuite NOT IN (1, 2) OR
       @cipherText IS NULL OR @cipherVector IS NULL OR
       (@contentSuite = 1 AND (DATALENGTH(@cipherText) > @maximumContentBytes OR
           DATALENGTH(@cipherVector) <> 12 OR @authenticationTag IS NULL OR
           DATALENGTH(@authenticationTag) <> 16)) OR
       (@contentSuite = 2 AND (DATALENGTH(@cipherText) NOT BETWEEN 16 AND @maximumContentBytes + 16 OR
           DATALENGTH(@cipherText) % 16 <> 0 OR DATALENGTH(@cipherVector) <> 16 OR
           @authenticationTag IS NOT NULL)) OR
       DATALENGTH(@protectionDescriptor) > 32000 OR DATALENGTH(@protectedKey) > 2225184 OR
       (@signature IS NOT NULL AND DATALENGTH(@signature) <> 32) OR
       (SELECT COUNT(*) FROM @recipients) > 100 OR EXISTS (
           SELECT 1 FROM @recipients WHERE [CipherParams] <> @cipherParams OR
               DATALENGTH([CipherKey]) NOT BETWEEN 8 AND 4096 OR DATALENGTH([Signature]) <> 32)
        THROW 50026, 'The encrypted item format or size is invalid.', 1;
    -- Accept only access paths used by the selected protection format.
    IF (@cipherParams = 2 AND (@protectionDescriptor IS NULL OR @protectedKey IS NULL OR
            DATALENGTH(@protectedKey) NOT BETWEEN 1 AND 1048576 OR @signature IS NULL OR
            EXISTS (SELECT 1 FROM @recipients))) OR
       (@cipherParams = 3 AND (@protectionDescriptor IS NOT NULL OR @protectedKey IS NOT NULL OR
            @signature IS NOT NULL OR NOT EXISTS (SELECT 1 FROM @recipients))) OR
       (@cipherParams = 4 AND (@signature IS NULL OR
            [dbo].[HasRecoveryDescriptor](@protectedKey, @protectionDescriptor, NULL) = 0))
        THROW 50026, 'The encrypted item format or size is invalid.', 1;
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
        IF @escrowUserId IS NOT NULL AND (@cipherParams NOT IN (3, 4) OR NOT EXISTS (
            SELECT 1 FROM @recipients WHERE [UserId] = @escrowUserId))
            THROW 50023, 'Include the Vault escrow certificate in the saved recipients.', 1;
        IF @escrowDescriptor IS NOT NULL AND (@cipherParams <> 4 OR
            [dbo].[HasRecoveryDescriptor](@protectedKey, @protectionDescriptor, @escrowDescriptor) = 0)
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
