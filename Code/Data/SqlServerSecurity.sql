-- SQL Server uses the Vault's saved recipient SIDs and Windows protection descriptor for access.
CREATE TYPE [dbo].[EncryptedRecipient] AS TABLE (
    [UserId] bigint NOT NULL PRIMARY KEY,
    [CipherKey] varbinary(max) NOT NULL,
    [CipherParams] bigint NOT NULL,
    [Signature] varbinary(max) NOT NULL
);
GO
CREATE USER [crypture_writer] WITHOUT LOGIN;
GO
CREATE FUNCTION [dbo].[SidBytes](@sid nvarchar(450))
RETURNS varbinary(85) WITH SCHEMABINDING
AS
BEGIN
    IF @sid IS NULL OR LEN(@sid) > 184 OR LEFT(@sid, 2) <> N'S-' OR RIGHT(@sid, 1) = N'-'
        RETURN NULL;
    DECLARE @start int = 3, @next int = CHARINDEX(N'-', @sid, 3);
    IF @next = 0 RETURN NULL;
    DECLARE @revision bigint = TRY_CONVERT(bigint, SUBSTRING(@sid, @start, @next - @start));
    SET @start = @next + 1;
    SET @next = CHARINDEX(N'-', @sid, @start);
    IF @next = 0 RETURN NULL;
    DECLARE @authority bigint = TRY_CONVERT(bigint, SUBSTRING(@sid, @start, @next - @start));
    IF @revision IS NULL OR @next - @start < 1 OR @revision NOT BETWEEN 0 AND 255 OR
       @authority IS NULL OR @authority NOT BETWEEN 0 AND 281474976710655 RETURN NULL;
    DECLARE @result varbinary(85) = CONVERT(binary(1), @revision) + 0x00 +
        SUBSTRING(CONVERT(binary(8), @authority), 3, 6);
    DECLARE @count int = 0, @part nvarchar(20), @number bigint;
    SET @start = @next + 1;
    WHILE @start <= LEN(@sid)
    BEGIN
        SET @next = CHARINDEX(N'-', @sid, @start);
        IF @next = 0 SET @next = LEN(@sid) + 1;
        SET @part = SUBSTRING(@sid, @start, @next - @start);
        SET @number = TRY_CONVERT(bigint, @part);
        IF @part = N'' OR @number IS NULL OR @number NOT BETWEEN 0 AND 4294967295 RETURN NULL;
        SET @result = @result + CONVERT(binary(1), @number % 256) +
            CONVERT(binary(1), (@number / 256) % 256) +
            CONVERT(binary(1), (@number / 65536) % 256) +
            CONVERT(binary(1), (@number / 16777216) % 256);
        SET @count = @count + 1;
        IF @count > 15 RETURN NULL;
        SET @start = @next + 1;
    END;
    IF @count = 0 RETURN NULL;
    RETURN SUBSTRING(@result, 1, 1) + CONVERT(binary(1), @count) +
        SUBSTRING(@result, 3, DATALENGTH(@result) - 2);
END;
GO
CREATE FUNCTION [dbo].[MatchesPrincipal](@sid nvarchar(450))
RETURNS bit WITH SCHEMABINDING
AS
BEGIN
    DECLARE @binarySid varbinary(85) = [dbo].[SidBytes](@sid);
    IF @binarySid IS NULL RETURN 0;
    IF @binarySid = SUSER_SID(ORIGINAL_LOGIN()) RETURN 1;
    IF IS_MEMBER(SUSER_SNAME(@binarySid)) = 1 RETURN 1;
    RETURN 0;
END;
GO
CREATE FUNCTION [dbo].[MatchesDescriptor](@descriptor nvarchar(max))
RETURNS bit WITH SCHEMABINDING
AS
BEGIN
    IF @descriptor IS NULL OR LEFT(@descriptor, 4) <> N'SID=' OR LEN(@descriptor) > 16000 OR
       RIGHT(@descriptor, 1) = N' ' RETURN 0;
    DECLARE @all bit = CASE WHEN CHARINDEX(N' AND ', @descriptor) > 0 THEN 1 ELSE 0 END;
    IF @all = 1 AND CHARINDEX(N' OR ', @descriptor) > 0 RETURN 0;
    DECLARE @separator nvarchar(5) = CASE WHEN @all = 1 THEN N' AND ' ELSE N' OR ' END;
    DECLARE @start int = 1, @next int, @entry nvarchar(450), @matches bit, @anyMatch bit = 0;
    WHILE @start <= LEN(@descriptor)
    BEGIN
        SET @next = CHARINDEX(@separator, @descriptor, @start);
        IF @next = 0 SET @next = LEN(@descriptor) + 1;
        SET @entry = SUBSTRING(@descriptor, @start, @next - @start);
        IF LEFT(@entry, 4) <> N'SID=' OR LEN(@entry) > 188 RETURN 0;
        SET @matches = [dbo].[MatchesPrincipal](SUBSTRING(@entry, 5, 450));
        IF @all = 1 AND @matches = 0 RETURN 0;
        IF @all = 0 AND @matches = 1 SET @anyMatch = 1;
        SET @start = @next + DATALENGTH(@separator) / 2;
    END;
    RETURN CASE WHEN @all = 1 OR @anyMatch = 1 THEN 1 ELSE 0 END;
END;
GO
CREATE FUNCTION [dbo].[ReadEnvelopeInt32](@envelope varbinary(max), @position int)
RETURNS int WITH SCHEMABINDING
AS
BEGIN
    IF @position < 1 OR @position + 3 > DATALENGTH(@envelope) RETURN NULL;
    DECLARE @value bigint = CONVERT(bigint, SUBSTRING(@envelope, @position, 1)) +
        CONVERT(bigint, SUBSTRING(@envelope, @position + 1, 1)) * 256 +
        CONVERT(bigint, SUBSTRING(@envelope, @position + 2, 1)) * 65536 +
        CONVERT(bigint, SUBSTRING(@envelope, @position + 3, 1)) * 16777216;
    IF @value > 2147483647 RETURN NULL;
    RETURN CONVERT(int, @value);
END;
GO
CREATE FUNCTION [dbo].[MatchesRecoveryEnvelope](@envelope varbinary(max), @primary nvarchar(max))
RETURNS bit WITH SCHEMABINDING
AS
BEGIN
    -- The recovery key envelope stores one or two UTF-8 descriptors before their protected keys.
    DECLARE @length int = DATALENGTH(@envelope), @maximumEnvelopeBytes int = 2225184,
        @maximumDescriptorBytes int = 64000, @maximumKeyBytes int = 1048576;
    IF @length IS NULL OR @length < 17 OR @length > @maximumEnvelopeBytes OR
       [dbo].[ReadEnvelopeInt32](@envelope, 1) <> 1 RETURN 0;
    DECLARE @count int = [dbo].[ReadEnvelopeInt32](@envelope, 5);
    IF @count NOT BETWEEN 1 AND 2 RETURN 0;
    DECLARE @position int = 9, @index int = 0, @descriptorLength int, @keyLength int,
        @descriptor nvarchar(max), @allowed bit = 0;
    WHILE @index < @count
    BEGIN
        SET @descriptorLength = [dbo].[ReadEnvelopeInt32](@envelope, @position);
        SET @position = @position + 4;
        IF @descriptorLength IS NULL OR @descriptorLength < 1 OR
           @descriptorLength > @maximumDescriptorBytes OR
           @position + @descriptorLength - 1 > @length RETURN 0;
        SET @descriptor = CONVERT(nvarchar(max),
            CONVERT(varchar(max), SUBSTRING(@envelope, @position, @descriptorLength)));
        IF @index = 0 AND @primary IS NOT NULL AND @descriptor <> @primary RETURN 0;
        IF [dbo].[MatchesDescriptor](@descriptor) = 1 SET @allowed = 1;
        SET @position = @position + @descriptorLength;
        SET @keyLength = [dbo].[ReadEnvelopeInt32](@envelope, @position);
        SET @position = @position + 4;
        IF @keyLength IS NULL OR @keyLength < 1 OR @keyLength > @maximumKeyBytes OR
           @position + @keyLength - 1 > @length RETURN 0;
        SET @position = @position + @keyLength;
        SET @index = @index + 1;
    END;
    IF @position <> @length + 1 RETURN 0;
    RETURN @allowed;
END;
GO
CREATE FUNCTION [dbo].[CanReadItem](@itemId bigint)
RETURNS TABLE WITH SCHEMABINDING
AS RETURN
    SELECT 1 AS [Allowed]
    WHERE USER_NAME() = N'crypture_writer' OR EXISTS (
        SELECT 1 FROM [dbo].[Instance] AS r
        INNER JOIN [dbo].[User] AS u ON u.[UserId] = r.[UserId]
        WHERE r.[ItemId] = @itemId AND [dbo].[MatchesPrincipal](u.[Sid]) = 1
    ) OR EXISTS (
        SELECT 1 FROM [dbo].[Cipher] AS c
        WHERE c.[ItemId] = @itemId AND
            ([dbo].[MatchesDescriptor](c.[ProtectionDescriptor]) = 1 OR
             [dbo].[MatchesRecoveryEnvelope](c.[ProtectedKey], c.[ProtectionDescriptor]) = 1)
    );
GO
-- Users cannot write the protected tables directly; the mutation procedures check affiliation first.
CREATE SECURITY POLICY [dbo].[VaultRecipientPolicy]
ADD FILTER PREDICATE [dbo].[CanReadItem]([ItemId]) ON [dbo].[Item]
WITH (STATE = ON, SCHEMABINDING = ON);
GO
CREATE VIEW [dbo].[AuthorizedCipher]
AS SELECT c.* FROM [dbo].[Cipher] AS c
CROSS APPLY [dbo].[CanReadItem](c.[ItemId]) AS a;
GO
CREATE VIEW [dbo].[AuthorizedInstance]
AS SELECT r.* FROM [dbo].[Instance] AS r
CROSS APPLY [dbo].[CanReadItem](r.[ItemId]) AS a;
GO
CREATE PROCEDURE [dbo].[DeleteItemCore] @itemId bigint
WITH EXECUTE AS 'crypture_writer'
AS
BEGIN
    SET NOCOUNT ON;
    DELETE FROM [dbo].[Item] WHERE [ItemId] = @itemId;
END;
GO
CREATE PROCEDURE [dbo].[DeleteItem] @itemId bigint
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
    BEGIN TRY
        BEGIN TRANSACTION;
        IF NOT EXISTS (SELECT 1 FROM [dbo].[CanReadItem](@itemId))
            THROW 50011, 'You are not a recipient of this item.', 1;
        EXEC [dbo].[DeleteItemCore] @itemId;
        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO
CREATE PROCEDURE [dbo].[RemoveCertificateCore] @userId bigint
WITH EXECUTE AS 'crypture_writer'
AS
BEGIN
    SET NOCOUNT ON;
    DELETE FROM [dbo].[User] WHERE [UserId] = @userId;
END;
GO
CREATE PROCEDURE [dbo].[RemoveCertificate] @userId bigint
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
CREATE ROLE [crypture_domain];
GRANT SELECT, INSERT, UPDATE, DELETE ON [dbo].[Item] TO [crypture_writer];
GRANT SELECT, INSERT, UPDATE, DELETE ON [dbo].[Cipher] TO [crypture_writer];
GRANT SELECT, INSERT, UPDATE, DELETE ON [dbo].[Instance] TO [crypture_writer];
GRANT SELECT, DELETE ON [dbo].[User] TO [crypture_writer];
GRANT SELECT ON [dbo].[CryptureVault] TO [crypture_domain];
GRANT SELECT ON [dbo].[Item] TO [crypture_domain];
GRANT SELECT ON [dbo].[AuthorizedCipher] TO [crypture_domain];
GRANT SELECT ON [dbo].[AuthorizedInstance] TO [crypture_domain];
GRANT SELECT ON [dbo].[User] TO [crypture_domain];
GRANT EXECUTE, REFERENCES ON TYPE::[dbo].[EncryptedRecipient] TO [crypture_domain];
GRANT EXECUTE ON [dbo].[DeleteItem] TO [crypture_domain];
GRANT EXECUTE ON [dbo].[RemoveCertificate] TO [crypture_domain];
