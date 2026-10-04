CREATE TABLE [dbo].[CryptureVault] (
    [Id] int NOT NULL CONSTRAINT [PK_CryptureVault] PRIMARY KEY CHECK ([Id] = 1),
    [SchemaVersion] int NOT NULL,
    [EscrowCertificateUserId] bigint NULL,
    [EscrowDescriptor] nvarchar(450) NULL,
    [EscrowLabel] nvarchar(450) NULL,
    CONSTRAINT [CK_CryptureVault_Escrow] CHECK (
        ([EscrowCertificateUserId] IS NULL AND [EscrowDescriptor] IS NULL AND [EscrowLabel] IS NULL) OR
        ([EscrowCertificateUserId] IS NOT NULL AND [EscrowDescriptor] IS NULL AND [EscrowLabel] IS NOT NULL) OR
        ([EscrowCertificateUserId] IS NULL AND [EscrowDescriptor] IS NOT NULL AND [EscrowLabel] IS NOT NULL))
);
INSERT INTO [dbo].[CryptureVault] ([Id], [SchemaVersion]) VALUES (1, 8);

CREATE TABLE [dbo].[User] (
    [UserId] bigint IDENTITY(1,1) NOT NULL CONSTRAINT [PK_User] PRIMARY KEY,
    [Certificate] varbinary(max) NOT NULL,
    [CertificateHash] AS CONVERT(binary(32), HASHBYTES('SHA2_256', [Certificate])) PERSISTED,
    [Sid] nvarchar(450) NOT NULL,
    CONSTRAINT [CK_User_Certificate] CHECK (DATALENGTH([Certificate]) BETWEEN 1 AND 16384),
    CONSTRAINT [CK_User_Sid] CHECK (DATALENGTH([Sid]) > 0)
);
CREATE UNIQUE INDEX [UX_User_CertificateHash] ON [dbo].[User] ([CertificateHash]);
ALTER TABLE [dbo].[CryptureVault] ADD CONSTRAINT [FK_CryptureVault_EscrowCertificate]
    FOREIGN KEY ([EscrowCertificateUserId]) REFERENCES [dbo].[User] ([UserId]);

CREATE TABLE [dbo].[Item] (
    [ItemId] bigint IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Item] PRIMARY KEY,
    [ItemType] nvarchar(450) NOT NULL CONSTRAINT [DF_Item_ItemType] DEFAULT N'text',
    [Label] nvarchar(max) NOT NULL,
    [ModifiedDate] datetime2(7) NOT NULL CONSTRAINT [DF_Item_ModifiedDate] DEFAULT SYSUTCDATETIME(),
    [ModifiedBy] bigint NULL,
    [ModifiedByIdentity] nvarchar(450) NULL,
    [CreatedDate] datetime2(7) NOT NULL CONSTRAINT [DF_Item_CreatedDate] DEFAULT SYSUTCDATETIME(),
    [RowVersion] rowversion NOT NULL,
    CONSTRAINT [CK_Item_Label] CHECK (DATALENGTH([Label]) BETWEEN 2 AND 32000),
    CONSTRAINT [FK_Item_User_ModifiedBy] FOREIGN KEY ([ModifiedBy]) REFERENCES [dbo].[User] ([UserId])
);
CREATE INDEX [IX_Item_ModifiedBy] ON [dbo].[Item] ([ModifiedBy]);

CREATE TABLE [dbo].[Cipher] (
    [ItemId] bigint NOT NULL CONSTRAINT [PK_Cipher] PRIMARY KEY,
    [CipherText] varbinary(max) NOT NULL,
    [CipherVector] varbinary(16) NOT NULL,
    [CipherParams] bigint NOT NULL,
    [ContentSuite] bigint NOT NULL,
    [AuthenticationTag] varbinary(16) NULL,
    [ProtectionDescriptor] nvarchar(max) NULL,
    [ProtectedKey] varbinary(max) NULL,
    [EscrowLabel] nvarchar(450) NULL,
    [Signature] varbinary(32) NULL,
    CONSTRAINT [CK_Cipher_Format] CHECK ([CipherParams] IN (2, 3, 4) AND [ContentSuite] IN (1, 2)),
    CONSTRAINT [CK_Cipher_Content] CHECK (
        ([ContentSuite] = 1 AND DATALENGTH([CipherText]) <= 68157440 AND
            DATALENGTH([CipherVector]) = 12 AND [AuthenticationTag] IS NOT NULL AND
            DATALENGTH([AuthenticationTag]) = 16) OR
        ([ContentSuite] = 2 AND DATALENGTH([CipherText]) BETWEEN 16 AND 68157456 AND
            DATALENGTH([CipherText]) % 16 = 0 AND DATALENGTH([CipherVector]) = 16 AND
            [AuthenticationTag] IS NULL)),
    CONSTRAINT [CK_Cipher_Metadata] CHECK (
        ([ProtectionDescriptor] IS NULL OR DATALENGTH([ProtectionDescriptor]) BETWEEN 2 AND 32000) AND
        ([ProtectedKey] IS NULL OR DATALENGTH([ProtectedKey]) BETWEEN 1 AND 2225184) AND
        ([Signature] IS NULL OR DATALENGTH([Signature]) = 32)),
    CONSTRAINT [CK_Cipher_Access] CHECK (
        ([CipherParams] = 2 AND [ProtectionDescriptor] IS NOT NULL AND [ProtectedKey] IS NOT NULL AND
            DATALENGTH([ProtectedKey]) <= 1048576 AND [Signature] IS NOT NULL) OR
        ([CipherParams] = 3 AND [ProtectionDescriptor] IS NULL AND [ProtectedKey] IS NULL AND [Signature] IS NULL) OR
        ([CipherParams] = 4 AND [ProtectedKey] IS NOT NULL AND DATALENGTH([ProtectedKey]) >= 17 AND
            [Signature] IS NOT NULL)),
    CONSTRAINT [FK_Cipher_Item] FOREIGN KEY ([ItemId]) REFERENCES [dbo].[Item] ([ItemId]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[Instance] (
    [InstanceId] bigint IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Instance] PRIMARY KEY,
    [ItemId] bigint NOT NULL,
    [UserId] bigint NOT NULL,
    [CipherKey] varbinary(4096) NOT NULL,
    [CipherParams] bigint NOT NULL,
    [Signature] varbinary(32) NOT NULL,
    CONSTRAINT [CK_Instance_Format] CHECK ([CipherParams] IN (3, 4)),
    CONSTRAINT [CK_Instance_Key] CHECK (DATALENGTH([CipherKey]) BETWEEN 8 AND 4096),
    CONSTRAINT [CK_Instance_Signature] CHECK (DATALENGTH([Signature]) = 32),
    CONSTRAINT [FK_Instance_Item] FOREIGN KEY ([ItemId]) REFERENCES [dbo].[Item] ([ItemId]) ON DELETE CASCADE,
    CONSTRAINT [FK_Instance_User] FOREIGN KEY ([UserId]) REFERENCES [dbo].[User] ([UserId]) ON DELETE CASCADE
);
CREATE UNIQUE INDEX [UX_Instance_Item_User] ON [dbo].[Instance] ([ItemId], [UserId]);
CREATE INDEX [IX_Instance_User] ON [dbo].[Instance] ([UserId]);
