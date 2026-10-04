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
INSERT INTO [dbo].[CryptureVault] ([Id], [SchemaVersion]) VALUES (1, 4);

CREATE TABLE [dbo].[User] (
    [UserId] bigint IDENTITY(1,1) NOT NULL CONSTRAINT [PK_User] PRIMARY KEY,
    [Certificate] varbinary(max) NOT NULL,
    [CertificateHash] AS CONVERT(binary(32), HASHBYTES('SHA2_256', [Certificate])) PERSISTED,
    [Sid] nvarchar(450) NULL,
    [IsEscrow] bit NOT NULL CONSTRAINT [DF_User_IsEscrow] DEFAULT 0
);
CREATE UNIQUE INDEX [UX_User_CertificateHash] ON [dbo].[User] ([CertificateHash]);
ALTER TABLE [dbo].[CryptureVault] ADD CONSTRAINT [FK_CryptureVault_EscrowCertificate]
    FOREIGN KEY ([EscrowCertificateUserId]) REFERENCES [dbo].[User] ([UserId]);

CREATE TABLE [dbo].[Item] (
    [ItemId] bigint IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Item] PRIMARY KEY,
    [ItemType] nvarchar(max) NOT NULL CONSTRAINT [DF_Item_ItemType] DEFAULT N'text',
    [Label] nvarchar(max) NOT NULL,
    [ModifiedDate] datetime2(7) NOT NULL CONSTRAINT [DF_Item_ModifiedDate] DEFAULT SYSDATETIME(),
    [ModifiedBy] bigint NULL,
    [ModifiedByIdentity] nvarchar(max) NULL,
    [CreatedDate] datetime2(7) NOT NULL CONSTRAINT [DF_Item_CreatedDate] DEFAULT SYSDATETIME(),
    [RowVersion] rowversion NOT NULL,
    CONSTRAINT [FK_Item_User_ModifiedBy] FOREIGN KEY ([ModifiedBy]) REFERENCES [dbo].[User] ([UserId])
);
CREATE INDEX [IX_Item_ModifiedBy] ON [dbo].[Item] ([ModifiedBy]);

CREATE TABLE [dbo].[Cipher] (
    [ItemId] bigint NOT NULL CONSTRAINT [PK_Cipher] PRIMARY KEY,
    [CipherText] varbinary(max) NOT NULL,
    [CipherVector] varbinary(max) NOT NULL,
    [CipherParams] bigint NOT NULL CONSTRAINT [DF_Cipher_CipherParams] DEFAULT 0,
    [ContentSuite] bigint NULL,
    [AuthenticationTag] varbinary(max) NULL,
    [ProtectionDescriptor] nvarchar(max) NULL,
    [ProtectedKey] varbinary(max) NULL,
    [EscrowLabel] nvarchar(450) NULL,
    [Signature] varbinary(max) NULL,
    CONSTRAINT [FK_Cipher_Item] FOREIGN KEY ([ItemId]) REFERENCES [dbo].[Item] ([ItemId]) ON DELETE CASCADE
);

CREATE TABLE [dbo].[Instance] (
    [InstanceId] bigint IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Instance] PRIMARY KEY,
    [ItemId] bigint NOT NULL,
    [UserId] bigint NOT NULL,
    [CipherKey] varbinary(max) NOT NULL,
    [CipherParams] bigint NOT NULL CONSTRAINT [DF_Instance_CipherParams] DEFAULT 0,
    [Signature] varbinary(max) NOT NULL,
    CONSTRAINT [FK_Instance_Item] FOREIGN KEY ([ItemId]) REFERENCES [dbo].[Item] ([ItemId]) ON DELETE CASCADE,
    CONSTRAINT [FK_Instance_User] FOREIGN KEY ([UserId]) REFERENCES [dbo].[User] ([UserId]) ON DELETE CASCADE
);
CREATE UNIQUE INDEX [UX_Instance_Item_User] ON [dbo].[Instance] ([ItemId], [UserId]);
CREATE INDEX [IX_Instance_User] ON [dbo].[Instance] ([UserId]);

CREATE TABLE [dbo].[PasswordGeneratorSettings] (
    [Id] int NOT NULL CONSTRAINT [PK_PasswordGeneratorSettings] PRIMARY KEY CHECK ([Id] = 1),
    [MinimumLength] int NOT NULL CHECK ([MinimumLength] BETWEEN 1 AND 1024),
    [MaximumLength] int NOT NULL,
    [IncludeUppercase] bit NOT NULL,
    [IncludeLowercase] bit NOT NULL,
    [IncludeDigits] bit NOT NULL,
    [IncludeSymbols] bit NOT NULL,
    [SymbolCharacters] nvarchar(94) NOT NULL,
    [ExcludedCharacters] nvarchar(256) NOT NULL,
    [ExcludeSimilar] bit NOT NULL,
    [RequireEachType] bit NOT NULL,
    CONSTRAINT [CK_PasswordGeneratorSettings_Length] CHECK
        ([MinimumLength] BETWEEN 1 AND 1024 AND [MaximumLength] BETWEEN [MinimumLength] AND 1024)
);
