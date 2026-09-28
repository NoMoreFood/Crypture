CREATE TABLE [Cipher] (
	[ItemId] integer  PRIMARY KEY NOT NULL,
	[CipherText] blob  NOT NULL,
	[CipherVector] blob  NOT NULL,
	[CipherParams] integer DEFAULT '0' NOT NULL,
	[ProtectionDescriptor] nvarchar NULL,
	[ProtectedKey] blob NULL,
	[Signature] blob NULL
,
    FOREIGN KEY ([ItemId])
        REFERENCES [Item]([ItemId]) ON DELETE CASCADE
);

CREATE TABLE [Instance] (
	[InstanceId]	integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	[ItemId]	integer NOT NULL,
	[UserId]	integer NOT NULL,
	[CipherKey]	blob NOT NULL,
	[CipherParams]	integer NOT NULL DEFAULT '0',
	[Signature]	blob NOT NULL
,
    FOREIGN KEY ([ItemId])
        REFERENCES [Item]([ItemId]) ON DELETE CASCADE,
    FOREIGN KEY ([UserId])
        REFERENCES [User]([UserId]) ON DELETE CASCADE
);

CREATE TABLE [Item] (
	[ItemId] integer  PRIMARY KEY AUTOINCREMENT NOT NULL,
	[ItemType]	nvarchar NOT NULL DEFAULT 'text',
	[Label] nvarchar  NOT NULL,
	[ModifiedDate] datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
	[ModifiedBy] integer NULL,
	[ModifiedByIdentity] nvarchar NULL,
	[CreatedDate] datetime DEFAULT CURRENT_TIMESTAMP NOT NULL
,
    FOREIGN KEY ([ModifiedBy])
        REFERENCES [User]([UserId]) ON DELETE SET NULL
);

CREATE TABLE [User] (
	[UserId]	integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	[Certificate]	blob UNIQUE NOT NULL,
	[Sid]	nvarchar COLLATE NOCASE
);

CREATE TABLE IF NOT EXISTS [PasswordGeneratorSettings] (
    [Id] integer PRIMARY KEY CHECK ([Id] = 1),
    [MinimumLength] integer NOT NULL CHECK ([MinimumLength] BETWEEN 1 AND 1024),
    [MaximumLength] integer NOT NULL CHECK ([MaximumLength] BETWEEN [MinimumLength] AND 1024),
    [IncludeUppercase] integer NOT NULL CHECK ([IncludeUppercase] IN (0, 1)),
    [IncludeLowercase] integer NOT NULL CHECK ([IncludeLowercase] IN (0, 1)),
    [IncludeDigits] integer NOT NULL CHECK ([IncludeDigits] IN (0, 1)),
    [IncludeSymbols] integer NOT NULL CHECK ([IncludeSymbols] IN (0, 1)),
    [SymbolCharacters] nvarchar NOT NULL,
    [ExcludedCharacters] nvarchar NOT NULL,
    [ExcludeSimilar] integer NOT NULL CHECK ([ExcludeSimilar] IN (0, 1)),
    [RequireEachType] integer NOT NULL CHECK ([RequireEachType] IN (0, 1))
);
