CREATE TABLE [Cipher] (
	[ItemId] integer  PRIMARY KEY NOT NULL,
	[CipherText] blob  NOT NULL,
	[CipherVector] blob  NOT NULL,
	[CipherParams] integer DEFAULT '0' NOT NULL
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
[Label] nvarchar  NOT NULL,
[ModifiedDate] datetime DEFAULT 'CURRENT_TIMESTAMP' NOT NULL,
[ModifiedBy] integer  NULL,
[CreatedDate] datetime DEFAULT 'CURRENT_TIMESTAMP' NOT NULL
);

CREATE TABLE [User] (
	[UserId]	integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	[Certificate]	blob UNIQUE NOT NULL,
	[Sid]	nvarchar COLLATE NOCASE
);
