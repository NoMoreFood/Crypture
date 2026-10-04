CREATE TABLE [Cipher] (
	[ItemId] integer  PRIMARY KEY NOT NULL,
	[CipherText] blob  NOT NULL,
	[CipherVector] blob  NOT NULL,
	[CipherParams] integer DEFAULT '0' NOT NULL,
	[ContentSuite] integer NULL,
	[AuthenticationTag] blob NULL,
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
	[ModifiedDate] datetime DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	[ModifiedBy] integer NULL,
	[ModifiedByIdentity] nvarchar NULL,
	[CreatedDate] datetime DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
,
    FOREIGN KEY ([ModifiedBy])
        REFERENCES [User]([UserId]) ON DELETE SET NULL
);

CREATE TABLE [User] (
	[UserId]	integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	[Certificate]	blob UNIQUE NOT NULL,
	[Sid]	nvarchar COLLATE NOCASE
);

CREATE UNIQUE INDEX [UX_Instance_Item_User] ON [Instance] ([ItemId], [UserId]);
CREATE INDEX [IX_Instance_User] ON [Instance] ([UserId]);
CREATE INDEX [IX_Item_ModifiedBy] ON [Item] ([ModifiedBy]);
