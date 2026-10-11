# Crypture

Crypture stores passwords and other sensitive data in encrypted file Vaults (`.cryptdb`) or SQL Server Vaults on Windows. Protect items with Windows users and security groups (CNG DPAPI-NG), certificates, or FIDO2 security keys.

## Getting Started

Install the MSI matching your Windows architecture, or extract the portable ZIP and run `Crypture.exe` from its **x64** or **arm64** folder. Both distributions include the required .NET runtime and dependencies. Application preferences are stored in your Windows user profile.

1. Choose **Home → New** and select a location for your Vault. The new-item dialog opens automatically.
2. Enter an **Item Label** and the content to protect, then select a protection mode below. Use **Add New Item** for additional items. Labels are visible without decryption, so keep secrets in the protected content.
3. Choose **Encrypt & Save**. To open an item, double-click it and choose **Unlock**. Certificate private keys may require a PIN or password. FIDO2 keys require user verification and the Windows security-key prompts.

Vaults can be copied or shared, but recipients still need the required Windows identity infrastructure, certificate private key, or FIDO2 security key. Copying a Vault or the application does not transfer those keys.

## SQL Server Vaults

Choose **Home → SQL Server...**, enter the server and database, then choose **Connect**. Connections use your signed-in Windows account and require encryption. Leave **Trust the server certificate** unchecked unless you have verified the server by another means.

To create a Vault, select **Create a new database** and choose an emergency recovery certificate or Windows user/group from Active Directory. The database name must be unused, and your SQL Server account needs permission to create the database and provision access. Crypture grants the domain's Domain Users group its restricted Vault role. SQL Server limits access to encrypted item content using saved Windows recipients and certificate affiliations; decryption still requires the corresponding Windows identity or private key.

Use domain Windows recipients or certificates to protect items. Local Windows scopes and FIDO2 protection are unavailable. Enrolling your own certificate requires proof that you can use its private key. Enrolling another user's certificate requires a verified Active Directory association and Vault owner permission. The Vault owner can select an AD-published certificate and choose **Designate Escrow** to change emergency recovery. Recovery changes apply when items are saved; existing items retain their saved recovery until then.

**Back Up...** is available when your account has SQL Server backup permission. Enter a path on the server or a filename in its default backup folder; the SQL Server service account needs write access there. Restore these backups using SQL Server administration tools.

## Windows Users and Groups (DPAPI-NG)

Choose **User Based** in the item editor and a scope:

* **Domain Users and Groups** requires an Active Directory domain computer, key distribution, and suitable connectivity. Use **Browse...**, enter an account name or SID with **Add**, or choose **Add Me**. Users, security groups, computers, and service accounts are supported. SIDs determine access; unresolved names display as SIDs.
* **Saving Account's Local Windows Profile** (`LOCAL=user`) requires the original Windows profile and its protection keys. This is the default on standalone computers and for local logons.
* **All Users on This Computer** (`LOCAL=machine`) allows every user on the encrypting computer to decrypt if they can read the Vault. It cannot target selected local accounts or groups and does not grant access on another computer.

For domain recipients, choose **Allow Any Listed User or Group** for sharing or **Require All Listed Users and Groups** to require every listed identity. Include yourself or a recovery group if you need access later. Domain logons on domain computers default to domain scope; standalone computers hide it. Selecting a local SID or Everyone does not enable domain sharing, and domain scope cannot target local accounts or groups. Crypture never changes protection scope automatically when encryption fails.

Use certificates to share with selected users without Active Directory. See Microsoft's [DPAPI-NG overview](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi) and [local protection scopes](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-constants).

## Certificate Protection

Add public certificates using **Certificates → Store** or the certificate import workflow. Choose **Certificate Based** in the item editor and select recipients with **Choose Recipients...**. Certificates with a matching local private key are selected for new items. Crypture searches both the current user's and the computer's Personal certificate stores; the Windows account must have permission to use the private key. Each selected certificate can independently decrypt the item.

Supported algorithms:

* **RSA:** at least 2048 bits; requires Key Encipherment when key usage is specified.
* **ECC / ECDH:** P-256, P-384, or P-521; requires Key Agreement when key usage is specified. The private key must support ECDH; ECDSA signing-only keys cannot decrypt. Choose **ECDH** in the certificate wizard.
* **ML-KEM:** 512, 768, or 1024; requires compatible Windows CNG support and Key Encipherment when key usage is specified. Availability is checked at runtime. Import an issued X.509 certificate; recipients need its CNG private key in their Windows Personal store. The wizard does not issue ML-KEM certificates, so use compatible PKI/provider tooling.

For post-quantum confidentiality, **all recipients**, including automatic/recovery certificates, must use ML-KEM. Adding RSA or ECC leaves a classical decryption path; mixing recipients is not hybrid encryption. Certificate issuance and distribution also affect security. This support applies to certificate protection, not DPAPI-NG. See Microsoft's [post-quantum cryptography documentation](https://devblogs.microsoft.com/dotnet/post-quantum-cryptography-in-dotnet/).

The certificate wizard discovers providers in the background. Use **Refresh Providers** after changing a hardware token or provider. Expired certificates can decrypt historical data but cannot be used for new encryption. Visibility settings for expired or untrusted certificates affect selection only; saving still requires certificates to pass encryption validation.

To change an existing item's protection, decrypt it, select the new mode and recipients, then save. This replaces its keys and recipients but cannot revoke earlier Vault copies or exported plaintext. If `AutomaticallyAddedCertificatesList` is configured, its certificates are required on every save and principal-only protection is unavailable.

## FIDO2 Security Key Protection

Choose **FIDO2 Security Key** in the item editor for a file Vault, then choose **Encrypt & Save**. Windows creates a credential on the first save and handles the key's PIN or biometric verification and touch prompts. Saving or decrypting an item requires the security key that protected it. **Use Another Key** becomes available after unlocking an item; the replacement is set up when you save.

This method requires a FIDO2 authenticator supporting `hmac-secret` and user verification, plus a Windows session whose WebAuthn API supports retrieving that secret. FIDO U2F-only keys cannot encrypt items this way. The encryption option is hidden for new items when Windows support is unavailable or `EnableFidoProtection` is disabled in `Crypture.exe.config`. Saved FIDO2 items retain their protection details and recovery actions. SQL Server Vaults require Windows or certificate recipients and do not offer FIDO2 protection.

A copied file Vault can use the same security key on another compatible Windows computer. A Vault backup contains the credential identifier and encrypted keys, but cannot replace a lost or reset security key. Preserve the original key for earlier copies when changing an item's key.

Configured Windows and certificate recovery recipients are added independently on every save. Mandatory certificates from `AutomaticallyAddedCertificatesList` also receive independent access. For a locked FIDO2 item with saved recovery access, choose **Use Recovery** to decrypt without contacting the security key. Saved recovery remains available when FIDO2 support or new FIDO2 saves are disabled. Without recovery access, losing the key or resetting its FIDO credentials prevents decryption.

FIDO2 protection derives a wrapping key from the authenticator's `hmac-secret` output and encrypts the item's content keys with AES-256-GCM. The content still uses the configured AES suite. The Vault stores the public credential identifier, random salt, and authenticated key envelope; it does not store the authenticator's secret output. See Microsoft's [Windows WebAuthn API documentation](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis).

## Password Generator

Choose **Home → Passwords → Generate Password...**, even without an open Vault, or generate from an unlocked text item. Configure minimum/maximum length (1–1024), uppercase/lowercase letters, digits, and punctuation. Set both lengths equal for a fixed length. Options include custom symbols, excluded or similar characters, and requiring every enabled type. Defaults are **20–24 characters**, all four types required, with similar characters excluded.

Passwords use the Windows-backed .NET cryptographic random number generator with unbiased length and character sampling. Use **Copy** or **Insert Password**, then encrypt/save the item to store it. Choosing **Generate** remembers the options for your Windows account, across Vaults and when no Vault is open.

## Authenticator Codes (TOTP)

Choose **TOTP Authenticator** as an item's type. Under **Authenticator Setup**, import the service's `otpauth://totp/` setup link or Base32 secret. **Import QR Image...** reads a setup QR code from an image file; **Paste QR Image** reads one from a clipboard image or screenshot. Use an image containing one authenticator setup code.

Confirm the issuer, account, algorithm, digits, and rotation period, then choose **Encrypt & Save**. Unlock the item to see the current code and copy it with the copy button. Codes use the Windows clock, so keep it synchronized with the service. SHA-1, SHA-256, and SHA-512 are supported, with six or eight digits and a period from 1 to 3600 seconds; the defaults are SHA-1, six digits, and 30 seconds. Counter-based HOTP setup links are not supported.

Use the service's settings for an existing account. **Generate New Secret** creates a seed that must be registered with the service before its codes will work. The secret, setup information, and account are encrypted with the item; copying them uses the protected clipboard timeout.

## Appearance and Clipboard

Crypture follows the Windows app color setting by default. **View → Appearance → Theme** offers **Use Windows Setting**, **Light**, and **Dark**; your choice is remembered per Windows account. Windows-owned dialogs retain their system appearance.

Copying or cutting protected text or a generated password starts a clipboard timeout configured by `ClipboardTimeoutSeconds` (five minutes by default). Crypture marks these copies to exclude them from Windows clipboard history and cloud sync. It leaves newer clipboard contents alone, keeps the timer active if the editor or generator closes, and attempts to clear its unchanged copy when Crypture exits. Other clipboard managers and already pasted copies may retain the text.

Windows session lock or disconnect conceals open secrets. Crypture also conceals them after `AutoConcealIdleMinutes` of inactivity in the app (ten minutes by default; set it to `0` to disable idle concealment). Saved items with no unsaved changes are locked and cleared. Unsaved edits and generated passwords stay in memory behind a disabled, opaque view until you choose **Reveal**; closing an editor still prompts before discarding unsaved edits.

## Vault Health Check

Choose **Advanced → Vault Tools → Health Check** to check saved recipient certificates, Windows principals, and certificate owner identities. Certificates are checked for expiry (including a 30-day warning), encryption suitability, and chain trust, using the **Allow Self-Signed** and **Do Revocation Check** settings. Unavailable or skipped revocation checks are warnings.

Windows resolves local and well-known SIDs; domain SIDs are also checked directly in Active Directory. Unresolved or disabled accounts are warnings; missing certificates and invalid protection policies are errors. Connectivity failures remain unverified. Local profile/computer scopes are informational because they contain no individual recipient SID.

The check does not decrypt items, change the Vault, contact FIDO2 security keys, test group membership, or prove every recipient can decrypt. Use **Show Only Issues** to filter results and **Run Again** after restoring connectivity or changing validation settings. Lookups run in the background and can be cancelled between requests.

## Working With Vaults

* **Ctrl+F** searches labels, modifier names, protection modes, SIDs, and certificates; **F5** refreshes the Vault.
* **Ctrl+S** encrypts and saves; **Lock Item (Ctrl+L)** clears decrypted editor content. Locking or closing prompts before discarding edits. Conflicting saves are rejected with your edits preserved.
* **Back Up...** creates a consistent encrypted Vault snapshot. Preserve certificate private keys, FIDO2 security keys, and Windows recovery infrastructure separately: Vault backups do not replace them. New file Vaults and file Vault backups require unused filenames.
* **Hide Missing Certificate Keys** filters certificate items only; Windows and FIDO2 access are checked when decrypting.
* A certificate cannot be removed if it is a certificate item's last recipient or is configured for emergency recovery. Optional recovery certificates can be removed from items that retain primary Windows or FIDO2 access. File uploads and expanded downloads are limited to 64 MB.

### Keyboard Shortcuts

Shortcuts apply to the active view and enabled actions. FIDO2 key prompts are handled by Windows.

| Shortcut | Action |
| --- | --- |
| **Ctrl+F** | Focus the Vault browser's search field. |
| **F5** | Refresh the open Vault. |
| **Enter** | Open the selected item or certificate when its list has focus. |
| **Ctrl+S** | Encrypt and save an unlocked item. |
| **Ctrl+L** | Lock an unlocked saved item, prompting before discarding edits. |
| **Esc** | Cancel the active Vault loading, creation, refresh, item loading, or backup operation. |
| **Alt+K** | Choose another security key when **Use Another Key** is available in the FIDO2 editor. |
| **Alt+R** | Use saved recovery when **Use Recovery** is available for a locked FIDO2 item. |

## Encryption and Privacy

New saves use **AES-256-GCM** by default. Set `ContentEncryptionSuite` to `Aes256CbcHmacSha256` to use **AES-256-CBC with HMAC-SHA256** for new saves instead. Both suites authenticate the item's metadata and encrypted content before revealing plaintext. Each saved item records its suite, so changing the default does not change existing items until they are saved again. Windows protection wraps content keys with DPAPI-NG and authenticates the descriptor and protected key blob. Certificate items use authenticated recipient envelopes: RSA-OAEP-SHA1 for provider compatibility, or ECDH/ML-KEM with SP800-108 HMAC-SHA256 key derivation and AES-256-GCM key wrapping. Cryptographic operations use Windows/.NET primitives.

Labels, timestamps, modifier identities, recipient certificates, and Windows protection descriptors remain visible. Certificate access depends on the private key, not its account label. Only authenticated item formats are supported; legacy unauthenticated items cannot be decrypted. Authentication does not prevent deleting or replaying an entire Vault snapshot, so retain filesystem permissions and backups.

## Building and Packaging

Build on Windows with the **.NET SDK** required by `global.json`. From the repository root, run `dotnet build Code\Crypture.sln`; the SDK restores NuGet dependencies automatically. The project uses WPF and Windows certificate enrollment COM support.

Run `Build\Build.cmd` to restore dependencies and publish self-contained applications for **win-x64** and **win-arm64**. `Binaries` receives a portable ZIP with a single executable per architecture, an unpacked ZIP with the application files and dependencies, and an MSI installer for each architecture. To package a single architecture, pass `-RuntimeIdentifier win-x64`, `-RuntimeIdentifier win-arm64`, or `-RuntimeIdentifier win-x86`. The build restores WiX tooling and validates each MSI. License notices are available in **About**.

Signed packaging requires Windows SDK signing tools, internet access to NuGet and the timestamp service, and a trusted, valid code-signing certificate with an accessible private key. The script uses the newest installed SDK SignTool and selects a certificate from the current user's Personal store, falling back to the computer's store. It signs, timestamps, and verifies the application executables and MSI packages before publishing. Pass `-SkipSigning` to produce an unsigned build for local testing.

Package names use the version from `Code\Crypture.csproj`. Keep it aligned with `Code\Properties\AssemblyInfo.cs` and the application manifest. Each run uses a fresh subdirectory under `Build\PackageStage`; existing release packages are not overwritten. Move an existing package before building the same version again.

The portable executable uses built-in configuration defaults. To customize application settings or recovery, place a `Crypture.exe.config` beside it, using `Code\App.config` as the starting point. The MSI installs a configuration file and accepts settings as public properties named `CRYPTURE_` followed by the uppercase setting name, such as `CRYPTURE_CLIPBOARDTIMEOUTSECONDS=60`. These set the installed defaults; saved user preferences can override user-scoped settings.

### Validation

From the repository root, run `dotnet run --project Tests\Crypture.Tests.csproj`. The suite covers encryption, tampering, protection conversion, Vault recovery, concurrent Vault access, password policies, clipboard expiration, and WPF controls using temporary Vaults and keys. Computer-store private-key round trips require an elevated test process.

* Set `CRYPTURE_TEST_DOMAIN_SIDS` to semicolon-separated SIDs or account names granting the test account access to enable domain authorization tests. These require a domain-connected machine with AD key distribution; otherwise they are skipped.
* Set `CRYPTURE_TEST_SQLSERVER` to a Windows-authenticated connection string to enable SQL Server integration checks. The test account must be able to create and remove temporary databases.
* Set `CRYPTURE_TEST_FIDO_HARDWARE=1` to run interactive checks with a compatible physical security key.
* Set `CRYPTURE_TEST_RENDER_DIR` to an output directory for UI renders.
* ML-KEM round trips use the real Windows provider and are skipped when unsupported.
