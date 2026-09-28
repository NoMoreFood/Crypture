# Crypture

Crypture stores passwords and other sensitive data in encrypted Vault files (`.cryptdb`) on Windows. Protect items
with Windows users and security groups (CNG DPAPI-NG), certificates, or local Windows protection.

## Getting Started

Requires Windows with **.NET Framework 4.8 or later**.

Install an MSI package, or extract **Crypture-2.0.0-portable.zip** and run `Crypture.exe`. Keep all extracted files,
including the `x86` and `x64` folders. The ZIP includes the signed executable and dependencies for both
architectures; no installer or 7-Zip utility is needed. Application preferences are stored in your Windows user
profile.

1. Choose **Home → New** and select a location for your Vault. The new-item dialog opens automatically.
2. Enter an **Item Label** and the content to protect, then select a protection mode below. Use **Add New Item**
   for additional items. Labels are visible without decryption, so keep secrets in the protected content.
3. Choose **Encrypt & Save**. To open an item, double-click it and choose **Decrypt & Load**. Certificate private
   keys may require a PIN or password.

Vaults can be copied or shared, but recipients still need the required Windows identity infrastructure or
certificate private key. Copying a Vault or the portable application does not transfer those keys.

## Windows Users and Groups (DPAPI-NG)

Choose **Windows Users and Groups (DPAPI-NG)** and a scope:

* **Domain Users and Groups** requires an Active Directory domain computer, key distribution, and suitable
  connectivity. Use **Browse...**, enter an account name or SID with **Add**, or choose **Add Me**. Users, security
  groups, computers, and service accounts are supported. SIDs determine access; unresolved names display as SIDs.
* **Saving Account's Local Windows Profile** (`LOCAL=user`) requires the original Windows profile and its protection
  keys. This is the default on standalone computers and for local logons.
* **All Users on This Computer** (`LOCAL=machine`) allows every user on the encrypting computer to decrypt if they
  can read the Vault. It cannot target selected local accounts or groups and does not grant access on another
  computer.

For domain recipients, choose **Allow Any Listed Principal (OR)** for sharing or **Require All Listed Principals
(AND)** to require every listed identity. Include yourself or a recovery group if you need access later. Domain
logons on domain computers default to domain scope; standalone computers disable it. Selecting a local SID or
Everyone does not enable domain sharing, and domain scope cannot target local accounts or groups. Crypture never
changes protection scope automatically when encryption fails.

Use certificates to share with selected users without Active Directory. See Microsoft's [DPAPI-NG
overview](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi) and [local protection
scopes](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi-constants).

## Certificate Protection

Add public certificates using **Certificates → Store** or the certificate import workflow. Choose **Certificates
(RSA, ECC, ML-KEM)** in the item editor and select recipients with **Share With...**. Certificates with a matching
local private key are selected for new items. Each selected certificate can independently decrypt the item.

Supported algorithms:

* **RSA:** at least 2048 bits; requires Key Encipherment when key usage is specified.
* **ECC / ECDH:** P-256, P-384, or P-521; requires Key Agreement when key usage is specified. The private key must
  support ECDH; ECDSA signing-only keys cannot decrypt. Choose **ECDH** in the certificate wizard.
* **ML-KEM:** 512, 768, or 1024; requires compatible Windows CNG support and Key Encipherment when key usage is
  specified. Availability is checked at runtime. Import an issued X.509 certificate; recipients need its CNG private
  key in their Windows Personal store. The wizard does not issue ML-KEM certificates, so use compatible PKI/provider
  tooling.

For post-quantum confidentiality, **all recipients**, including automatic/recovery certificates, must use ML-KEM.
Adding RSA or ECC leaves a classical decryption path; mixing recipients is not hybrid encryption. Certificate
issuance and distribution also affect security. This support applies to certificate protection, not DPAPI-NG. See
Microsoft's [post-quantum cryptography
documentation](https://devblogs.microsoft.com/dotnet/post-quantum-cryptography-in-dotnet/).

The certificate wizard discovers providers in the background. Use **Refresh Providers** after changing a hardware
token or provider. Expired certificates can decrypt historical data but cannot be used for new encryption.

To change an existing item's protection, decrypt it, select the new mode and recipients, then save. This replaces
its keys and recipients but cannot revoke earlier Vault copies or exported plaintext. If
`AutomaticallyAddedCertificatesList` is configured, its certificates are required on every save and principal-only
protection is unavailable.

## Password Generator

Choose **Home → Passwords → Generate Password...**, even without an open Vault, or generate from an unlocked text
item. Configure minimum/maximum length (1–1024), uppercase/lowercase letters, digits, and punctuation. Set both
lengths equal for a fixed length. Options include custom symbols, excluded or similar characters, and requiring
every enabled type. Defaults are **20–24 characters**, all four types required, with similar characters excluded.

Passwords use the Windows-backed .NET cryptographic random number generator with unbiased length and character
sampling. Use **Copy** or **Insert Password**, then encrypt/save the item to store it. Options are remembered per
Vault; without an open Vault, changes last only for the current generator window.

## Appearance and Clipboard

Crypture follows the Windows app color setting by default. **View → Appearance → Theme** offers **Use Windows
Setting**, **Light**, and **Dark**; your choice is remembered per Windows account. Windows-owned dialogs retain
their system appearance.

Copying or cutting protected text or a generated password starts an automatic **five-minute clipboard timeout**.
Newer clipboard contents are left alone. Closing the editor or generator keeps the timer active; exiting Crypture
also attempts to clear its unchanged clipboard content. Clipboard history, managers, and already pasted copies are
unaffected.

## Vault Health Check

Choose **Advanced → Vault Tools → Health Check** to check saved recipient certificates, Windows principals, and
certificate owner identities. Certificates are checked for expiry (including a 30-day warning), encryption
suitability, and chain trust, using the **Allow Self-Signed** and **Do Revocation Check** settings. Unavailable or
skipped revocation checks are warnings.

Windows resolves local and well-known SIDs; domain SIDs are also checked directly in Active Directory. Unresolved or
disabled accounts are warnings; missing certificates and invalid protection policies are errors. Connectivity
failures remain unverified. Local profile/computer scopes are informational because they contain no individual
recipient SID.

The check does not decrypt items, change the Vault, test group membership, or prove every recipient can decrypt. Use
**Show Only Issues** to filter results and **Run Again** after restoring connectivity or changing validation
settings. Lookups run in the background and can be cancelled between requests.

## Working With Vaults

* **Ctrl+F** searches labels, modifier names, protection modes, SIDs, and certificates; **F5** refreshes the Vault.
* **Ctrl+S** encrypts and saves; **Lock Item (Ctrl+L)** clears decrypted editor content. Locking or closing prompts
  before discarding edits. Conflicting saves are rejected with your edits preserved.
* **Back Up...** creates a consistent encrypted Vault snapshot. Preserve certificate private keys and Windows
  recovery infrastructure separately: Vault backups do not include them. New Vaults and backups require unused
  filenames.
* **Hide Missing Certificate Keys** filters certificate items only; Windows access is checked when decrypting.
* A certificate cannot be removed if it is an item's last recipient. File uploads and expanded downloads are limited
  to 64 MB.

## Encryption and Privacy

New saves use **AES-256-CBC with HMAC-SHA256**, authenticating the label, item type, IV, and ciphertext before
decryption. Windows protection wraps both keys with DPAPI-NG and also authenticates the descriptor and protected key
blob. Certificate items use authenticated recipient envelopes: RSA-OAEP-SHA1 for provider compatibility, or
ECDH/ML-KEM with SP800-108 HMAC-SHA256 key derivation and AES-256-GCM key wrapping. Cryptographic operations use
Windows/.NET primitives.

Labels, timestamps, modifier identities, recipient certificates, and Windows protection descriptors remain visible.
Certificate access depends on the private key, not its account label. Older items remain readable and show a legacy
notice until saved again; newly authenticated items cannot be opened by older Crypture releases. Authentication does
not prevent deleting or replaying an entire Vault snapshot, so retain filesystem permissions and backups.

## Building and Packaging

For development, restore `Code\packages.config` into `Code\packages` and build `Code\Crypture.sln` with Visual
Studio/MSBuild. Required components are .NET desktop build tools, the **.NET Framework 4.8 targeting pack**, and
Windows certificate enrollment COM support. Package restore requires MSBuild 16.5 or later.

Run `Code\Build\Build.cmd` to restore dependencies, rebuild Release, and create **x86/x64 MSIs and a portable ZIP**
in `Binaries`. Packaging also requires a current .NET SDK, Windows SDK signing tools, internet access to NuGet and
the timestamp service, and a valid code-signing certificate with an accessible private key.

The script installs/updates a private copy of the latest stable WiX and matching extensions, uses the newest
installed Windows SDK SignTool, and selects an eligible certificate from the current user's Personal store (falling
back to the local machine's store when no candidate is present). It signs and timestamps the staged executable and
installers, verifies their signatures, and validates both MSIs before publishing. Failures stop packaging; unsigned
releases are not produced.

WiX 7 requires acceptance of its [EULA](https://docs.firegiant.com/wix/osmf/). After reviewing it, run
`Code\Build\.tools\wix.exe eula accept wix7`; the script does not accept it automatically.

Versions come from `Code\Properties\AssemblyInfo.cs`: Crypture 2.0 uses `2.0.0.0` for assemblies and `2.0.0` for
packages. Use `Major.Minor.Build.0` and keep assembly, manifest, and publish versions aligned. Existing packages are
not overwritten; move or remove `Code\Build\PackageStage` before another run. Signing uses staged copies; the ZIP
contains the signed runtime payload, dependencies, and licenses, while the ZIP archive itself is unsigned.

### Validation

Build `Tests\Crypture.Tests.csproj` and run `Tests\bin\Debug\Crypture.Tests.exe`. The suite covers encryption,
tampering, protection conversion, Vault recovery, password policies, clipboard expiration, and WPF controls using
temporary Vaults/keys.

* Set `CRYPTURE_TEST_DOMAIN_SIDS` to semicolon-separated SIDs or account names granting the test account access to
  enable domain authorization tests. These require a domain-connected machine with AD key distribution; otherwise
  they are skipped.
* Set `CRYPTURE_TEST_RENDER_DIR` to an output directory for UI renders.
* ML-KEM round trips use the real Windows provider and are skipped when unsupported.
