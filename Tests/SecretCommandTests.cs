using Crypture;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

internal static partial class RegressionTests
{
    private static (int ExitCode, string Output, string Error) ReadSecret(params string[] args)
    {
        using StringWriter oOutput = new StringWriter();
        using StringWriter oError = new StringWriter();
        int nExitCode = SecretCommand.Run(["get-secret", .. args], oOutput, oError);
        return (nExitCode, oOutput.ToString(), oError.ToString());
    }

    private static void TestSecretCommand(string sDirectory)
    {
        // Exercise persistence and the actual Windows key store with an isolated, removable private key.
        string sPath = Path.Combine(sDirectory, "Script Vault.cryptdb");
        SqliteVaultStorage oStorage = new SqliteVaultStorage(sPath);
        oStorage.Create();
        string sKeyName = "Crypture.ScriptingTest-" + Guid.NewGuid().ToString("N");
        CngKeyCreationParameters oKeyOptions = new CngKeyCreationParameters();
        oKeyOptions.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));
        using CngKey oKey = CngKey.Create(CngAlgorithm.Rsa, sKeyName, oKeyOptions);
        using RSA oRsa = new RSACng(oKey);
        using X509Certificate2 oCert = Certificate(oRsa, "Scripting Test", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1));
        using X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        oStore.Open(OpenFlags.ReadWrite);
        oStore.Add(oCert);
        try
        {
            const string SecretValue = "  Password \"quotes\" \\ snowman \u2603 \U0001F511\r\nsecond line\r\n";
            byte[] oPlain = Encoding.Unicode.GetBytes(SecretValue);
            User oUser = new User { Certificate = oCert.RawData };
            Item oCertificateItem = new Item { Label = "Service Password", ItemType = "text" };
            Item oWindowsItem = new Item { Label = "Windows Password", ItemType = "text" };
            Item oEmptyItem = new Item { Label = "Empty Password", ItemType = "text" };
            Item oFile = new Item { Label = "Attachment", ItemType = ".txt" };
            Item oTotp = new Item { Label = "Authenticator", ItemType = "totp" };
            Item oRichText = new Item { Label = "Rich Text", ItemType = "richtext" };
            Item oInvalidText = new Item { Label = "Invalid Text", ItemType = "text" };
            Item oFidoOnly = new Item { Label = "FIDO2 Only", ItemType = "text" };
            Item oFidoWindows = new Item { Label = "FIDO2 Windows Recovery", ItemType = "text" };
            Item oFidoCertificate = new Item { Label = "FIDO2 Certificate Recovery", ItemType = "text" };
            using FidoKeyAccess oFido = new FidoKeyAccess(RandomNumberGenerator.GetBytes(64),
                RandomNumberGenerator.GetBytes(FidoKeyProtection.SaltBytes),
                RandomNumberGenerator.GetBytes(FidoKeyProtection.SecretBytes));
            using RSA oUnavailableKey = new RSACng(2048);
            using X509Certificate2 oUnavailableCert = Certificate(oUnavailableKey, "Unavailable Scripting Key",
                DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1));
            Item oDenied = new Item { Label = "Denied", ItemType = "text" };
            using (CryptureEntities oContent = new CryptureEntities(oStorage))
            {
                oContent.Users.Add(oUser);
                User oUnavailableUser = new User { Certificate = oUnavailableCert.RawData };
                oContent.Users.Add(oUnavailableUser);
                oContent.SaveChanges();
                ItemCryptography.Encrypt(oCertificateItem, oPlain, [oUser]);
                ItemCryptography.Encrypt(oWindowsItem, oPlain, null, PrincipalProtection.LocalUserDescriptor);
                ItemCryptography.Encrypt(oEmptyItem, [], [oUser]);
                ItemCryptography.Encrypt(oFile, oPlain, [oUser]);
                ItemCryptography.Encrypt(oTotp, oPlain, [oUser]);
                ItemCryptography.Encrypt(oRichText, oPlain, [oUser]);
                ItemCryptography.Encrypt(oInvalidText, [0x00, 0xD8], [oUser]);
                ItemCryptography.Encrypt(oFidoOnly, oPlain, null, oFidoKey: oFido);
                ItemCryptography.Encrypt(oFidoWindows, oPlain, null,
                    sRecoveryDescriptor: PrincipalProtection.LocalUserDescriptor, oFidoKey: oFido);
                ItemCryptography.Encrypt(oFidoCertificate, oPlain, [oUser], oFidoKey: oFido);
                ItemCryptography.Encrypt(oDenied, oPlain, [oUnavailableUser]);
                oContent.Items.AddRange(oCertificateItem, oWindowsItem, oEmptyItem, oFile, oTotp, oRichText, oDenied);
                oContent.Items.AddRange(oInvalidText, oFidoOnly, oFidoWindows, oFidoCertificate);
                oContent.SaveChanges();
            }

            // JSON must preserve whitespace, Unicode, quotes, and newlines exactly for script consumers.
            var oResult = ReadSecret("--vault", sPath, "--label", oCertificateItem.Label);
            using (JsonDocument oJson = JsonDocument.Parse(oResult.Output))
                Check(oResult.ExitCode == 0 && oResult.Error.Length == 0 &&
                    oJson.RootElement.GetProperty("Value").GetString() == SecretValue &&
                    oJson.RootElement.GetProperty("ItemId").GetInt64() == oCertificateItem.ItemId,
                    "Scripting retrieves a certificate-protected Text Secret as lossless JSON");
            oResult = ReadSecret("--vault", sPath, "--id", oWindowsItem.ItemId.ToString());
            using (JsonDocument oJson = JsonDocument.Parse(oResult.Output))
                Check(oResult.ExitCode == 0 && oJson.RootElement.GetProperty("Value").GetString() == SecretValue,
                    "Scripting retrieves a Windows-protected secret by ID");
            oResult = ReadSecret("--vault", sPath, "--label", oEmptyItem.Label,
                "--certificate", oCert.Thumbprint.ToLowerInvariant());
            using (JsonDocument oJson = JsonDocument.Parse(oResult.Output))
                Check(oResult.ExitCode == 0 && oJson.RootElement.GetProperty("Value").GetString() == "",
                    "Scripting preserves empty passwords and accepts an explicit certificate");
            foreach (Item oRecoveryItem in new[] { oFidoWindows, oFidoCertificate })
            {
                oResult = ReadSecret("--vault", sPath, "--id", oRecoveryItem.ItemId.ToString());
                using JsonDocument oJson = JsonDocument.Parse(oResult.Output);
                Check(oResult.ExitCode == 0 && oJson.RootElement.GetProperty("Value").GetString() == SecretValue,
                    "Scripting uses saved recovery access for " + oRecoveryItem.Label);
            }

            // Reading succeeds on a read-only file without changing it or the active desktop Vault.
            byte[] oBefore = SHA256.HashData(File.ReadAllBytes(sPath));
            IVaultStorage oCurrentStorage = CryptureEntities.Storage;
            FileAttributes oAttributes = File.GetAttributes(sPath);
            try
            {
                File.SetAttributes(sPath, oAttributes | FileAttributes.ReadOnly);
                oResult = ReadSecret("--vault", sPath, "--label", oCertificateItem.Label);
                Check(oResult.ExitCode == 0 && ReferenceEquals(oCurrentStorage, CryptureEntities.Storage) &&
                    SHA256.HashData(File.ReadAllBytes(sPath)).SequenceEqual(oBefore),
                    "Scripting reads without changing the Vault or desktop connection");
            }
            finally { File.SetAttributes(sPath, oAttributes); }

            foreach (string sLabel in new[] { "Missing", "service password", oDenied.Label,
                oFile.Label, oTotp.Label, oRichText.Label, oFidoOnly.Label, oInvalidText.Label })
            {
                oResult = ReadSecret("--vault", sPath, "--label", sLabel);
                Check(oResult.ExitCode == 1 && oResult.Output.Length == 0 && oResult.Error.Length > 0 &&
                    !oResult.Error.Contains(SecretValue), "Scripting fails without secret output for " + sLabel);
            }
            oResult = ReadSecret("--vault", sPath, "--label", oWindowsItem.Label,
                "--certificate", new string('0', 40));
            Check(oResult.ExitCode == 1 && oResult.Output.Length == 0,
                "An explicit certificate does not fall back to Windows access");
            string sMissing = Path.Combine(sDirectory, "Missing.cryptdb");
            oResult = ReadSecret("--vault", sMissing, "--id", "1");
            Check(oResult.ExitCode == 1 && oResult.Output.Length == 0 && !File.Exists(sMissing),
                "Scripting never creates a missing Vault");
            foreach (string[] oArguments in new[]
            {
                Array.Empty<string>(), new[] { "--vault", sPath }, new[] { "--vault" },
                new[] { "--vault", sPath, "--id", "-1" },
                new[] { "--vault", sPath, "--id", "1", "--id", "2" },
                new[] { "--vault", sPath, "--label", "x", "--id", "1" },
                new[] { "--vault", sPath, "--id", "1", "--certificate", "invalid" },
                new[] { "--connection-string", "Server=localhost;Database=Vault;User ID=someone;Password=x",
                    "--id", "1" }
            })
            {
                oResult = ReadSecret(oArguments);
                Check(oResult.ExitCode == 2 && oResult.Output.Length == 0 && oResult.Error.Length > 0,
                    "Scripting rejects invalid selectors and SQL authentication before retrieval");
            }

            // Exercise the production executable and PowerShell's native-process pipeline without a window.
            TestSecretProcess(sPath, oCertificateItem.Label, SecretValue);

            // Ambiguity and authenticated metadata corruption must fail before any plaintext is written.
            using (CryptureEntities oContent = new CryptureEntities(oStorage))
            {
                Item oDuplicate = new Item { Label = oCertificateItem.Label, ItemType = "text" };
                User oRecipient = oContent.Users.Single(u => u.UserId == oUser.UserId);
                ItemCryptography.Encrypt(oDuplicate, oPlain, [oRecipient]);
                oContent.Items.Add(oDuplicate);
                oContent.SaveChanges();
                oResult = ReadSecret("--vault", sPath, "--label", oCertificateItem.Label);
                Check(oResult.ExitCode == 1 && oResult.Output.Length == 0 && oResult.Error.Contains("--id"),
                    "Duplicate labels require an item ID");
                oResult = ReadSecret("--vault", sPath, "--id", oCertificateItem.ItemId.ToString());
                Check(oResult.ExitCode == 0, "ID selection resolves duplicate labels");
                Item oTampered = oContent.Items.Single(i => i.ItemId == oCertificateItem.ItemId);
                oTampered.Label = "Altered Label";
                oContent.SaveChanges();
                oResult = ReadSecret("--vault", sPath, "--id", oTampered.ItemId.ToString());
                Check(oResult.ExitCode == 1 && oResult.Output.Length == 0,
                    "Scripting authenticates metadata before returning a password");
            }
            TestSilentCertificateAccess(oCert);
            TestSecretSqlServer(oCert, SecretValue);
        }
        finally
        {
            oStore.Remove(oCert);
            oKey.Delete();
        }
    }

    private static void TestSecretProcess(string sVault, string sLabel, string sExpected)
    {
        string sExecutable = Environment.GetEnvironmentVariable("CRYPTURE_TEST_EXECUTABLE") ??
            Path.Combine(AppContext.BaseDirectory, "Crypture.exe");
        string sScript = Path.Combine(Path.GetDirectoryName(sVault), "ReadSecret.ps1");
        File.WriteAllText(sScript, """
            param($Executable, $Vault, $Label)
            $ErrorActionPreference = 'Stop'
            $secret = & $Executable get-secret --vault $Vault --label $Label | ConvertFrom-Json
            if ($LASTEXITCODE -ne 0) { throw 'Secret retrieval failed.' }
            $credential = [pscredential]::new('TestUser', (ConvertTo-SecureString $secret.Value -AsPlainText -Force))
            [Console]::WriteLine([Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
                $credential.GetNetworkCredential().Password)))
            $ErrorActionPreference = 'Continue'
            $missing = & $Executable get-secret --vault $Vault --id 9223372036854775807 2>$null | Out-String
            if ($LASTEXITCODE -ne 1 -or $missing.Length -ne 0) { throw 'Invalid retrieval failure output or exit code.' }
            """);
        ProcessStartInfo oStart = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        oStart.Environment.Remove("PSModulePath");
        foreach (string sArgument in new[] { "-NoProfile", "-NonInteractive", "-File", sScript,
            sExecutable, sVault, sLabel }) oStart.ArgumentList.Add(sArgument);
        using Process oProcess = Process.Start(oStart);
        var oOutput = oProcess.StandardOutput.ReadToEndAsync();
        var oError = oProcess.StandardError.ReadToEndAsync();
        if (!oProcess.WaitForExit(30000))
        {
            oProcess.Kill(true);
            throw new Exception("Secret retrieval unexpectedly waited for interaction.");
        }
        string sErrors = oError.GetAwaiter().GetResult();
        Check(oProcess.ExitCode == 0 && sErrors.Length == 0 &&
            oOutput.GetAwaiter().GetResult().Trim() == Convert.ToBase64String(Encoding.Unicode.GetBytes(sExpected)),
            "PowerShell captures Crypture output and constructs a PSCredential without changing the password" +
                (sErrors.Length == 0 ? "" : Environment.NewLine + sErrors));
    }

    private static void TestSecretSqlServer(X509Certificate2 oCertificate, string sExpected)
    {
        string sConnection = Environment.GetEnvironmentVariable("CRYPTURE_TEST_SQLSERVER");
        if (String.IsNullOrWhiteSpace(sConnection)) return;
        string sDatabase = "CryptureScripting_" + Guid.NewGuid().ToString("N");
        SqlConnectionStringBuilder oBuilder = new SqlConnectionStringBuilder(sConnection)
        {
            InitialCatalog = sDatabase, Pooling = false
        };
        SqlServerVaultStorage oStorage = new SqlServerVaultStorage(oBuilder.ConnectionString)
        {
            GrantDomainUsers = false,
            EscrowChoice = SqlServerEscrowChoice.ForCertificate(oCertificate.RawData,
                CertificateOperations.CurrentUserSid, "Scripting Test")
        };
        CreateVault(oStorage);
        try
        {
            User oRecipient = new User
            {
                UserId = oStorage.Escrow.CertificateUserId.Value, Certificate = oCertificate.RawData
            };
            Item oItem = new Item { Label = "Service Password", ItemType = "text", ModifiedBy = oRecipient.UserId };
            Item oOtherCase = new Item
            {
                Label = "service password", ItemType = "text", ModifiedBy = oRecipient.UserId
            };
            foreach (Item oSecret in new[] { oItem, oOtherCase })
            {
                ItemCryptography.Encrypt(oSecret, Encoding.Unicode.GetBytes(sExpected), [oRecipient]);
                SqlServerItemOperations.Save(oStorage, oSecret, oSecret);
            }

            // Ordinal selection remains exact under a case-insensitive SQL Server collation.
            var oResult = ReadSecret("--connection-string", oStorage.ConnectionString, "--label", oItem.Label);
            using (JsonDocument oJson = JsonDocument.Parse(oResult.Output))
                Check(oResult.ExitCode == 0 && oJson.RootElement.GetProperty("Value").GetString() == sExpected &&
                    oJson.RootElement.GetProperty("ItemId").GetInt64() == oItem.ItemId,
                    "Scripting retrieves SQL Server secrets with exact label matching");

            // Possessing the private key cannot bypass the server's enrolled Windows identity checks.
            using (SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString))
            {
                oConnection.Open();
                using SqlCommand oCommand = new SqlCommand(
                    "UPDATE [dbo].[User] SET [Sid] = N'S-1-5-21-1-2-3-5555'", oConnection);
                oCommand.ExecuteNonQuery();
            }
            oResult = ReadSecret("--connection-string", oStorage.ConnectionString, "--id", oItem.ItemId.ToString());
            Check(oResult.ExitCode == 1 && oResult.Output.Length == 0,
                "Scripting honors SQL Server authorization even when the private key is available");
        }
        finally
        {
            oBuilder.InitialCatalog = "master";
            using SqlConnection oConnection = new SqlConnection(oBuilder.ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand("ALTER DATABASE [" + sDatabase +
                "] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [" + sDatabase + "];", oConnection);
            oCommand.ExecuteNonQuery();
        }
    }

    private static void TestSilentCertificateAccess(X509Certificate2 oRsaCert)
    {
        // Test the silent native operations against real CAPI, CNG, and supported post-quantum providers.
        CspParameters oParameters = new CspParameters(24)
        {
            KeyContainerName = "Crypture.SilentTest-" + Guid.NewGuid().ToString("N"),
            Flags = CspProviderFlags.NoPrompt
        };
        using (RSA oLegacy = new RSACryptoServiceProvider(2048, oParameters) { PersistKeyInCsp = false })
        using (X509Certificate2 oCertificate = Certificate(oLegacy, "Silent CAPI Test",
            DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(1)))
            TestRecipientEnvelope(oCertificate, oRsaCert, "Silent CAPI RSA");
        foreach (CngAlgorithm oAlgorithm in new[] { CngAlgorithm.ECDiffieHellmanP256,
            CngAlgorithm.ECDiffieHellmanP384, CngAlgorithm.ECDiffieHellmanP521 })
        {
            using CngKey oKey = CngKey.Create(oAlgorithm, null, new CngKeyCreationParameters
            {
                KeyUsage = CngKeyUsages.KeyAgreement | CngKeyUsages.Signing
            });
            using X509Certificate2 oCertificate = EccCertificate(oKey);
            TestRecipientEnvelope(oCertificate, oRsaCert, "Silent " + oAlgorithm.Algorithm);
        }
        TestPersistedCertificate(false, oRsaCert);
        if (MLKem.IsSupported) TestPersistedCertificate(true, oRsaCert);
    }
}
