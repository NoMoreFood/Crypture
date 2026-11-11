using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Crypture
{
    internal static class SecretCommand
    {
        private const string Usage = """
            Crypture get-secret (--vault FILE | --connection-string CONNECTION)
                                (--label LABEL | --id ID) [--certificate THUMBPRINT]

            Retrieve a Text Secret using the current Windows account or an installed recipient certificate.
            Labels match exactly and must be unique. SQL Server uses Windows integrated authentication.
            Certificate access is silent. FIDO2 items require saved Windows or certificate recovery access.
            ML-KEM requires a software private key without UI protection.
            Success writes one JSON object with ItemId, Label, and Value to standard output.
            Value contains the decrypted secret. Capture the output and keep it out of logs.
            Errors go to standard error. Exit codes: 0 success, 1 retrieval failed, 2 invalid arguments.

            PowerShell:
              $secret = & .\Crypture.exe get-secret --vault C:\Secrets.cryptdb --label 'Password' | ConvertFrom-Json
              if ($LASTEXITCODE -ne 0) { throw 'Crypture could not retrieve the secret.' }
              $password = ConvertTo-SecureString $secret.Value -AsPlainText -Force
              $credential = [pscredential]::new('DOMAIN\ServiceAccount', $password)
            """;

        internal static bool IsCommand(string[] args) => args.Length > 0 &&
            (args[0].Equals("get-secret", StringComparison.OrdinalIgnoreCase) || args[0] is "--help" or "-h");

        internal static int RunConsole(string[] args)
        {
            // Preserve redirected streams when attaching a GUI-subsystem executable to its caller's console.
            IntPtr hOutput = GetStdHandle(-11), hError = GetStdHandle(-12);
            if (hOutput == IntPtr.Zero || hOutput == new IntPtr(-1))
            {
                if (AttachConsole(uint.MaxValue) && hError != IntPtr.Zero && hError != new IntPtr(-1))
                    SetStdHandle(-12, hError);
            }
            Console.OutputEncoding = new UTF8Encoding(false);
            AppContext.SetData("APP_CONFIG_FILE", ConfigurationDefaults.ConfigPath);
            return Run(args, Console.Out, Console.Error);
        }

        internal static int Run(string[] args, TextWriter oOutput, TextWriter oError)
        {
            int nFailureCode = 2;
            try
            {
                if (args.Length == 1 && args[0] is "--help" or "-h" || args.Length == 2 &&
                    args[0].Equals("get-secret", StringComparison.OrdinalIgnoreCase) && args[1] is "--help" or "-h")
                {
                    oOutput.WriteLine(Usage);
                    return 0;
                }

                // Require an explicit Vault and one unambiguous selector before accessing keys or content.
                if (args.Length == 0 || !args[0].Equals("get-secret", StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Use get-secret --help for usage.");
                Dictionary<string, string> oOptions = new Dictionary<string, string>(StringComparer.Ordinal);
                for (int nIndex = 1; nIndex < args.Length; nIndex += 2)
                {
                    string sOption = args[nIndex];
                    if (sOption is not ("--vault" or "--connection-string" or "--label" or "--id" or "--certificate") ||
                        nIndex + 1 >= args.Length || !oOptions.TryAdd(sOption, args[nIndex + 1]) ||
                        String.IsNullOrEmpty(args[nIndex + 1]))
                        throw new ArgumentException("Unknown, repeated, or incomplete option. Use get-secret --help.");
                }
                oOptions.TryGetValue("--vault", out string sVault);
                oOptions.TryGetValue("--connection-string", out string sConnection);
                oOptions.TryGetValue("--label", out string sLabel);
                oOptions.TryGetValue("--id", out string sId);
                oOptions.TryGetValue("--certificate", out string sThumbprint);
                if ((sVault == null) == (sConnection == null) || (sLabel == null) == (sId == null))
                    throw new ArgumentException("Specify one Vault and either --label or --id. Use get-secret --help.");
                long nItemId = 0;
                if (sId != null && (!Int64.TryParse(sId, NumberStyles.None, CultureInfo.InvariantCulture,
                    out nItemId) || nItemId <= 0))
                    throw new ArgumentException("The item ID must be a positive integer.");
                if (sThumbprint != null)
                {
                    sThumbprint = sThumbprint.Replace(" ", "", StringComparison.Ordinal);
                    if (sThumbprint.Length != 40 || sThumbprint.Any(c => !Uri.IsHexDigit(c)))
                        throw new ArgumentException("The certificate thumbprint must contain 40 hexadecimal digits.");
                }

                // File retrieval opens an existing Vault read-only; SQL Server retains its authorized views.
                IVaultStorage oStorage = sVault != null
                    ? SqliteVaultStorage.FromConnectionString(new SqliteConnectionStringBuilder
                    {
                        DataSource = Path.GetFullPath(sVault), Mode = SqliteOpenMode.ReadOnly,
                        ForeignKeys = true, Pooling = false
                    }.ConnectionString)
                    : new SqlServerVaultStorage(sConnection);
                nFailureCode = 1;
                Item oItem = ReadItem(oStorage, nItemId, sLabel).GetAwaiter().GetResult();
                byte[] oPlainText = Decrypt(oItem, sThumbprint);
                try
                {
                    string sValue = new UnicodeEncoding(false, false, true).GetString(oPlainText);
                    oOutput.WriteLine(JsonSerializer.Serialize(new { oItem.ItemId, oItem.Label, Value = sValue }));
                    return 0;
                }
                finally { CryptographicOperations.ZeroMemory(oPlainText); }
            }
            catch (Exception oException)
            {
                oError.WriteLine("Crypture: " + (oException is DecoderFallbackException
                    ? "The Text Secret contains invalid Unicode text." : oException.Message));
                return nFailureCode;
            }
        }

        private static async Task<Item> ReadItem(IVaultStorage oStorage, long nItemId, string sLabel)
        {
            await oStorage.ValidateAsync(CancellationToken.None).ConfigureAwait(false);
            using CryptureEntities oContent = new CryptureEntities(oStorage);
            Item oItem = null;

            // Resolve the label and load every authenticated recipient from the same database snapshot.
            await oStorage.ReadSnapshotAsync(oContent, async () =>
            {
                if (sLabel != null)
                {
                    var oCandidates = await oContent.Items.Where(i => i.Label == sLabel)
                        .Select(i => new { i.ItemId, i.Label }).ToListAsync().ConfigureAwait(false);
                    var oMatches = oCandidates.Where(i => i.Label.Equals(sLabel, StringComparison.Ordinal)).ToList();
                    if (oMatches.Count > 1)
                        throw new InvalidOperationException("The label matches multiple items. Use --id with " +
                            "one of these item IDs: " + String.Join(", ", oMatches.Select(i => i.ItemId)) + ".");
                    nItemId = oMatches.SingleOrDefault()?.ItemId ?? 0;
                }
                oItem = await oContent.Items.Include(i => i.Cipher).Include(i => i.Instances)
                    .ThenInclude(i => i.User).AsNoTracking().AsSplitQuery()
                    .SingleOrDefaultAsync(i => i.ItemId == nItemId).ConfigureAwait(false);
            }, CancellationToken.None).ConfigureAwait(false);
            if (oItem == null) throw new InvalidOperationException("The requested item was not found.");
            if (oItem.ItemType != "text")
                throw new InvalidOperationException("get-secret requires a Text Secret item.");
            if (oItem.Cipher == null)
                throw new InvalidOperationException("The encrypted content is unavailable to this account.");
            return oItem;
        }

        private static byte[] Decrypt(Item oItem, string sThumbprint)
        {
            // Windows and saved recovery access need no UI and use the existing authenticated decrypt path.
            CryptographicException oLastError = null;
            if (sThumbprint == null && oItem.Cipher.CipherParams is ItemCryptography.PrincipalFormat or
                ItemCryptography.RecoveryFormat or ItemCryptography.FidoFormat)
            {
                try { return ItemCryptography.Decrypt(oItem, bSilent: true); }
                catch (CryptographicException oError) { oLastError = oError; }
            }

            // Match public certificate bytes before opening a private key, and suppress provider prompts.
            X509Certificate2Collection oCertificates = CertificateOperations.GetPersonalCertificates();
            try
            {
                foreach (X509Certificate2 oCertificate in oCertificates)
                {
                    if (!oCertificate.HasPrivateKey || sThumbprint != null &&
                        !oCertificate.Thumbprint.Equals(sThumbprint, StringComparison.OrdinalIgnoreCase)) continue;
                    Instance oInstance = oItem.Instances.FirstOrDefault(i => i.User?.Certificate != null &&
                        i.User.Certificate.SequenceEqual(oCertificate.RawData));
                    if (oInstance == null) continue;
                    try { return ItemCryptography.Decrypt(oItem, oInstance, oCertificate, bSilent: true); }
                    catch (CryptographicException oError) { oLastError = oError; }
                }
            }
            finally
            {
                foreach (X509Certificate2 oCertificate in oCertificates) oCertificate.Dispose();
            }
            throw new CryptographicException("No unattended decryption path succeeded. Use an authorized Windows " +
                "account or a recipient private key that can operate without a prompt." +
                (oLastError == null ? "" : " " + oLastError.Message), oLastError);
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetStdHandle(int nHandle);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetStdHandle(int nHandle, IntPtr hHandle);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AttachConsole(uint nProcessId);
    }
}
