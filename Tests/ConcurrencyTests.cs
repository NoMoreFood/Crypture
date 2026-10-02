using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Crypture;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

internal static partial class RegressionTests
{
    private const int ConcurrentWriterCount = 4;
    private const int ConcurrentRevisions = 30;
    private const int ConcurrentLoadSeconds = 10;

    private static void TestConcurrentDatabase(string sDirectory, X509Certificate2 oCert, X509Certificate2 oOtherCert)
    {
        string sPreviousConnection = CryptureEntities.ConnectionString;
        string sRoot = Path.Combine(sDirectory, "concurrency");
        Directory.CreateDirectory(sRoot);
        string sDatabase = Path.Combine(sRoot, "shared.cryptdb");
        string sSchema = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql"));
        File.WriteAllBytes(Path.Combine(sRoot, "primary.pfx"), oCert.Export(X509ContentType.Pfx));
        File.WriteAllBytes(Path.Combine(sRoot, "secondary.pfx"), oOtherCert.Export(X509ContentType.Pfx));
        try
        {
            // Exercise actual encryption and persistence across independent application processes.
            DatabaseOperations.CreateDatabase(sDatabase, sSchema);
            CryptureEntities.DatabasePath = sDatabase;
            User[] oUsers = { new User { Certificate = oCert.RawData }, new User { Certificate = oOtherCert.RawData } };
            using (CryptureEntities oContext = new())
            {
                oContext.Users.AddRange(oUsers);
                oContext.SaveChanges();
            }
            DatabaseOperations.SavePasswordOptions(ConcurrentOptions(30));
            for (int nWriter = 0; nWriter < ConcurrentWriterCount; nWriter++)
                SaveConcurrentItem(new Item(), "concurrent:" + nWriter + ":0", oUsers);
            long[] nIds;
            using (CryptureEntities oContext = new())
                nIds = oContext.Items.OrderBy(i => i.ItemId).Select(i => i.ItemId).ToArray();
            File.WriteAllLines(Path.Combine(sRoot, "items.txt"), nIds.Select(i => i.ToString()));
            string[] sWriters = Enumerable.Range(0, ConcurrentWriterCount).Select(i => "writer-" + i).ToArray();
            string[] sReaders = Enumerable.Range(0, 4).Select(i => "reader-" + i).ToArray();
            Dictionary<string, long> oCounts = RunConcurrentClients(sRoot, "workload",
                sWriters.Concat(sReaders).Concat(new[] { "backup", "health" }));
            Check(oCounts["writes"] == ConcurrentWriterCount * ConcurrentRevisions * 2 &&
                oCounts["deletes"] == ConcurrentWriterCount * ConcurrentRevisions,
                "Four writer processes create, update, convert, and delete items without losing successful writes");
            Check(oCounts["reads"] >= 4 * 40 * ConcurrentWriterCount && oCounts["overlappingReads"] > 0,
                "Four reader processes decrypt complete committed item versions while writers are active");
            Check(oCounts["backups"] >= 5 && oCounts["healthChecks"] >= 5,
                "Backups and health checks remain consistent during concurrent writes");
            ValidateConcurrentVault(sDatabase, oCert, oOtherCert);
            using (CryptureEntities oContext = new())
                Check(oContext.Items.Count() == ConcurrentWriterCount &&
                    oContext.Items.All(i => i.Label.EndsWith(":" + ConcurrentRevisions)),
                    "Every writer's final revision survives and temporary items are removed");

            // The WPF browser reads metadata separately from encrypted item loads.
            oCounts = RunConcurrentClients(sRoot, "browser", sWriters.Concat(new[] { "browser" }));
            Check(oCounts["refreshes"] >= 40 && oCounts["overlappingRefreshes"] > 0,
                "Browser refreshes keep item labels, recipients, and protection modes in the same snapshot");

            // All contenders open the same original version before any competing save begins.
            SaveConcurrentItem(new Item(), "collision:0:0", oUsers);
            long nShared;
            using (CryptureEntities oContext = new())
                nShared = oContext.Items.Single(i => i.Label == "collision:0:0").ItemId;
            File.WriteAllText(Path.Combine(sRoot, "shared.txt"), nShared.ToString());
            oCounts = RunConcurrentClients(sRoot, "collision",
                Enumerable.Range(0, 8).Select(i => "collision-" + i));
            Check(oCounts["writes"] == 1 && oCounts["conflicts"] == 7,
                "Eight simultaneous edits produce one committed winner and seven explicit stale-edit rejections");
            ValidateConcurrentItem(DatabaseOperations.LoadItem(nShared), oCert, oOtherCert);
            oCounts = RunConcurrentClients(sRoot, "delete", new[] { "delete", "resave" });
            using (CryptureEntities oContext = new())
                Check(oCounts["deletes"] == 1 && oCounts["writes"] + oCounts["conflicts"] == 1 &&
                    !oContext.Items.Any(i => i.ItemId == nShared) &&
                    !oContext.Ciphers.Any(i => i.ItemId == nShared) &&
                    !oContext.Instances.Any(i => i.ItemId == nShared),
                    "Competing save and deletion never resurrect the item or leave encrypted orphan records");

            // Certificate deletion must serialize with saves that depend on that recipient.
            SaveConcurrentItem(new Item(), "recipient:0:0", oUsers);
            using (CryptureEntities oContext = new())
                nShared = oContext.Items.Single(i => i.Label == "recipient:0:0").ItemId;
            File.WriteAllText(Path.Combine(sRoot, "shared.txt"), nShared.ToString());
            oCounts = RunConcurrentClients(sRoot, "recipient", new[] { "remove-recipient", "recipient-save" });
            Check(oCounts["writes"] + oCounts["certificateDeletes"] == 1 &&
                oCounts["missingRecipientRejections"] + oCounts["lastRecipientRejections"] == 1,
                "Recipient deletion and replacement preserve a readable item and reject the losing operation");
            Item oRecipientItem = DatabaseOperations.LoadItem(nShared);
            ValidateConcurrentItem(oRecipientItem, oCert, oOtherCert, nExpectedRecipients: 1);
            SaveConcurrentItem(oRecipientItem, "recipient:0:2", new[] { oUsers[0] });

            // Held reader and writer locks test waiting, timeout rollback, and recovery after release.
            using (SqliteConnection oConnection = new(CryptureEntities.ConnectionString))
            {
                oConnection.Open();
                foreach (bool bReader in new[] { false, true })
                {
                    using (SqliteTransaction oTransaction = oConnection.BeginTransaction(deferred: bReader))
                    {
                        using (SqliteCommand oCommand = new("SELECT COUNT(*) FROM Item", oConnection, oTransaction))
                            oCommand.ExecuteScalar();
                        string sPhase = bReader ? "reader-lock" : "writer-lock";
                        oCounts = RunConcurrentClients(sRoot, sPhase, new[] { "locked-writer" }, oProcesses =>
                        {
                            WaitForConcurrentCondition(() => File.Exists(Path.Combine(sRoot, sPhase, "attempt")));
                            Thread.Sleep(250);
                            Check(!oProcesses[0].HasExited,
                                "A save waits for a held " + (bReader ? "reader" : "writer") + " lock");
                            oTransaction.Commit();
                        });
                    }
                    Check(oCounts["writes"] == 1, "A waiting save completes after the database lock is released");
                }
                Item oBefore = DatabaseOperations.LoadItem(nIds[0]);
                using (SqliteTransaction oTransaction = oConnection.BeginTransaction())
                    oCounts = RunConcurrentClients(sRoot, "timeout", new[] { "timeout-writer" });
                Item oAfter = DatabaseOperations.LoadItem(nIds[0]);
                Check(oCounts["lockTimeouts"] == 1 && oAfter.Label == oBefore.Label &&
                    oAfter.Cipher.CipherText.SequenceEqual(oBefore.Cipher.CipherText),
                    "A bounded lock timeout leaves the previously committed encrypted item intact");

                SaveConcurrentItem(new Item(), "blocked-delete:0:2", new[] { oUsers[0] });
                using (CryptureEntities oContext = new())
                    nShared = oContext.Items.Single(i => i.Label == "blocked-delete:0:2").ItemId;
                File.WriteAllText(Path.Combine(sRoot, "shared.txt"), nShared.ToString());
                using (SqliteTransaction oTransaction = oConnection.BeginTransaction(deferred: true))
                {
                    using (SqliteCommand oCommand = new("SELECT COUNT(*) FROM Item", oConnection, oTransaction))
                        oCommand.ExecuteScalar();
                    oCounts = RunConcurrentClients(sRoot, "delete-lock", new[] { "delete" }, oProcesses =>
                    {
                        WaitForConcurrentCondition(() => File.Exists(Path.Combine(sRoot, "delete-lock", "attempt")));
                        Thread.Sleep(250);
                        Check(!oProcesses[0].HasExited, "Single-item deletion waits for an active reader");
                        oTransaction.Commit();
                    });
                }
                Check(oCounts["deletes"] == 1, "Single-item deletion commits after the reader releases its lock");

                using (SqliteCommand oCommand = oConnection.CreateCommand())
                {
                    oCounts = RunConcurrentClients(sRoot, "backup-lock", new[] { "locked-backup" }, oProcesses =>
                    {
                        WaitForConcurrentCondition(() => File.Exists(Path.Combine(sRoot, "backup-lock", "attempt")));
                        Thread.Sleep(250);
                        Check(!oProcesses[0].HasExited,
                            "Backup waits for an exclusive writer instead of failing busy");
                        oCommand.CommandText = "ROLLBACK";
                        oCommand.ExecuteNonQuery();
                    }, () =>
                    {
                        oCommand.CommandText = "BEGIN EXCLUSIVE";
                        oCommand.ExecuteNonQuery();
                    });
                }
                Check(oCounts["backups"] == 1, "Backup completes after the exclusive writer releases its lock");
            }

            // Terminate a process after modifying all three item tables inside an uncommitted transaction.
            Item oBeforeCrash = DatabaseOperations.LoadItem(nIds[0]);
            RunConcurrentClients(sRoot, "crash", new[] { "crash-writer" }, oProcesses => oProcesses[0].Kill(true));
            Item oAfterCrash = DatabaseOperations.LoadItem(nIds[0]);
            Check(oAfterCrash.Label == oBeforeCrash.Label &&
                oAfterCrash.Cipher.CipherText.SequenceEqual(oBeforeCrash.Cipher.CipherText) &&
                oAfterCrash.Instances.Count == oBeforeCrash.Instances.Count,
                "Process termination rolls back uncommitted metadata, ciphertext, and recipient changes");
            ValidateConcurrentVault(sDatabase, oCert, oOtherCert);

            // File creation, backup publication, and legacy schema upgrades also have competing callers.
            oCounts = RunConcurrentClients(sRoot, "create", Enumerable.Range(0, 4).Select(i => "create-" + i));
            Check(oCounts["creations"] == 1 && oCounts["existingFileRejections"] == 3,
                "Concurrent creation of one Vault filename preserves the single successful creator");
            DatabaseOperations.EnsureProtectionSchema(Path.Combine(sRoot, "created.cryptdb"));
            oCounts = RunConcurrentClients(sRoot, "backup-race",
                Enumerable.Range(0, 4).Select(i => "backup-race-" + i));
            Check(oCounts["backups"] == 1 && oCounts["existingFileRejections"] == 3 &&
                !Directory.EnumerateFiles(sRoot, "*.tmp").Any(),
                "Concurrent backups to one filename publish one valid snapshot and clean temporary files");
            ValidateConcurrentVault(Path.Combine(sRoot, "competing-backup.cryptdb"), oCert, oOtherCert);

            string sLegacy = sSchema[..sSchema.IndexOf("CREATE TABLE IF NOT EXISTS", StringComparison.Ordinal)]
                .Replace("\t[ModifiedByIdentity] nvarchar NULL,\r\n", "")
                .Replace("\t[ContentSuite] integer NULL,\r\n", "")
                .Replace("\t[AuthenticationTag] blob NULL,\r\n", "")
                .Replace("\t[ProtectionDescriptor] nvarchar NULL,\r\n", "")
                .Replace("\t[ProtectedKey] blob NULL,\r\n", "")
                .Replace("\t[Signature] blob NULL\r\n", "")
                .Replace("[CipherParams] integer DEFAULT '0' NOT NULL,",
                    "[CipherParams] integer DEFAULT '0' NOT NULL");
            string sLegacyPath = Path.Combine(sRoot, "legacy.cryptdb");
            DatabaseOperations.CreateDatabase(sLegacyPath, sLegacy);
            oCounts = RunConcurrentClients(sRoot, "migration",
                Enumerable.Range(0, 6).Select(i => "migrate-" + i));
            CryptureEntities.DatabasePath = sLegacyPath;
            using (CryptureEntities oContext = new()) oContext.Items.Include(i => i.Cipher).ToList();
            Check(oCounts["migrations"] == 6 && DatabaseOperations.LoadPasswordOptions().MinimumLength == 20,
                "Six simultaneous legacy Vault opens complete the schema migration without duplicate columns");
        }
        finally
        {
            CryptureEntities.ConnectionString = sPreviousConnection;
        }
    }

    private static Dictionary<string, long> RunConcurrentClients(string sRoot, string sPhase,
        IEnumerable<string> sRoles, Action<IReadOnlyList<Process>> oAfterStart = null, Action oBeforeStart = null)
    {
        string sSignals = Path.Combine(sRoot, sPhase);
        Directory.CreateDirectory(sSignals);
        List<(string Role, Process Process, Task<string> Output, Task<string> Errors)> oClients = new();
        Stopwatch oWatch = Stopwatch.StartNew();
        Console.WriteLine("Concurrency phase: " + sPhase);
        try
        {
            foreach (string sRole in sRoles)
            {
                ProcessStartInfo oStart = new(Environment.ProcessPath)
                {
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                };
                oStart.Environment["CRYPTURE_TEST_CONCURRENCY_ROLE"] = sRole;
                oStart.Environment["CRYPTURE_TEST_CONCURRENCY_ROOT"] = sRoot;
                oStart.Environment["CRYPTURE_TEST_CONCURRENCY_SIGNALS"] = sSignals;
                Process oProcess = Process.Start(oStart);
                oClients.Add((sRole, oProcess, oProcess.StandardOutput.ReadToEndAsync(),
                    oProcess.StandardError.ReadToEndAsync()));
            }
            WaitForConcurrentCondition(() => oClients.All(c =>
                File.Exists(Path.Combine(sSignals, c.Role + ".ready")) || c.Process.HasExited));
            oBeforeStart?.Invoke();
            File.WriteAllText(Path.Combine(sSignals, "start"), "");
            oAfterStart?.Invoke(oClients.Select(c => c.Process).ToList());
            long nProgressSeconds = 0;
            WaitForConcurrentCondition(() =>
            {
                if (oWatch.Elapsed.TotalSeconds >= nProgressSeconds + 10)
                {
                    nProgressSeconds = (long)oWatch.Elapsed.TotalSeconds;
                    foreach (var oClient in oClients.Where(c => c.Role.StartsWith("writer-")))
                    {
                        string sProgressPath = Path.Combine(sSignals, oClient.Role + ".progress");
                        try
                        {
                            if (File.Exists(sProgressPath))
                            {
                                using StreamReader oReader = new(new FileStream(sProgressPath,
                                    FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
                                Console.WriteLine(oClient.Role + " at " + nProgressSeconds +
                                    "s: " + oReader.ReadToEnd());
                            }
                        }
                        catch (IOException) { }
                    }
                }
                return oClients.All(c => c.Process.HasExited) || oClients.Any(c =>
                    c.Process.HasExited && c.Process.ExitCode != 0 && c.Role != "crash-writer");
            });
            foreach (var oClient in oClients)
                if (!oClient.Process.HasExited) oClient.Process.Kill(true);
            Dictionary<string, long> oTotals = new();
            List<string> sFailures = new();
            foreach (var oClient in oClients)
            {
                oClient.Process.WaitForExit();
                string sOutput = oClient.Output.GetAwaiter().GetResult();
                string sErrors = oClient.Errors.GetAwaiter().GetResult();
                if (oClient.Role == "crash-writer")
                {
                    if (oClient.Process.ExitCode == 0) sFailures.Add("The crash worker exited normally.");
                    continue;
                }
                if (oClient.Process.ExitCode != 0)
                {
                    sFailures.Add(oClient.Role + ": " + sErrors + sOutput);
                    continue;
                }
                foreach (var oCount in JsonSerializer.Deserialize<Dictionary<string, long>>(sOutput))
                    oTotals[oCount.Key] = oTotals.GetValueOrDefault(oCount.Key) + oCount.Value;
            }
            if (sFailures.Count != 0) throw new Exception(String.Join(Environment.NewLine, sFailures));
            Console.WriteLine(sPhase + " completed in " + oWatch.Elapsed.TotalSeconds.ToString("F1") + "s: " +
                String.Join(", ", oTotals.Where(c => c.Value != 0).Select(c => c.Key + "=" + c.Value)));
            return oTotals;
        }
        finally
        {
            foreach (var oClient in oClients)
            {
                if (!oClient.Process.HasExited) oClient.Process.Kill(true);
                oClient.Process.WaitForExit();
                oClient.Process.Dispose();
            }
        }
    }

    private static int RunConcurrencyWorker(string sRole)
    {
        string sRoot = Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONCURRENCY_ROOT");
        string sSignals = Environment.GetEnvironmentVariable("CRYPTURE_TEST_CONCURRENCY_SIGNALS");
        string sDatabase = Path.Combine(sRoot, "shared.cryptdb");
        Dictionary<string, long> oCounts = new[] { "writes", "reads", "overlappingReads", "deletes", "backups",
            "healthChecks", "refreshes", "overlappingRefreshes", "conflicts", "certificateDeletes",
            "missingRecipientRejections", "lastRecipientRejections", "lockTimeouts", "creations",
            "existingFileRejections", "migrations" }.ToDictionary(k => k, _ => 0L);
        try
        {
            using X509Certificate2 oCert = X509CertificateLoader.LoadPkcs12FromFile(
                Path.Combine(sRoot, "primary.pfx"), null, X509KeyStorageFlags.EphemeralKeySet);
            using X509Certificate2 oOtherCert = X509CertificateLoader.LoadPkcs12FromFile(
                Path.Combine(sRoot, "secondary.pfx"), null, X509KeyStorageFlags.EphemeralKeySet);
            CryptureEntities.DatabasePath = sDatabase;
            User[] oUsers;
            using (CryptureEntities oContext = new()) oUsers = oContext.Users.OrderBy(u => u.UserId).ToArray();
            long[] nIds = File.ReadAllLines(Path.Combine(sRoot, "items.txt")).Select(Int64.Parse).ToArray();
            bool bShared = sRole.StartsWith("collision-") || sRole is "delete" or "resave" or
                "remove-recipient" or "recipient-save";
            Item oOriginal = bShared ? DatabaseOperations.LoadItem(Int64.Parse(
                File.ReadAllText(Path.Combine(sRoot, "shared.txt")))) : DatabaseOperations.LoadItem(nIds[0]);
            if (sRole == "timeout-writer")
                CryptureEntities.ConnectionString = new SqliteConnectionStringBuilder(
                    CryptureEntities.ConnectionString) { DefaultTimeout = 1 }.ConnectionString;

            // Keep the crash transaction alive until the parent forcibly terminates this process.
            using CryptureEntities oCrashContext = sRole == "crash-writer" ? new() : null;
            using var oCrashTransaction = oCrashContext?.Database.BeginTransaction();
            if (oCrashContext != null)
                oCrashContext.Database.ExecuteSqlRaw(
                    "UPDATE Item SET Label = 'uncommitted' WHERE ItemId = {0}; " +
                    "UPDATE Cipher SET CipherText = X'00' WHERE ItemId = {0}; " +
                    "DELETE FROM Instance WHERE ItemId = {0};", nIds[0]);
            File.WriteAllText(Path.Combine(sSignals, sRole + ".ready"), "");
            WaitForConcurrentCondition(() => File.Exists(Path.Combine(sSignals, "start")));
            bool WritersActive() => Enumerable.Range(0, ConcurrentWriterCount).Any(i =>
                !File.Exists(Path.Combine(sSignals, "writer-" + i + ".done")));
            Stopwatch oWatch = Stopwatch.StartNew();

            if (sRole.StartsWith("writer-"))
            {
                int nWriter = Int32.Parse(sRole[7..]);
                DatabaseOperations.EnsureProtectionSchema(sDatabase);
                for (int nRevision = 1; nRevision <= ConcurrentRevisions; nRevision++)
                {
                    string sProgress = Path.Combine(sSignals, sRole + ".progress");
                    File.WriteAllText(sProgress, "revision " + nRevision + ": load");
                    Item oItem = DatabaseOperations.LoadItem(nIds[nWriter]);
                    File.WriteAllText(sProgress, "revision " + nRevision + ": update");
                    SaveConcurrentItem(oItem, "concurrent:" + nWriter + ":" + nRevision, oUsers);
                    File.WriteAllText(sProgress, "revision " + nRevision + ": create");
                    SaveConcurrentItem(new Item(), "temporary:" + nWriter + ":" + nRevision, oUsers);
                    File.WriteAllText(sProgress, "revision " + nRevision + ": delete");
                    using (CryptureEntities oContext = new())
                    {
                        oContext.Items.Remove(oContext.Items.Single(i =>
                            i.Label == "temporary:" + nWriter + ":" + nRevision));
                        oContext.SaveChanges();
                    }
                    File.WriteAllText(sProgress, "revision " + nRevision + ": settings");
                    DatabaseOperations.SavePasswordOptions(ConcurrentOptions(30 + nWriter * 40 + nRevision));
                    oCounts["writes"] += 2;
                    oCounts["deletes"]++;
                }
                File.WriteAllText(Path.Combine(sSignals, sRole + ".progress"), "finished");
            }
            else if (sRole.StartsWith("reader-"))
            {
                for (int nPass = 0; nPass < 40 ||
                    WritersActive() && oWatch.Elapsed.TotalSeconds < ConcurrentLoadSeconds; nPass++)
                {
                    if (oWatch.Elapsed.TotalSeconds > 60)
                        throw new TimeoutException("Reader workload did not finish.");
                    bool bActive = WritersActive();
                    foreach (long nId in nIds)
                    {
                        ValidateConcurrentItem(DatabaseOperations.LoadItem(nId), oCert, oOtherCert);
                        oCounts["reads"]++;
                        if (bActive) oCounts["overlappingReads"]++;
                    }
                    PasswordOptions oOptions = DatabaseOperations.LoadPasswordOptions();
                    PasswordOptions oExpected = ConcurrentOptions(oOptions.MinimumLength);
                    if (oOptions.MaximumLength != oExpected.MaximumLength ||
                        oOptions.IncludeDigits != oExpected.IncludeDigits ||
                        oOptions.SymbolCharacters != oExpected.SymbolCharacters ||
                        oOptions.ExcludedCharacters != oExpected.ExcludedCharacters)
                        throw new Exception("A reader observed mixed password-generator settings.");
                }
            }
            else if (sRole is "backup" or "health" or "browser")
            {
                ItemBrowser oBrowser = null;
                if (sRole == "browser")
                {
                    new Application
                    {
                        ShutdownMode = ShutdownMode.OnExplicitShutdown,
                        Resources = new ResourceDictionary
                            { Source = new Uri("pack://application:,,,/Crypture;component/Themes/Controls.xaml") }
                    };
                    App.ApplyTheme(false);
                    oBrowser = new ItemBrowser();
                }
                try
                {
                    for (int nPass = 0; nPass < (sRole == "browser" ? 40 : 5) ||
                        WritersActive() && oWatch.Elapsed.TotalSeconds < ConcurrentLoadSeconds; nPass++)
                    {
                        if (oWatch.Elapsed.TotalSeconds > 60) throw new TimeoutException(sRole + " did not finish.");
                        if (sRole == "backup")
                        {
                            string sBackup = Path.Combine(sSignals, "backup-" + nPass + ".cryptdb");
                            DatabaseOperations.BackupDatabase(sDatabase, sBackup);
                            ValidateConcurrentVault(sBackup, oCert, oOtherCert);
                            CryptureEntities.DatabasePath = sDatabase;
                            oCounts["backups"]++;
                        }
                        else if (sRole == "health")
                        {
                            VaultHealthReport oReport = VaultHealthCheck.Run(
                                sDatabase, true, false, CancellationToken.None);
                            if (oReport.ItemCount < ConcurrentWriterCount ||
                                oReport.Findings.Any(f => f.Severity == HealthStatus.Error))
                                throw new Exception("A health check observed an incomplete committed item graph.");
                            oCounts["healthChecks"]++;
                        }
                        else
                        {
                            bool bActive = WritersActive();
                            typeof(ItemBrowser).GetMethod(
                                "RefreshData", BindingFlags.Instance | BindingFlags.NonPublic)
                                .Invoke(oBrowser, null);
                            foreach (Item oItem in oBrowser.ItemList)
                                ValidateConcurrentItem(oItem, oCert, oOtherCert, false);
                            oCounts["refreshes"]++;
                            if (bActive) oCounts["overlappingRefreshes"]++;
                        }
                    }
                }
                finally
                {
                    if (oBrowser != null)
                    {
                        oBrowser.Closing -= (System.ComponentModel.CancelEventHandler)Delegate.CreateDelegate(
                            typeof(System.ComponentModel.CancelEventHandler), oBrowser, "oItemBrowser_Closing");
                        oBrowser.Close();
                        Application.Current.Shutdown();
                    }
                }
            }
            else if (sRole.StartsWith("collision-") || sRole is "resave" or "recipient-save")
            {
                int nWriter = sRole.StartsWith("collision-") ? Int32.Parse(sRole[10..]) : 0;
                try
                {
                    SaveConcurrentItem(oOriginal, (sRole == "recipient-save" ? "recipient" : "collision") +
                        ":" + nWriter + ":" + (sRole == "recipient-save" ? 2 : nWriter + 1),
                        sRole == "recipient-save" ? new[] { oUsers[1] } : oUsers);
                    oCounts["writes"]++;
                }
                catch (InvalidOperationException oError) when (oError.Message.Contains("changed or was removed"))
                {
                    oCounts["conflicts"]++;
                }
                catch (DbUpdateException oError) when (sRole == "recipient-save" &&
                    oError.InnerException is SqliteException { SqliteExtendedErrorCode: 787 })
                {
                    oCounts["missingRecipientRejections"]++;
                }
            }
            else if (sRole == "delete")
            {
                File.WriteAllText(Path.Combine(sSignals, "attempt"), "");
                using CryptureEntities oContext = new();
                oContext.Items.Remove(oContext.Items.Find(oOriginal.ItemId));
                oContext.SaveChanges();
                oCounts["deletes"]++;
            }
            else if (sRole == "remove-recipient")
            {
                try
                {
                    DatabaseOperations.RemoveCertificate(oUsers[1].UserId);
                    oCounts["certificateDeletes"]++;
                }
                catch (InvalidOperationException oError) when (oError.Message.Contains("only recipient"))
                {
                    oCounts["lastRecipientRejections"]++;
                }
            }
            else if (sRole is "locked-writer" or "timeout-writer")
            {
                File.WriteAllText(Path.Combine(sSignals, "attempt"), "");
                try
                {
                    int nRevision = Int32.Parse(oOriginal.Label.Split(':')[2]) + 4;
                    SaveConcurrentItem(oOriginal, "concurrent:0:" + nRevision, oUsers);
                    oCounts["writes"]++;
                }
                catch (SqliteException oError) when (sRole == "timeout-writer" && oError.SqliteErrorCode == 5)
                {
                    oCounts["lockTimeouts"]++;
                }
            }
            else if (sRole == "locked-backup")
            {
                File.WriteAllText(Path.Combine(sSignals, "attempt"), "");
                string sBackup = Path.Combine(sSignals, "locked-backup.cryptdb");
                DatabaseOperations.BackupDatabase(sDatabase, sBackup);
                ValidateConcurrentVault(sBackup, oCert, oOtherCert);
                oCounts["backups"]++;
            }
            else if (sRole == "crash-writer") Thread.Sleep(Timeout.Infinite);
            else if (sRole.StartsWith("create-") || sRole.StartsWith("backup-race-"))
            {
                try
                {
                    if (sRole.StartsWith("create-"))
                    {
                        DatabaseOperations.CreateDatabase(Path.Combine(sRoot, "created.cryptdb"),
                            File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SQLite.sql")));
                        oCounts["creations"]++;
                    }
                    else
                    {
                        DatabaseOperations.BackupDatabase(sDatabase, Path.Combine(sRoot, "competing-backup.cryptdb"));
                        oCounts["backups"]++;
                    }
                }
                catch (IOException)
                {
                    oCounts["existingFileRejections"]++;
                }
            }
            else if (sRole.StartsWith("migrate-"))
            {
                DatabaseOperations.EnsureProtectionSchema(Path.Combine(sRoot, "legacy.cryptdb"));
                oCounts["migrations"]++;
            }
            else throw new ArgumentException("Unknown concurrency role: " + sRole);
            File.WriteAllText(Path.Combine(sSignals, sRole + ".done"), "");
            Console.WriteLine(JsonSerializer.Serialize(oCounts));
            return 0;
        }
        catch (Exception oError)
        {
            Console.Error.WriteLine(oError);
            return 1;
        }
    }

    private static void SaveConcurrentItem(Item oItem, string sLabel, User[] oUsers)
    {
        int nRevision = Int32.Parse(sLabel.Split(':')[2]);
        oItem.Label = sLabel;
        oItem.ItemType = nRevision % 3 == 0 ? "text" : "file";
        string sDescriptor = (nRevision % 4) switch
        {
            1 => PrincipalProtection.LocalUserDescriptor,
            3 => PrincipalProtection.LocalMachineDescriptor,
            _ => null
        };
        DatabaseOperations.SaveItem(oItem, ConcurrentPayload(sLabel),
            nRevision % 4 == 2 ? oUsers.Take(1) : oUsers, sDescriptor);
    }

    private static byte[] ConcurrentPayload(string sLabel)
    {
        int nRevision = Int32.Parse(sLabel.Split(':')[2]);
        int nLength = (nRevision % 5) switch { 0 => 0, 1 => 8193, 2 => 65537, 3 => 524289, _ => 32769 };
        byte[] oPayload = new byte[nLength];
        byte[] oHeader = Encoding.UTF8.GetBytes(sLabel);
        for (int nIndex = 0; nIndex < oPayload.Length; nIndex++)
            oPayload[nIndex] = (byte)(oHeader[nIndex % oHeader.Length] ^ nIndex);
        return oPayload;
    }

    private static PasswordOptions ConcurrentOptions(int nMinimum) => new()
    {
        MinimumLength = nMinimum, MaximumLength = nMinimum + 3, IncludeDigits = nMinimum % 2 == 0,
        SymbolCharacters = nMinimum % 2 == 0 ? "!#" : "@$", ExcludedCharacters = nMinimum.ToString()
    };

    private static void ValidateConcurrentItem(Item oItem, X509Certificate2 oCert, X509Certificate2 oOtherCert,
        bool bDecrypt = true, int? nExpectedRecipients = null)
    {
        int nRevision = Int32.Parse(oItem.Label.Split(':')[2]);
        string sDescriptor = (nRevision % 4) switch
        {
            1 => PrincipalProtection.LocalUserDescriptor,
            3 => PrincipalProtection.LocalMachineDescriptor,
            _ => null
        };
        int nRecipients = nExpectedRecipients ?? (sDescriptor != null ? 0 : nRevision % 4 == 0 ? 2 : 1);
        if (oItem.ItemType != (nRevision % 3 == 0 ? "text" : "file") || oItem.Cipher == null ||
            oItem.Cipher.ProtectionDescriptor != sDescriptor ||
            oItem.Cipher.CipherParams != (sDescriptor == null
                ? ItemCryptography.CertificateFormat : ItemCryptography.PrincipalFormat) ||
            oItem.Instances.Count != nRecipients || oItem.Instances.Any(i => i.User == null))
            throw new Exception("Mixed or incomplete item snapshot: " + oItem.Label + ", format=" +
                oItem.Cipher?.CipherParams + ", recipients=" + oItem.Instances.Count);
        if (!bDecrypt) return;
        byte[] oExpected = ConcurrentPayload(oItem.Label);
        if (sDescriptor != null)
        {
            if (!ItemCryptography.Decrypt(oItem).SequenceEqual(oExpected))
                throw new Exception("A Windows-protected reader observed inconsistent content: " + oItem.Label);
            return;
        }
        foreach (Instance oInstance in oItem.Instances)
        {
            X509Certificate2 oRecipient = oInstance.User.Certificate.SequenceEqual(oCert.RawData) ? oCert : oOtherCert;
            if (!ItemCryptography.Decrypt(oItem, oInstance, oRecipient).SequenceEqual(oExpected))
                throw new Exception("A certificate reader observed inconsistent content: " + oItem.Label);
        }
    }

    private static void ValidateConcurrentVault(string sPath, X509Certificate2 oCert, X509Certificate2 oOtherCert)
    {
        string sPreviousConnection = CryptureEntities.ConnectionString;
        try
        {
            CryptureEntities.DatabasePath = sPath;
            using (CryptureEntities oContext = new())
                foreach (Item oItem in oContext.Items.Include(i => i.Cipher).Include(i => i.Instances)
                    .ThenInclude(i => i.User).ToList()) ValidateConcurrentItem(oItem, oCert, oOtherCert);
            using SqliteConnection oConnection = new(CryptureEntities.ConnectionString);
            oConnection.Open();
            using SqliteCommand oCommand = new("PRAGMA integrity_check", oConnection);
            if (!String.Equals(oCommand.ExecuteScalar(), "ok")) throw new Exception("Vault integrity check failed.");
            oCommand.CommandText = "PRAGMA foreign_key_check";
            using SqliteDataReader oReader = oCommand.ExecuteReader();
            if (oReader.Read()) throw new Exception("Vault contains orphaned records.");
        }
        finally
        {
            CryptureEntities.ConnectionString = sPreviousConnection;
        }
    }

    private static void WaitForConcurrentCondition(Func<bool> oReady)
    {
        Stopwatch oWatch = Stopwatch.StartNew();
        while (!oReady())
        {
            if (oWatch.Elapsed.TotalSeconds > 90) throw new TimeoutException("Concurrent clients did not finish.");
            Thread.Sleep(25);
        }
    }
}
