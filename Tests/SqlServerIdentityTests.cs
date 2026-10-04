using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using Crypture;
using Microsoft.Data.SqlClient;

internal static partial class RegressionTests
{
    private sealed record SqlIdentityFixture(string ConnectionString, string RecipientSid, string UnrelatedSid,
        string MemberGroupSid, string AccessGroupSid, long OwnerUserId, long RecipientUserId,
        long OwnerOnlyItemId, long DirectItemId, long GroupItemId, long RevocableItemId);

    private static int RunSqlServerIdentityTests(string sRole)
    {
        if (sRole == "help")
        {
            Console.WriteLine("Use a dedicated domain SQL server and three separate Windows sessions: " +
                "owner, recipient, and unrelated. Set CRYPTURE_TEST_AD_ROLE to the session's role.");
            Console.WriteLine("Set CRYPTURE_TEST_AD_FIXTURE to the same new JSON path in a shared writable folder.");
            Console.WriteLine("For the owner, set CRYPTURE_TEST_SQLSERVER, CRYPTURE_TEST_AD_RECIPIENT, " +
                "CRYPTURE_TEST_AD_UNRELATED, CRYPTURE_TEST_AD_MEMBER_GROUP, and CRYPTURE_TEST_AD_ACCESS_GROUP.");
            Console.WriteLine("The recipient must belong to MEMBER_GROUP, nested inside ACCESS_GROUP, " +
                "without direct ACCESS_GROUP membership. The unrelated account must belong to neither group.");
            return 0;
        }
        string sFixture = Environment.GetEnvironmentVariable("CRYPTURE_TEST_AD_FIXTURE");
        try
        {
            if (!PrincipalProtection.IsDomainJoined)
                throw new InvalidOperationException("AD identity tests require a domain-joined Windows machine.");
            if (String.IsNullOrWhiteSpace(sFixture))
                throw new InvalidOperationException("Set CRYPTURE_TEST_AD_FIXTURE to a new JSON file in a folder " +
                    "that the owner, recipient, and unrelated Windows accounts can read and write.");
            if (sRole == "owner") CreateSqlIdentityFixture(Path.GetFullPath(sFixture));
            else if (sRole is "recipient" or "unrelated") ProbeSqlIdentityFixture(sRole, Path.GetFullPath(sFixture));
            else throw new InvalidOperationException("CRYPTURE_TEST_AD_ROLE must be owner, recipient, or unrelated.");
            Console.WriteLine("Completed " + nChecks + " real Windows identity checks for " + sRole + ".");
            return 0;
        }
        catch (Exception oError)
        {
            Console.Error.WriteLine(oError.Message);
            if (sRole is "recipient" or "unrelated" && !String.IsNullOrWhiteSpace(sFixture))
                File.WriteAllText(sFixture + "." + sRole + ".failed", oError.Message);
            return 1;
        }
    }

    private static void CreateSqlIdentityFixture(string sFixturePath)
    {
        string ReadSid(string sVariable)
        {
            string sAccount = Environment.GetEnvironmentVariable(sVariable);
            if (String.IsNullOrWhiteSpace(sAccount)) throw new InvalidOperationException("Set " + sVariable +
                " to an existing dedicated AD test account or security group.");
            return ((SecurityIdentifier)new NTAccount(sAccount).Translate(typeof(SecurityIdentifier))).Value;
        }

        // Explicit account names select the test identities without collecting credentials or changing AD.
        string sRecipient = ReadSid("CRYPTURE_TEST_AD_RECIPIENT");
        string sUnrelated = ReadSid("CRYPTURE_TEST_AD_UNRELATED");
        string sMemberGroup = ReadSid("CRYPTURE_TEST_AD_MEMBER_GROUP");
        string sAccessGroup = ReadSid("CRYPTURE_TEST_AD_ACCESS_GROUP");
        string sOwner = WindowsIdentity.GetCurrent().User.Value;
        if (new[] { sOwner, sRecipient, sUnrelated, sMemberGroup, sAccessGroup }.Distinct().Count() != 5)
            throw new InvalidOperationException("Use distinct owner, recipient, unrelated, and nested " +
                "group identities.");
        if (File.Exists(sFixturePath)) throw new IOException("Choose a new AD fixture file for this test run.");
        string sServer = Environment.GetEnvironmentVariable("CRYPTURE_TEST_SQLSERVER");
        if (String.IsNullOrWhiteSpace(sServer))
            throw new InvalidOperationException("Set CRYPTURE_TEST_SQLSERVER to the dedicated SQL test server's " +
                "Windows-authenticated connection string.");
        SqlConnectionStringBuilder oBuilder = new SqlConnectionStringBuilder(sServer)
        {
            InitialCatalog = "CryptureIdentityTest_" + Guid.NewGuid().ToString("N"), Pooling = false
        };
        using RSA oKey = RSA.Create(2048);
        using X509Certificate2 oOwnerCert = Certificate(oKey, "AD owner", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1));
        using X509Certificate2 oRecipientCert = Certificate(oKey, "AD recipient", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1));
        using X509Certificate2 oGroupCert = Certificate(oKey, "AD nested group", DateTimeOffset.Now.AddDays(-1),
            DateTimeOffset.Now.AddDays(1));
        SqlServerVaultStorage oStorage = new SqlServerVaultStorage(oBuilder.ConnectionString)
        {
            EscrowChoice = SqlServerEscrowChoice.ForCertificate(oOwnerCert.RawData, sOwner, "AD test owner")
        };
        bool bCreated = false;
        try
        {
            oStorage.Create();
            bCreated = true;
            long nOwner = oStorage.Escrow.CertificateUserId.Value;
            long nRecipient = EnrollTestCertificate(oStorage, oRecipientCert.RawData, sRecipient);
            long nGroup = EnrollTestCertificate(oStorage, oGroupCert.RawData, sAccessGroup);
            User oOwner = new User { UserId = nOwner, Certificate = oOwnerCert.RawData, Sid = sOwner };
            User oRecipient = new User { UserId = nRecipient, Certificate = oRecipientCert.RawData, Sid = sRecipient };
            User oGroup = new User { UserId = nGroup, Certificate = oGroupCert.RawData, Sid = sAccessGroup };
            long Save(string sLabel, params User[] oRecipients)
            {
                Item oItem = new Item { Label = sLabel, ItemType = "text" };
                Item oEncrypted = new Item();
                ItemCryptography.Encrypt(oEncrypted, Encoding.Unicode.GetBytes(sLabel), oRecipients);
                SqlServerItemOperations.Save(oStorage, oItem, oEncrypted);
                return oItem.ItemId;
            }
            SqlIdentityFixture oFixture = new SqlIdentityFixture(oStorage.ConnectionString, sRecipient, sUnrelated,
                sMemberGroup, sAccessGroup, nOwner, nRecipient, Save("Owner only", oOwner),
                Save("Direct recipient", oOwner, oRecipient), Save("Nested group", oOwner, oGroup),
                Save("Revocable recipient", oOwner, oRecipient));
            using (FileStream oFile = new FileStream(sFixturePath, FileMode.CreateNew))
                JsonSerializer.Serialize(oFile, oFixture, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine("Fixture ready: " + sFixturePath);
            Console.WriteLine("Run this test executable in separate recipient and unrelated Windows sessions. " +
                "Set CRYPTURE_TEST_AD_FIXTURE to that path and CRYPTURE_TEST_AD_ROLE to recipient or unrelated.");
            WaitForIdentitySignal(sFixturePath, "recipient.ready");
            WaitForIdentitySignal(sFixturePath, "unrelated.done");

            // Revoke an existing recipient while its real Windows SQL session stays connected.
            CryptureEntities.Storage = oStorage;
            Item oRevoked = DatabaseOperations.LoadItem(oFixture.RevocableItemId);
            Item oOwnerOnly = new Item();
            ItemCryptography.Encrypt(oOwnerOnly, Encoding.Unicode.GetBytes("Recipient access revoked"),
                new[] { oOwner });
            SqlServerItemOperations.Save(oStorage, oRevoked, oOwnerOnly);
            File.WriteAllText(sFixturePath + ".revoked", "Recipient removed from the saved access paths.");
            WaitForIdentitySignal(sFixturePath, "recipient.done");
            Check(true, "Separate AD users verify direct, nested group, and revoked recipient access");
        }
        finally
        {
            if (bCreated)
            {
                SqlConnectionStringBuilder oMaster = new SqlConnectionStringBuilder(sServer)
                    { InitialCatalog = "master", Pooling = false };
                using SqlConnection oConnection = new SqlConnection(oMaster.ConnectionString);
                oConnection.Open();
                using SqlCommand oDrop = new SqlCommand("ALTER DATABASE [" + oBuilder.InitialCatalog +
                    "] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [" + oBuilder.InitialCatalog + "]",
                    oConnection);
                oDrop.ExecuteNonQuery();
            }
        }
    }

    private static void ProbeSqlIdentityFixture(string sRole, string sFixturePath)
    {
        SqlIdentityFixture oFixture = JsonSerializer.Deserialize<SqlIdentityFixture>(File.ReadAllText(sFixturePath));
        string sExpected = sRole == "recipient" ? oFixture.RecipientSid : oFixture.UnrelatedSid;
        using WindowsIdentity oIdentity = WindowsIdentity.GetCurrent();
        Check(oIdentity.User.Value == sExpected, "The probe runs under its designated Windows account");
        SqlServerVaultStorage oStorage = new SqlServerVaultStorage(oFixture.ConnectionString);
        string sDatabase = oStorage.DatabaseName;
        const string sPrefix = "CryptureIdentityTest_";
        if (!sDatabase.StartsWith(sPrefix, StringComparison.Ordinal) ||
            !Guid.TryParseExact(sDatabase.Substring(sPrefix.Length), "N", out _))
            throw new InvalidOperationException("Identity probes require a temporary database created by " +
                "the owner test.");
        CryptureEntities.Storage = oStorage;
        using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
        oConnection.Open();
        using (SqlCommand oCommand = new SqlCommand("SELECT SUSER_SID(ORIGINAL_LOGIN()), " +
            "IS_ROLEMEMBER(N'db_owner'), IS_SRVROLEMEMBER(N'sysadmin')", oConnection))
        using (SqlDataReader oReader = oCommand.ExecuteReader())
        {
            oReader.Read();
            Check(new SecurityIdentifier((byte[])oReader[0], 0).Value == sExpected,
                "SQL Server authenticates the actual Windows login used by the probe");
            Check(oReader.GetInt32(1) == 0 && oReader.GetInt32(2) == 0,
                "The real user has no database owner or server administrator bypass");
        }
        WindowsPrincipal oPrincipal = new WindowsPrincipal(oIdentity);
        bool bRecipient = sRole == "recipient";
        Check(oPrincipal.IsInRole(new SecurityIdentifier(oFixture.AccessGroupSid)) == bRecipient,
            "Only the recipient's Windows token includes the nested access group");
        if (bRecipient)
        {
            Check(oPrincipal.IsInRole(new SecurityIdentifier(oFixture.MemberGroupSid)),
                "The recipient's Windows token includes the nested member group");
            var oOuter = ReadAdMembership(oFixture.AccessGroupSid);
            var oInner = ReadAdMembership(oFixture.MemberGroupSid);
            var oUser = ReadAdMembership(sExpected);
            Check(oOuter.Members.Contains(oInner.Dn, StringComparer.OrdinalIgnoreCase) &&
                !oOuter.Members.Contains(oUser.Dn, StringComparer.OrdinalIgnoreCase),
                "The access group contains the member group rather than a direct recipient membership");
        }
        Check(CountIdentityRows(oConnection, "Item", oFixture.DirectItemId) == (bRecipient ? 1 : 0) &&
            CountIdentityRows(oConnection, "Item", oFixture.GroupItemId) == (bRecipient ? 1 : 0),
            "Real Windows affiliation controls direct and nested group item visibility");

        // Direct table writes must stay unavailable even when an affiliated row is visible.
        foreach (string sStatement in new[]
        {
            "INSERT INTO Item (Label) VALUES (N'Unverified direct insert')",
            "UPDATE Item SET Label = N'Unverified direct update' WHERE ItemId = @id",
            "DELETE FROM Item WHERE ItemId = @id"
        })
        {
            using SqlCommand oCommand = new SqlCommand(sStatement, oConnection);
            oCommand.Parameters.AddWithValue("@id", oFixture.DirectItemId);
            bool bDenied = false;
            try { oCommand.ExecuteNonQuery(); }
            catch (SqlException oError) when (oError.Number == 229) { bDenied = true; }
            Check(bDenied, "The real Windows login cannot bypass the mutation procedures with a direct table write");
        }
        AssertIdentityDenied(oConnection, oStorage, oFixture, oFixture.OwnerOnlyItemId);
        if (!bRecipient)
        {
            AssertIdentityDenied(oConnection, oStorage, oFixture, oFixture.DirectItemId);
            AssertIdentityDenied(oConnection, oStorage, oFixture, oFixture.GroupItemId);
            File.WriteAllText(sFixturePath + ".unrelated.done", "Unrelated access rejected.");
            return;
        }

        // Use ordinary mutation procedures from a separately authenticated, non-owner Windows account.
        Item oDirect = DatabaseOperations.LoadItem(oFixture.DirectItemId);
        oDirect.Label = "Updated by the real recipient";
        oDirect.ModifiedBy = null;
        SqlServerItemOperations.Save(oStorage, oDirect, oDirect);
        Check(DatabaseOperations.LoadItem(oDirect.ItemId).Label == oDirect.Label,
            "A separately authenticated recipient can modify its associated row");
        Item oTransient = new Item { Label = "Created by the real recipient", ItemType = "text" };
        SqlServerItemOperations.Save(oStorage, oTransient, oDirect);
        DatabaseOperations.DeleteItem(DatabaseOperations.LoadItem(oTransient.ItemId));
        Check(CountIdentityRows(oConnection, "Item", oTransient.ItemId) == 0,
            "A separately authenticated recipient can add and delete its associated row");
        Item oBeforeRevocation = DatabaseOperations.LoadItem(oFixture.RevocableItemId);
        File.WriteAllText(sFixturePath + ".recipient.ready", "Recipient SQL session remains connected.");
        WaitForIdentitySignal(sFixturePath, "revoked");
        AssertIdentityDenied(oConnection, oStorage, oFixture, oFixture.RevocableItemId, oBeforeRevocation);
        using SqlConnection oFresh = new SqlConnection(oStorage.ConnectionString);
        oFresh.Open();
        Check(CountIdentityRows(oFresh, "Item", oFixture.RevocableItemId) == 0,
            "Revocation also applies to a freshly authenticated Windows SQL session");
        File.WriteAllText(sFixturePath + ".recipient.done", "Revoked access rejected.");
    }

    private static void AssertIdentityDenied(SqlConnection oConnection, SqlServerVaultStorage oStorage,
        SqlIdentityFixture oFixture, long nItemId, Item oSaved = null)
    {
        Check(CountIdentityRows(oConnection, "Item", nItemId) == 0 &&
            CountIdentityRows(oConnection, "AuthorizedCipher", nItemId) == 0 &&
            CountIdentityRows(oConnection, "AuthorizedInstance", nItemId) == 0,
            "An unaffiliated real Windows login cannot read item, ciphertext, or recipient rows");
        Item oProbe = oSaved ?? new Item { ItemId = nItemId, RowVersion = new byte[8] };
        oProbe.Label = "Unaffiliated write probe";
        oProbe.ItemType = "text";
        oProbe.ModifiedBy = null;
        Item oEncrypted = new Item
        {
            Cipher = new Cipher
            {
                CipherParams = 3, ContentSuite = 1, CipherText = new byte[] { 1 },
                CipherVector = new byte[12], AuthenticationTag = new byte[16]
            }
        };
        oEncrypted.Instances.Add(new Instance
        {
            UserId = oFixture.OwnerUserId, CipherParams = 3, CipherKey = new byte[8], Signature = new byte[32]
        });
        foreach (bool bDelete in new[] { true, false })
        {
            bool bDenied = false;
            try
            {
                if (bDelete) SqlServerItemOperations.Delete(oStorage, oProbe);
                else SqlServerItemOperations.Save(oStorage, oProbe, oEncrypted);
            }
            catch (SqlException oError) when (oError.Number == 50011) { bDenied = true; }
            Check(bDenied, "An unaffiliated real Windows login cannot " + (bDelete ? "delete" : "modify") +
                " the protected row");
        }
    }

    private static int CountIdentityRows(SqlConnection oConnection, string sView, long nItemId)
    {
        using SqlCommand oCommand = new SqlCommand("SELECT COUNT(*) FROM [dbo].[" + sView +
            "] WHERE [ItemId] = @id", oConnection);
        oCommand.Parameters.AddWithValue("@id", nItemId);
        return (int)oCommand.ExecuteScalar();
    }

    private static (string Dn, string[] Members) ReadAdMembership(string sSid)
    {
        SecurityIdentifier oSid = new SecurityIdentifier(sSid);
        byte[] oBytes = new byte[oSid.BinaryLength];
        oSid.GetBinaryForm(oBytes, 0);
        using DirectoryEntry oRoot = new DirectoryEntry("LDAP://RootDSE");
        using DirectoryEntry oDomain = new DirectoryEntry("LDAP://" +
            (string)oRoot.Properties["defaultNamingContext"].Value);
        using DirectorySearcher oSearch = new DirectorySearcher(oDomain)
        {
            Filter = "(objectSid=" + String.Concat(oBytes.Select(b => "\\" + b.ToString("X2"))) + ")"
        };
        oSearch.PropertiesToLoad.Add("distinguishedName");
        oSearch.PropertiesToLoad.Add("member");
        SearchResult oResult = oSearch.FindOne() ??
            throw new InvalidOperationException("The AD test identity is missing.");
        return ((string)oResult.Properties["distinguishedName"][0],
            oResult.Properties["member"].Cast<string>().ToArray());
    }

    private static void WaitForIdentitySignal(string sFixture, string sSignal)
    {
        Stopwatch oWait = Stopwatch.StartNew();
        while (!File.Exists(sFixture + "." + sSignal))
        {
            foreach (string sRole in new[] { "recipient", "unrelated" })
                if (File.Exists(sFixture + "." + sRole + ".failed"))
                    throw new InvalidOperationException("The " + sRole + " Windows identity probe failed.");
            if (oWait.Elapsed > TimeSpan.FromMinutes(5))
                throw new TimeoutException("Timed out waiting for the " + sSignal + " Windows identity probe.");
            Thread.Sleep(250);
        }
    }
}
