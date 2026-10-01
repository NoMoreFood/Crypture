using System;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestDirectoryResolution()
    {
        // Check real Windows resolution and filter inputs that would otherwise broaden an LDAP search.
        string sFilter = ForestDirectory.BuildFilter("alice)(|(objectSid=*))(", false);
        Check(sFilter.Contains(@"alice\29\28|\28objectSid=\2a\29\29\28") &&
            !sFilter.Contains("alice)(|"), "Forest searches escape LDAP filter injection");
        Check(ForestDirectory.BuildFilter("Jörg*", true).Contains(@"Jörg\2a") &&
            !ForestDirectory.BuildFilter("Jörg", true).Contains("objectCategory=group"),
            "Certificate owner searches preserve Unicode and select only user objects");
        Check(ForestDirectory.BuildFilter("alex", false).Contains("groupType:1.2.840.113556.1.4.803:=2147483648") &&
            ForestDirectory.BuildFilter("alex", false).Contains("objectClass=computer"),
            "Principal searches include computers and require security-enabled groups");
        Check(ForestDirectory.BuildFilter("alex", false, true).Contains("(sAMAccountName=alex)") &&
            !ForestDirectory.BuildFilter("alex", false, true).Contains("*alex*"),
            "Typed forest resolution requires an exact account match");
        Check(ForestDirectory.BuildFilter("S-1-1-0", false)
            .Contains(@"(objectSid=\01\01\00\00\00\00\00\01\00\00\00\00)"),
            "SID searches use an exact binary LDAP match");
        using (WindowsIdentity oIdentity = WindowsIdentity.GetCurrent())
            Check(ForestDirectory.BuildFilter(oIdentity.Name, false) ==
                ForestDirectory.BuildFilter(oIdentity.User.Value, false),
                "Qualified Windows accounts search by their resolved SID");
        Reject(() => ForestDirectory.BuildFilter(" ", false), "Reject a blank forest search");
        Reject(() => ForestDirectory.BuildFilter(new string('x', 257), false), "Bound forest query length");
        Reject(() => ForestDirectory.BuildFilter("S-1-invalid", false), "Reject invalid SID searches");
        Reject(() => ForestDirectory.Search("alex", false, new CancellationToken(true)),
            "Canceled searches do not start directory discovery");

        DirectoryAccount oFirst = new("Alex", "alex@child.example.test", "User", "child.example.test",
            "S-1-5-21-1-2-3-1000", "CN=Alex,DC=child,DC=example,DC=test", []);
        DirectoryAccount oOther = new("Alex", "alex@other.test", "Security Group", "other.test",
            "S-1-5-21-4-5-6-1000", "CN=Alex,DC=other,DC=test", []);
        DirectorySearchResult oResult = new("example.test", [oFirst, oOther], false);
        Reject(() => ForestDirectory.ResolvePrincipal("alex", s => oResult),
            "Ambiguous forest accounts require an explicit selection");
        Reject(() => ForestDirectory.ResolvePrincipal("missing", s => new("example.test", [], false)),
            "A missing forest account does not resolve");
        ProtectionPrincipal oPrincipal = ForestDirectory.ResolvePrincipal("alex", s =>
            new("example.test", [oFirst], false));
        Check(oPrincipal.Sid == oFirst.Sid && oPrincipal.Name == oFirst.Account,
            "Forest resolution retains the selected domain account and SID");

        string sLiveQuery = Environment.GetEnvironmentVariable("CRYPTURE_TEST_FOREST_QUERY");
        if (!PrincipalProtection.IsDomainJoined || String.IsNullOrWhiteSpace(sLiveQuery))
        {
            Console.WriteLine("SKIP: Live forest searches require domain membership and CRYPTURE_TEST_FOREST_QUERY.");
            return;
        }
        DirectorySearchResult oLive = ForestDirectory.Search(sLiveQuery, false, CancellationToken.None);
        Check(oLive.Accounts.Count > 0 && oLive.Accounts.All(a => new SecurityIdentifier(a.Sid).IsAccountSid()),
            "A live forest search returns directory accounts with valid SIDs");
    }
}
