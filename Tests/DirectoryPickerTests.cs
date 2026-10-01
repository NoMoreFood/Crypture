using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Crypture;

internal static partial class RegressionTests
{
    private static void TestDirectoryPicker()
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

        // Exercise the same asynchronous dialog used by both callers without requiring a live forest.
        using ManualResetEventSlim oEntered = new();
        using ManualResetEventSlim oRelease = new();
        string sCapturedQuery = null;
        bool bCapturedUsersOnly = true;
        DirectoryPicker oPicker = new(false, oFind: (s, b, t) =>
        {
            sCapturedQuery = s;
            bCapturedUsersOnly = b;
            oEntered.Set();
            oRelease.Wait(t);
            return oResult;
        });
        try
        {
            TextBox oQuery = (TextBox)oPicker.FindName("oQuery");
            Button oSearch = (Button)oPicker.FindName("oSearchButton");
            Button oAdd = (Button)oPicker.FindName("oAddButton");
            Button oCancel = (Button)oPicker.FindName("oCancelSearchButton");
            DataGrid oResults = (DataGrid)oPicker.FindName("oResults");
            TextBlock oStatus = (TextBlock)oPicker.FindName("oStatus");
            Task oEmpty = Application.Current.Dispatcher.Invoke(oPicker.SearchAsync);
            Check(oEmpty.IsCompleted && !oEntered.IsSet && !oAdd.IsEnabled,
                "An empty picker stays ready without searching or allowing an empty selection");
            oQuery.Text = "  alex  ";
            Task oRun = Application.Current.Dispatcher.Invoke(oPicker.SearchAsync);
            PumpUntil(() => oEntered.IsSet);
            Check(!oQuery.IsEnabled && !oSearch.IsEnabled && !oAdd.IsEnabled && oCancel.IsEnabled,
                "An active forest search keeps results unavailable and allows cancellation");
            Check(sCapturedQuery == "alex" && !bCapturedUsersOnly,
                "The principal picker searches the forest for the entered account");
            oRelease.Set();
            PumpUntil(() => oRun.IsCompleted);
            oRun.GetAwaiter().GetResult();
            Check(oResults.Items.Count == 2 && oStatus.Text.Contains("example.test: 2 matches") &&
                oQuery.IsEnabled && !oCancel.IsEnabled, "Forest results appear and searching becomes available again");
            oResults.SelectAll();
            Check(oAdd.IsEnabled && oResults.SelectedItems.Count == 2,
                "The picker can select identically named accounts from different forest domains");
            oPicker.WindowStartupLocation = WindowStartupLocation.Manual;
            oPicker.Left = oPicker.Top = -10000;
            oPicker.ShowActivated = false;
            oPicker.Dispatcher.BeginInvoke(new Action(() => oAdd.RaiseEvent(new RoutedEventArgs(Button.ClickEvent))));
            Check(oPicker.ShowDialog() == true && oPicker.SelectedAccounts.Select(a => a.Sid)
                .SequenceEqual(new[] { oFirst.Sid, oOther.Sid }),
                "Confirming the picker returns the selected principals and their distinct SIDs");
        }
        finally { oRelease.Set(); oPicker.Close(); }

        int nAttempts = 0;
        DirectoryPicker oOwners = new(true, 1, (s, b, t) =>
        {
            Check(b, "Certificate selection asks for forest users and certificate attributes");
            if (++nAttempts == 1) throw new InvalidOperationException("Directory Unavailable");
            return oResult with { Truncated = true };
        });
        try
        {
            ((TextBox)oOwners.FindName("oQuery")).Text = "alex";
            Task oRun = Application.Current.Dispatcher.Invoke(oOwners.SearchAsync);
            PumpUntil(() => oRun.IsCompleted);
            oRun.GetAwaiter().GetResult();
            Check(((TextBlock)oOwners.FindName("oStatus")).Text.Contains("Directory Unavailable") &&
                ((Button)oOwners.FindName("oSearchButton")).IsEnabled,
                "A directory failure is visible and permits retry");
            oRun = Application.Current.Dispatcher.Invoke(oOwners.SearchAsync);
            PumpUntil(() => oRun.IsCompleted);
            oRun.GetAwaiter().GetResult();
            Check(oOwners.Title == "Choose Certificate Owners" &&
                ((TextBlock)oOwners.FindName("oStatus")).Text.Contains("Refine the search"),
                "Certificate mode identifies itself and reports truncated searches");
            DataGrid oResults = (DataGrid)oOwners.FindName("oResults");
            oResults.SelectAll();
            Check(!((Button)oOwners.FindName("oAddButton")).IsEnabled,
                "Selecting more than the allowed principal count cannot be confirmed");
            oResults.SelectedItems.Remove(oOther);
            Check(((Button)oOwners.FindName("oAddButton")).IsEnabled,
                "Reducing selection to the allowed count restores confirmation");
        }
        finally { oOwners.Close(); }

        using ManualResetEventSlim oWaiting = new();
        DirectoryPicker oCanceled = new(oFind: (s, b, t) =>
        {
            oWaiting.Set();
            t.WaitHandle.WaitOne();
            t.ThrowIfCancellationRequested();
            return oResult;
        });
        try
        {
            ((TextBox)oCanceled.FindName("oQuery")).Text = "alex";
            Task oRun = Application.Current.Dispatcher.Invoke(oCanceled.SearchAsync);
            PumpUntil(() => oWaiting.IsSet);
            ((Button)oCanceled.FindName("oCancelSearchButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            PumpUntil(() => oRun.IsCompleted);
            oRun.GetAwaiter().GetResult();
            Check(((TextBlock)oCanceled.FindName("oStatus")).Text == "Search canceled." &&
                ((DataGrid)oCanceled.FindName("oResults")).Items.Count == 0 &&
                !((Button)oCanceled.FindName("oAddButton")).IsEnabled,
                "Canceling a search discards results and leaves no selectable stale principals");
        }
        finally { oCanceled.Close(); }

        using ManualResetEventSlim oLateRelease = new();
        CancellationToken oLateToken = default;
        DirectoryPicker oClosed = new(oFind: (s, b, t) =>
        {
            oLateToken = t;
            oLateRelease.Wait();
            return oResult;
        });
        ((TextBox)oClosed.FindName("oQuery")).Text = "alex";
        Task oLate = Application.Current.Dispatcher.Invoke(oClosed.SearchAsync);
        PumpUntil(() => oLateToken.CanBeCanceled);
        oClosed.Close();
        oLateRelease.Set();
        PumpUntil(() => oLate.IsCompleted);
        oLate.GetAwaiter().GetResult();
        Check(oLateToken.IsCancellationRequested && ((DataGrid)oClosed.FindName("oResults")).Items.Count == 0 &&
            oClosed.SelectedAccounts.Count == 0, "Closing the picker cancels and discards late directory results");

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
