using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Crypture
{
    internal sealed record DirectoryAccount(string Name, string Account, string Type, string Domain,
        string Sid, string DistinguishedName, byte[][] Certificates);

    internal sealed record DirectorySearchResult(string Forest, List<DirectoryAccount> Accounts, bool Truncated);

    internal static class ForestDirectory
    {
        internal const int MaxResults = 500;

        internal static string BuildFilter(string sQuery, bool bUsersOnly, bool bExact = false)
        {
            sQuery = sQuery?.Trim();
            if (String.IsNullOrEmpty(sQuery) || sQuery.Length > 256)
                throw new InvalidOperationException("Enter a name, account, UPN, or SID (up to 256 characters).");
            if (sQuery.Contains('\\'))
                sQuery = new NTAccount(sQuery).Translate(typeof(SecurityIdentifier)).Value;

            // Escape filter values so account names cannot change the LDAP query.
            string sMatch;
            if (sQuery.StartsWith("S-", StringComparison.OrdinalIgnoreCase))
            {
                SecurityIdentifier oSid = new SecurityIdentifier(sQuery);
                byte[] oBytes = new byte[oSid.BinaryLength];
                oSid.GetBinaryForm(oBytes, 0);
                sMatch = "(objectSid=" + String.Concat(oBytes.Select(b => "\\" + b.ToString("x2"))) + ")";
            }
            else
            {
                string sValue = sQuery.Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28")
                    .Replace(")", "\\29").Replace("\0", "\\00");
                string sPattern = bExact ? sValue : "*" + sValue + "*";
                sMatch = "(|(displayName=" + sPattern + ")(name=" + sPattern + ")(sAMAccountName=" +
                    sPattern + ")(userPrincipalName=" + sPattern + ")(distinguishedName=" + sValue + "))";
            }
            string sTypes = bUsersOnly ? "(&(objectCategory=person)(objectClass=user))" :
                "(|(&(objectCategory=person)(objectClass=user))(objectClass=computer)" +
                "(&(objectCategory=group)(groupType:1.2.840.113556.1.4.803:=2147483648)))";
            return "(&(objectSid=*)" + sTypes + sMatch + ")";
        }

        internal static DirectorySearchResult Search(string sQuery, bool bUsersOnly, CancellationToken oToken,
            bool bExact = false)
        {
            oToken.ThrowIfCancellationRequested();
            string sFilter = BuildFilter(sQuery, bUsersOnly, bExact);

            // A Global Catalog search without a domain DN includes every domain and tree in the forest.
            using Domain oDomain = Domain.GetComputerDomain();
            using Forest oForest = oDomain.Forest;
            using GlobalCatalog oCatalog = oForest.FindGlobalCatalog();
            using DirectorySearcher oSearcher = oCatalog.GetDirectorySearcher();
            using DirectoryEntry oRoot = oSearcher.SearchRoot;
            oSearcher.Filter = sFilter;
            oSearcher.SearchScope = SearchScope.Subtree;
            oSearcher.ReferralChasing = ReferralChasingOption.None;
            oSearcher.PageSize = 100;
            oSearcher.SizeLimit = MaxResults + 1;
            oSearcher.ServerTimeLimit = TimeSpan.FromSeconds(15);
            oSearcher.ClientTimeout = TimeSpan.FromSeconds(20);
            oSearcher.PropertiesToLoad.AddRange(["displayName", "name", "sAMAccountName", "userPrincipalName",
                "objectClass", "objectSid", "distinguishedName"]);
            if (bUsersOnly) oSearcher.PropertiesToLoad.Add("userCertificate");
            oToken.ThrowIfCancellationRequested();
            using SearchResultCollection oMatches = oSearcher.FindAll();
            List<DirectoryAccount> oAccounts = [];
            bool bTruncated = false;
            foreach (SearchResult oMatch in oMatches)
            {
                oToken.ThrowIfCancellationRequested();
                if (oAccounts.Count == MaxResults) { bTruncated = true; break; }
                if (oMatch.Properties["objectSid"].Count == 0) continue;
                string Field(string sName) => oMatch.Properties[sName].Count == 0 ? "" :
                    Convert.ToString(oMatch.Properties[sName][0]);
                string sDn = Field("distinguishedName");
                string sDns = String.Join(".", Regex.Matches(sDn, @"(?i)(?:^|(?<!\\),)DC=([^,]+)")
                    .Select(m => m.Groups[1].Value));
                string[] oClasses = oMatch.Properties["objectClass"].Cast<string>().ToArray();
                string sType = oClasses.Contains("group") ? "Security Group" :
                    oClasses.Any(c => c.Contains("ManagedServiceAccount", StringComparison.OrdinalIgnoreCase))
                        ? "Service Account" : oClasses.Contains("computer") ? "Computer" : "User";
                string sAccount = Field("userPrincipalName");
                if (String.IsNullOrEmpty(sAccount)) sAccount = sDns + "\\" + Field("sAMAccountName");
                string sName = Field("displayName");
                string sSid = new SecurityIdentifier((byte[])oMatch.Properties["objectSid"][0], 0).Value;
                byte[][] oCertificates = bUsersOnly ? oMatch.Properties["userCertificate"].OfType<byte[]>()
                    .Select(c => c.ToArray()).ToArray() : [];
                oAccounts.Add(new DirectoryAccount(String.IsNullOrEmpty(sName) ? Field("name") : sName,
                    sAccount, sType, sDns, sSid, sDn, oCertificates));
            }
            oToken.ThrowIfCancellationRequested();
            return new DirectorySearchResult(oForest.Name, oAccounts.OrderBy(a => a.Name,
                StringComparer.OrdinalIgnoreCase).ThenBy(a => a.Domain).ToList(), bTruncated);
        }

        internal static ProtectionPrincipal ResolvePrincipal(string sAccount,
            Func<string, DirectorySearchResult> oSearch = null)
        {
            DirectorySearchResult oResult = oSearch != null ? oSearch(sAccount) :
                Search(sAccount, false, CancellationToken.None, true);
            if (oResult.Truncated || oResult.Accounts.Count != 1)
                throw new InvalidOperationException(oResult.Accounts.Count == 0 ?
                    "No matching Windows principal was found in the forest." :
                    "More than one principal matches. Use Browse to select the intended account and domain.");
            DirectoryAccount oAccount = oResult.Accounts[0];
            return new ProtectionPrincipal(oAccount.Sid, oAccount.Account);
        }
    }

    public partial class DirectoryPicker : Window
    {
        private readonly bool bUsersOnly;
        private readonly int nSelectionLimit;
        private readonly Func<string, bool, CancellationToken, DirectorySearchResult> oSearch;
        private CancellationTokenSource oCancellation;
        private bool bClosed;
        internal IReadOnlyList<DirectoryAccount> SelectedAccounts { get; private set; } = [];

        internal DirectoryPicker(bool bCertificates = false, int nLimit = PrincipalProtection.MaxPrincipals,
            Func<string, bool, CancellationToken, DirectorySearchResult> oFind = null)
        {
            if (nLimit < 1) throw new InvalidOperationException("An item can have up to 100 Windows principals.");
            InitializeComponent();
            bUsersOnly = bCertificates;
            nSelectionLimit = nLimit;
            oSearch = oFind ?? ((s, b, t) => ForestDirectory.Search(s, b, t));
            if (bCertificates) Title = oHeading.Text = "Choose Certificate Owners";
            oQuery.Focus();
        }

        private async void oSearchButton_Click(object sender, RoutedEventArgs e) => await SearchAsync();

        internal async Task SearchAsync()
        {
            if (oCancellation != null || bClosed) return;
            if (String.IsNullOrWhiteSpace(oQuery.Text))
            {
                oStatus.Text = "Enter a name, account, UPN, or SID to search.";
                oQuery.Focus();
                return;
            }
            string sQuery = oQuery.Text.Trim();
            oCancellation = new CancellationTokenSource();
            CancellationToken oToken = oCancellation.Token;
            oQuery.IsEnabled = oSearchButton.IsEnabled = oAddButton.IsEnabled = false;
            oCancelSearchButton.IsEnabled = true;
            oResults.ItemsSource = null;
            oStatus.Text = "Searching the entire forest...";
            try
            {
                DirectorySearchResult oResult = await Task.Run(() => oSearch(sQuery, bUsersOnly, oToken));
                oToken.ThrowIfCancellationRequested();
                if (bClosed) return;
                oResults.ItemsSource = oResult.Accounts;
                oStatus.Text = oResult.Forest + ": " + (oResult.Truncated ?
                    "Showing the first 500 matches. Refine the search to see other results." :
                    oResult.Accounts.Count + " matches.");
            }
            catch (OperationCanceledException)
            {
                if (!bClosed) oStatus.Text = "Search canceled.";
            }
            catch (Exception oError)
            {
                if (!bClosed) oStatus.Text = "Search could not complete. " + oError.GetBaseException().Message;
            }
            finally
            {
                oCancellation.Dispose();
                oCancellation = null;
                if (!bClosed)
                {
                    oQuery.IsEnabled = oSearchButton.IsEnabled = true;
                    oCancelSearchButton.IsEnabled = false;
                    oResults_SelectionChanged(null, null);
                }
            }
        }

        private void oResults_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (oAddButton == null) return;
            int nSelected = oResults.SelectedItems.Count;
            oAddButton.IsEnabled = oCancellation == null && nSelected > 0 && nSelected <= nSelectionLimit;
            oSelection.Text = nSelected + " Selected (Maximum " + nSelectionLimit + ")";
        }

        private void oAddButton_Click(object sender, RoutedEventArgs e)
        {
            if (!oAddButton.IsEnabled || bClosed) return;
            SelectedAccounts = oResults.SelectedItems.Cast<DirectoryAccount>().ToArray();
            DialogResult = true;
        }

        private void oResults_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (ItemsControl.ContainerFromElement(oResults, e.OriginalSource as DependencyObject) is DataGridRow)
                oAddButton_Click(sender, e);
        }

        private void oCancelSearchButton_Click(object sender, RoutedEventArgs e) => oCancellation?.Cancel();

        private void oWindow_Closed(object sender, EventArgs e)
        {
            bClosed = true;
            oCancellation?.Cancel();
        }
    }
}
