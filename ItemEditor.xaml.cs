﻿using Fluent;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data.Entity;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Interop;

namespace Crypture
{
    public partial class ItemEditor : RibbonWindow
    {
        public string CurrentUserSid { get; set; } = WindowsIdentity.GetCurrent().User.Value;
        public bool IsEditable { get; set; }
        public Item ThisItem { get; set; } = new Item();
        public ObservableCollection<User> UserList { get; set; } = new ObservableCollection<User>();
        public ObservableCollection<User> UserListSelected { get; set; } = new ObservableCollection<User>();

        public ItemEditor(bool bNewItem = true)
        {
            ThisItem.Label = "My New Item";
            DataContext = ThisItem;
            InitializeComponent();

            // setup sorting for the drop down list of certs
            oItemSharedWith.Items.IsLiveSorting = true;
            oItemSharedWith.Items.SortDescriptions.Add(
                new SortDescription(oItemSharedWith.DisplayMemberPath, ListSortDirection.Ascending));

            // setup sorting for the shared with list
            oAddCertDropDown.Items.IsLiveSorting = true;
            oAddCertDropDown.Items.SortDescriptions.Add(
                new SortDescription(oAddCertDropDown.DisplayMemberPath, ListSortDirection.Ascending));

            // add in our keys by default
            if (bNewItem) using (CryptureEntities oContent = new CryptureEntities())
                {
                    UserList = new ObservableCollection<User>(oContent.Users.ToList<User>());
                    UserListSelected = new ObservableCollection<User>(oContent.Users.Where(
                        u => u.Sid == CurrentUserSid));
                    if (UserListSelected.Count > 0)
                    {
                        ThisItem.ModifiedBy = UserListSelected[0].UserId;
                    }

                    // initialize the date values to something reasonable
                    ThisItem.CreatedDate = DateTime.MinValue;
                    ThisItem.ModifiedDate = DateTime.MinValue;

                    oItemSharedWith.ItemsSource = UserListSelected;
                    oAddCertDropDown.ItemsSource = UserList;
                }

            // set editing controls
            SetEditingControls(bNewItem);
        }

        public ItemEditor(Item oItem) : this(false)
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                // attach the passed item to the database context
                ThisItem = oItem;
                oContent.Entry(ThisItem).State = EntityState.Unchanged;
                oContent.Entry(ThisItem).Reload();

                // force visual refresh
                DataContext = ThisItem;

                // populate the full user list and the selected user list
                UserList = new ObservableCollection<User>(oContent.Users.ToList<User>());
                UserListSelected = new ObservableCollection<User>(
                    ThisItem.Instances.Select(i => i.User).Distinct());
                oItemSharedWith.ItemsSource = UserListSelected;
                oAddCertDropDown.ItemsSource = UserList;
            }
        }

        public void SetEditingControls(bool bEnabled)
        {
            // toggle what controls are available based on whether item item is decoded
            oAddCertDropDown.IsEnabled = bEnabled;
            oLoadItemButton.IsEnabled = !bEnabled;
            oSaveItemButton.IsEnabled = bEnabled;
            oItemData.IsEnabled = bEnabled;
            oTextLockImage.Visibility = (bEnabled) ? Visibility.Collapsed : Visibility.Visible;
            oItemData.Visibility = (bEnabled) ? Visibility.Visible : Visibility.Collapsed;
        }

        private void oSaveItemButton_Click(object sender, RoutedEventArgs e)
        {
            // update the entity using the local copy we have
            using (CryptureEntities oContent = new CryptureEntities())
            {
                oContent.Entry(ThisItem).State = (ThisItem.CreatedDate == DateTime.MinValue)
                    ? EntityState.Added : EntityState.Modified;

                // verify the selected users
                foreach (User oUser in UserListSelected.ToArray())
                {
                    using (X509Certificate2 oCert = new X509Certificate2(oUser.Certificate))
                    {
                        if (oCert.Verify() == false && MessageBox.Show(this,
                            "The certificate for '" + oUser.Name + "' cannot be verified. " +
                            ((oUser.IsSelfSigned) ? "This certificate appears to be self-signed. " : "") +
                            "Should this certificate be removed from the list?",
                            "Cannot Verify Certificate",
                            MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
                        {
                            // remove from list and force refresh
                            UserListSelected.Remove(oUser);
                            oAddCertDropDown.Items.Refresh();
                        }
                    }
                }

                // error if there are no selected users
                if (UserListSelected.Count == 0)
                {
                    MessageBox.Show(this, "This certificate share list is empty and cannot be saved.",
                        "Empty Certificates List", MessageBoxButton.OK, MessageBoxImage.Question);
                    return;
                }

                using (Aes oCng = Aes.Create())
                {
                    // create new cipher object and associate it with this id
                    ThisItem.Cipher = new Cipher();
                    ThisItem.Cipher.Item = ThisItem;

                    using (MemoryStream oMemory = new MemoryStream())
                    using (CryptoStream oCrypto = new CryptoStream(
                        oMemory, oCng.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] oPlainByte = Encoding.Unicode.GetBytes(oItemData.Text);
                        oCrypto.Write(oPlainByte, 0, oPlainByte.Length);
                        oCrypto.FlushFinalBlock();
                        ThisItem.Cipher.CipherText = oMemory.ToArray();
                    }

                    ThisItem.Cipher.CipherVector = oCng.IV;
                    ThisItem.CreatedDate = DateTime.Now;
                    ThisItem.ModifiedDate = DateTime.Now;

                    // clear out any existing instances
                    oContent.Instances.RemoveRange(ThisItem.Instances);

                    // encode each instance
                    foreach (User oUser in UserListSelected)
                    {
                        Instance oInstance = new Instance();
                        oInstance.Signature = new byte[] { };
                        oInstance.UserId = oUser.UserId;
                        oInstance.ItemId = ThisItem.ItemId;

                        byte[] oCipherByte = null;
                        using (X509Certificate2 oCert = new X509Certificate2(oUser.Certificate))
                        {
                            if (Environment.OSVersion.Version.CompareTo(new Version(6, 2)) >= 0)
                            {
                                // For Windows 8 And Later
                                using (RSA oRSA = oCert.GetRSAPublicKey())
                                {
                                    oCipherByte = oRSA.Encrypt(oCng.Key, RSAEncryptionPadding.Pkcs1);
                                }
                            }
                            else
                            {
                                // For Windows 7 And Earlier
                                using (RSACryptoServiceProvider oRSA = oCert.PublicKey.Key as RSACryptoServiceProvider)
                                {
                                    oCipherByte = oRSA.Encrypt(oCng.Key, false);
                                }
                            }
                        }

                        oInstance.CipherKey = oCipherByte;
                        ThisItem.Instances.Add(oInstance);
                    }
                }

                // commit changes to database
                oContent.SaveChanges();
            }

            // close and return to calling dialog
            Close();
        }

        private X509Certificate2 GetUserKey(IEnumerable<User> SourceUserList)
        {
            // open our local certificate store
            using (X509Store oStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                oStore.Open(OpenFlags.ReadOnly);

                // collate the database certificates to those locally available
                X509Certificate2Collection oMyCertCollection = new X509Certificate2Collection();
                foreach (X509Certificate2 oStoreUser in oStore.Certificates)
                {
                    foreach (User oUser in SourceUserList) if (oStoreUser.HasPrivateKey)
                    {
                        if (StructuralComparisons.StructuralEqualityComparer.Equals(
                            oUser.Certificate, oStoreUser.RawData))
                        {
                            oMyCertCollection.Add(oStoreUser);
                        }
                    }
                }

                // error if no valid local certification might be available local certif
                if (oMyCertCollection.Count == 0)
                {
                    MessageBox.Show(this,
                        "Could not find any certificates to decode this item.",
                        "Not Shared With You");
                    return null;
                }

                // allow the certificate
                X509Certificate2Collection oCollection = X509Certificate2UI.SelectFromCollection(oMyCertCollection,
                    "Select Certificate", "Select Certificate To Decode", X509SelectionFlag.SingleSelection,
                    new WindowInteropHelper(this).Handle);
                if (oCollection.Count == 0) return null;
                return oCollection[0];
            }
        }

        private void oLoadItemButton_Click(object sender, RoutedEventArgs e)
        {
            // select all the certs associated with this user
            X509Certificate2 oCert = GetUserKey(UserListSelected.Where<User>(u => u.IsOwnedByCurrentUser));
            if (oCert == null) return;

            using (CryptureEntities oContent = new CryptureEntities())
            {
                // reconnect our instance so we can lookup the cipher
                oContent.Entry(ThisItem).State = EntityState.Unchanged;

                // try to decode our current data
                foreach (Instance oInstance in ThisItem.Instances)
                {
                    // see if the cert associated with the instance matches the one in the store
                    if (StructuralComparisons.StructuralEqualityComparer.Equals(
                        oInstance.User.Certificate, oCert.RawData))
                    {
                        // setup an aes decryptor using the iv and decrypted key
                        using (Aes oCng = Aes.Create())
                        {
                            // setup the aes key using the decrypted rsa data
                            if (Environment.OSVersion.Version.CompareTo(new Version(6, 2)) >= 0)
                            {
                                using (RSA oRSA = oCert.GetRSAPrivateKey())
                                {
                                    oCng.Key = oRSA.Decrypt(oInstance.CipherKey, RSAEncryptionPadding.Pkcs1);
                                    oCng.IV = ThisItem.Cipher.CipherVector;
                                }
                            }
                            else
                            {
                                using (RSACryptoServiceProvider oRSA = oCert.PrivateKey as RSACryptoServiceProvider)
                                {
                                    oCng.Key = oRSA.Decrypt(oInstance.CipherKey, false);
                                    oCng.IV = ThisItem.Cipher.CipherVector;
                                }
                            }

                            // attempt to decode the data
                            using (MemoryStream oMemory = new MemoryStream())
                            using (CryptoStream oCrypto = new CryptoStream(
                                oMemory, oCng.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                oCrypto.Write(ThisItem.Cipher.CipherText, 0, ThisItem.Cipher.CipherText.Length);
                                oCrypto.FlushFinalBlock();
                                oItemData.Text = Encoding.Unicode.GetString(oMemory.ToArray());
                            }
                        }
                        // change the ui to allow saving again
                        SetEditingControls(true);
                    }
                }
            }
        }

        private void oRemoveCertButton_Click(object sender, RoutedEventArgs e)
        {
            using (CryptureEntities oContent = new CryptureEntities())
            {
                for (int iSelected = oItemSharedWith.SelectedItems.Count - 1; iSelected >= 0; iSelected--)
                {
                    UserList.Remove((User)oItemSharedWith.SelectedItems[iSelected]);
                }
            }
        }

        private void MenuItemWithRadioButtons_Click(object sender, RoutedEventArgs e)
        {
            Fluent.MenuItem oMenu = (Fluent.MenuItem)sender;
            User oUser = (User)oMenu.DataContext;
            bool bIsInList = UserListSelected.Contains(oUser);

            if (bIsInList) UserListSelected.Remove(oUser);
            else UserListSelected.Add(oUser);

            oMenu.IsChecked = !bIsInList;
        }

        private void oRemoveItemButton_Click(object sender, RoutedEventArgs e)
        {
            // confirm removal
            if (MessageBox.Show(this,
                    "Are you sure you want to remove this item?",
                    "Removal Confirmation", MessageBoxButton.YesNo,
                    MessageBoxImage.Question) != MessageBoxResult.Yes) return;

            using (CryptureEntities oContent = new CryptureEntities())
            {
                oContent.Entry(ThisItem).State = EntityState.Unchanged;
                oContent.Items.Remove(ThisItem);
                oContent.SaveChanges();
                Close();
            }
        }

        private void oRootWindow_Closing(object sender, CancelEventArgs e)
        {
            // force collection in case the user loaded a large set of text into memory
            GC.Collect();
        }
    }

    public class CheckIfItemIsSelectedConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            ItemEditor oViewer = (ItemEditor)values[0];
            User oUser = (User)values[1];
            return oViewer.UserListSelected.Contains(oUser);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }
    }

    public class CheckIfDateIsNotSetConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            return ((DateTime)value == DateTime.MinValue) ? "- Not Yet Set -" : value;
        }

        public object ConvertBack(object value, Type targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            return null;
        }
    }
}