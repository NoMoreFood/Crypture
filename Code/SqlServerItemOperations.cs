using System;
using System.Data;
using Microsoft.Data.SqlClient;

namespace Crypture
{
    internal static class SqlServerItemOperations
    {
        internal static void Save(SqlServerVaultStorage oStorage, Item oItem, Item oEncrypted)
        {
            Cipher oCipher = oEncrypted.Cipher;
            DataTable oRecipients = new DataTable();
            oRecipients.Columns.Add("UserId", typeof(long));
            oRecipients.Columns.Add("CipherKey", typeof(byte[]));
            oRecipients.Columns.Add("CipherParams", typeof(long));
            oRecipients.Columns.Add("Signature", typeof(byte[]));
            foreach (Instance oInstance in oEncrypted.Instances)
                oRecipients.Rows.Add(oInstance.UserId, oInstance.CipherKey, oInstance.CipherParams,
                    oInstance.Signature);

            // The procedure checks the original Windows login against saved recipients before its owner writes.
            using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand("[dbo].[SaveItem]", oConnection)
            {
                CommandType = CommandType.StoredProcedure, CommandTimeout = 120
            };
            SqlParameter oItemId = oCommand.Parameters.Add("@itemId", SqlDbType.BigInt);
            oItemId.Direction = ParameterDirection.InputOutput;
            oItemId.Value = oItem.ItemId;
            oCommand.Parameters.Add("@expectedRowVersion", SqlDbType.Binary, 8).Value =
                (object)oItem.RowVersion ?? DBNull.Value;
            oCommand.Parameters.Add("@label", SqlDbType.NVarChar, -1).Value = oItem.Label;
            oCommand.Parameters.Add("@itemType", SqlDbType.NVarChar, -1).Value = oItem.ItemType;
            oCommand.Parameters.Add("@modifiedBy", SqlDbType.BigInt).Value =
                (object)oItem.ModifiedBy ?? DBNull.Value;
            oCommand.Parameters.Add("@cipherText", SqlDbType.VarBinary, -1).Value = oCipher.CipherText;
            oCommand.Parameters.Add("@cipherVector", SqlDbType.VarBinary, -1).Value = oCipher.CipherVector;
            oCommand.Parameters.Add("@cipherParams", SqlDbType.BigInt).Value = oCipher.CipherParams;
            oCommand.Parameters.Add("@contentSuite", SqlDbType.BigInt).Value =
                (object)oCipher.ContentSuite ?? DBNull.Value;
            oCommand.Parameters.Add("@authenticationTag", SqlDbType.VarBinary, -1).Value =
                (object)oCipher.AuthenticationTag ?? DBNull.Value;
            oCommand.Parameters.Add("@protectionDescriptor", SqlDbType.NVarChar, -1).Value =
                (object)oCipher.ProtectionDescriptor ?? DBNull.Value;
            oCommand.Parameters.Add("@protectedKey", SqlDbType.VarBinary, -1).Value =
                (object)oCipher.ProtectedKey ?? DBNull.Value;
            oCommand.Parameters.Add("@signature", SqlDbType.VarBinary, -1).Value =
                (object)oCipher.Signature ?? DBNull.Value;
            oCommand.Parameters.Add("@recipients", SqlDbType.Structured).Value = oRecipients;
            oCommand.Parameters["@recipients"].TypeName = "dbo.EncryptedRecipient";
            try { oCommand.ExecuteNonQuery(); }
            catch (SqlException oError) when (oError.Number is 50010 or 1205)
            {
                throw new InvalidOperationException("This item changed or was removed by another user. " +
                    "Your edits have been kept open. Copy them before reopening the item.", oError);
            }
            oItem.ItemId = (long)oItemId.Value;
        }

        internal static void Delete(SqlServerVaultStorage oStorage, Item oItem)
        {
            using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand("[dbo].[DeleteItem]", oConnection)
            {
                CommandType = CommandType.StoredProcedure
            };
            oCommand.Parameters.Add("@itemId", SqlDbType.BigInt).Value = oItem.ItemId;
            oCommand.Parameters.Add("@expectedRowVersion", SqlDbType.Binary, 8).Value =
                (object)oItem.RowVersion ?? DBNull.Value;
            try { oCommand.ExecuteNonQuery(); }
            catch (SqlException oError) when (oError.Number is 50010 or 1205)
            {
                throw new InvalidOperationException("This item changed or was removed by another user. " +
                    "Refresh the list before removing it.", oError);
            }
        }

        internal static void RemoveCertificate(SqlServerVaultStorage oStorage, long nUserId)
        {
            ExecuteIdProcedure(oStorage, "[dbo].[RemoveCertificate]", "@userId", nUserId);
        }

        private static void ExecuteIdProcedure(SqlServerVaultStorage oStorage, string sProcedure,
            string sParameter, long nId)
        {
            using SqlConnection oConnection = new SqlConnection(oStorage.ConnectionString);
            oConnection.Open();
            using SqlCommand oCommand = new SqlCommand(sProcedure, oConnection)
            {
                CommandType = CommandType.StoredProcedure
            };
            oCommand.Parameters.Add(sParameter, SqlDbType.BigInt).Value = nId;
            oCommand.ExecuteNonQuery();
        }
    }
}
