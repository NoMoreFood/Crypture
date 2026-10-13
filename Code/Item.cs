using System;
using System.Collections.Generic;

namespace Crypture
{
    public class Item
    {
        public long ItemId { get; set; }
        public string ItemType { get; set; }
        public string Label { get; set; }
        public DateTime ModifiedDate { get; set; }
        public long? ModifiedBy { get; set; }
        public string ModifiedByIdentity { get; set; }
        public DateTime CreatedDate { get; set; }
        public byte[] RowVersion { get; set; }

        public virtual ICollection<Instance> Instances { get; set; } = new HashSet<Instance>();
        public virtual User User { get; set; }
        public virtual Cipher Cipher { get; set; }

        // File attachments keep their extension as the item type; other types hold text content.
        internal bool IsFile => ItemType is not ("text" or "richtext" or "totp");
        public string ItemTypeDisplay => ItemType == "totp" ? "TOTP" :
            ItemType == "text" ? "Text Secret" : ItemType == "richtext" ? "Rich Text Secret" : "File Attachment";
        public string ModifiedByDisplay => ModifiedByIdentity ?? User?.Name ?? "";
        public string ProtectionDisplay => Cipher == null ? "Unknown" :
            (Cipher.CipherParams == ItemCryptography.RecoveryFormat
            ? (ItemCryptography.UsesWindowsProtection(Cipher) ? "User Based" : "Certificate Based")
            : Cipher.CipherParams == ItemCryptography.FidoFormat ? "FIDO2 Security Key"
            : Cipher.CipherParams == ItemCryptography.PrincipalFormat ? "User Based" :
            Cipher.CipherParams == ItemCryptography.CertificateFormat
            ? "Certificate Based" : "Unsupported") +
            (!String.IsNullOrEmpty(Cipher.EscrowLabel) ? " + Escrow: " + Cipher.EscrowLabel :
                Cipher.CipherParams == ItemCryptography.RecoveryFormat ? " + Recovery" : "");
    }
}
