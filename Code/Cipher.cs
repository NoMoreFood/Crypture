namespace Crypture
{
    public class Cipher
    {
        public long ItemId { get; set; }
        public byte[] CipherText { get; set; }
        public byte[] CipherVector { get; set; }
        public long CipherParams { get; set; }
        public long? ContentSuite { get; set; }
        public byte[] AuthenticationTag { get; set; }
        public string ProtectionDescriptor { get; set; }
        public byte[] ProtectedKey { get; set; }
        public string EscrowLabel { get; set; }
        public byte[] Signature { get; set; }

        public virtual Item Item { get; set; }
    }
}
