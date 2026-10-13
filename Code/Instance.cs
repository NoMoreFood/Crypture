namespace Crypture
{
    public class Instance
    {
        public long InstanceId { get; set; }
        public long ItemId { get; set; }
        public long UserId { get; set; }
        public byte[] CipherKey { get; set; }
        public long CipherParams { get; set; }
        public byte[] Signature { get; set; }

        public virtual User User { get; set; }
        public virtual Item Item { get; set; }
    }
}
