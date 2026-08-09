namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

public class ReservedPacket
    : InputStreamPacket
{
    public ReservedPacket(BcpgInputStream bcpgIn)
        : this(bcpgIn, newPacketFormat: false)
    {
    }

    public ReservedPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
        : base(bcpgIn, PacketTag.Reserved, newPacketFormat)
    {
    }
}
