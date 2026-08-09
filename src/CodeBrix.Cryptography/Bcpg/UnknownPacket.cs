using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

public sealed class UnknownPacket
    : ContainedPacket
{
    private readonly byte[] m_contents;

    public UnknownPacket(PacketTag tag, BcpgInputStream bcpgIn)
        : this(tag, bcpgIn, newPacketFormat: false)
    {
    }

    public UnknownPacket(PacketTag tag, BcpgInputStream bcpgIn, bool newPacketFormat)
        : base(tag, newPacketFormat)
    {
        m_contents = bcpgIn.ReadAll();
    }

    public byte[] GetContents() => Arrays.Clone(m_contents);

    public override void Encode(BcpgOutputStream bcpgOut) =>
        bcpgOut.WritePacket(HasNewPacketFormat, PacketTag, m_contents);
}
