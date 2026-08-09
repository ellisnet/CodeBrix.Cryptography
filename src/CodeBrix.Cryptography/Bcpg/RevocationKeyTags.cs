namespace CodeBrix.Cryptography.Bcpg; //was previously: Org.BouncyCastle.Bcpg;

public enum RevocationKeyTag
    : byte
{
    ClassDefault = 0x80,
    ClassSensitive = 0x40
}
