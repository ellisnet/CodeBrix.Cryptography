namespace CodeBrix.Cryptography.Pqc.Crypto.SphincsPlus; //was previously: Org.BouncyCastle.Pqc.Crypto.SphincsPlus;

internal class PK
{
    internal byte[] seed;
    internal byte[] root;

    internal PK(byte[] seed, byte[] root)
    {
        this.seed = seed;
        this.root = root;
    }
}
