namespace CodeBrix.Cryptography.Pqc.Crypto.Ntru.Owcpa; //was previously: Org.BouncyCastle.Pqc.Crypto.Ntru.Owcpa;

internal class OwcpaDecryptResult
{
    internal byte[] Rm;
    internal int Fail;

    internal OwcpaDecryptResult(byte[] rm, int fail)
    {
        Rm = rm;
        Fail = fail;
    }
}
