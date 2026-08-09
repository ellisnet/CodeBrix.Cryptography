using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Pqc.Crypto.Frodo; //was previously: Org.BouncyCastle.Pqc.Crypto.Frodo;

public sealed class FrodoPrivateKeyParameters
    : FrodoKeyParameters
{
    internal readonly byte[] privateKey;

    public FrodoPrivateKeyParameters(FrodoParameters parameters, byte[] privateKey)
        : base(true, parameters)
    {
        this.privateKey = Arrays.Clone(privateKey);
    }

    public byte[] GetPrivateKey()
    {
        return Arrays.Clone(privateKey);
    }

    public byte[] GetEncoded()
    {
        return Arrays.Clone(privateKey);
    }
}
