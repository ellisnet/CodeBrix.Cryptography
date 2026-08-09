using CodeBrix.Cryptography.Crypto;
using CodeBrix.Cryptography.Utilities;

namespace CodeBrix.Cryptography.Pqc.Crypto.Lms; //was previously: Org.BouncyCastle.Pqc.Crypto.Lms;

public abstract class LmsKeyParameters
    : AsymmetricKeyParameter, IEncodable
{
    internal LmsKeyParameters(bool isPrivateKey)
        : base(isPrivateKey)
    {
    }

    public abstract byte[] GetEncoded();
}
