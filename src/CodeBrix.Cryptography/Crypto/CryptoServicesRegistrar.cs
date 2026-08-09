using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto; //was previously: Org.BouncyCastle.Crypto;

public static class CryptoServicesRegistrar
{
    public static SecureRandom GetSecureRandom()
    {
        return new SecureRandom();
    }

    public static SecureRandom GetSecureRandom(SecureRandom secureRandom)
    {
        return secureRandom ?? GetSecureRandom();
    }
}
