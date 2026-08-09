using System;
using CodeBrix.Cryptography.Crypto.Parameters;
using CodeBrix.Cryptography.Security;

namespace CodeBrix.Cryptography.Crypto.Generators; //was previously: Org.BouncyCastle.Crypto.Generators;

/// <summary>
/// Key-pair generator for Ed448 (RFC 8032). Only the <see cref="SecureRandom"/> from the supplied
/// <see cref="KeyGenerationParameters"/> is used; the 57-byte seed is drawn directly from it.
/// </summary>
public class Ed448KeyPairGenerator
    : IAsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    /// <summary>Capture the <see cref="SecureRandom"/> that will source the seed.</summary>
    public virtual void Init(KeyGenerationParameters parameters)
    {
        this.random = parameters.Random;
    }

    /// <summary>Generate a fresh Ed448 key pair.</summary>
    public virtual AsymmetricCipherKeyPair GenerateKeyPair()
    {
        Ed448PrivateKeyParameters privateKey = new Ed448PrivateKeyParameters(random);
        Ed448PublicKeyParameters publicKey = privateKey.GeneratePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
