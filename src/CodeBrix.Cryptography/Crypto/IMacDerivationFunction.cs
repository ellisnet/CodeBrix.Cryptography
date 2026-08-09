namespace CodeBrix.Cryptography.Crypto; //was previously: Org.BouncyCastle.Crypto;

public interface IMacDerivationFunction
    : IDerivationFunction
{
    IMac Mac { get; }
}
