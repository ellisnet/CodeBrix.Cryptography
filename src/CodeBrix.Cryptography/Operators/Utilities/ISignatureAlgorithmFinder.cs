using CodeBrix.Cryptography.Asn1.X509;

namespace CodeBrix.Cryptography.Operators.Utilities; //was previously: Org.BouncyCastle.Operators.Utilities;

public interface ISignatureAlgorithmFinder
{
    /// <summary>
    /// Find the signature algorithm identifier that matches with the passed in signature name.
    /// </summary>
    /// <param name="signatureName">the name of the signature algorithm of interest.</param>
    /// <returns>an algorithm identifier for the signature name.</returns>
    AlgorithmIdentifier Find(string signatureName);
}
