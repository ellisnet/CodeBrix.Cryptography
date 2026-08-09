using System.IO;

namespace CodeBrix.Cryptography.Utilities; //was previously: Org.BouncyCastle.Utilities;

public interface IEncodable
{
    /// <summary>Return a byte array representing the implementing object.</summary>
    /// <returns>An encoding of this object as a byte array.</returns>
    /// <exception cref="IOException"/>
    byte[] GetEncoded();

    // TODO[api]
    //void EncodeTo(Stream output);
}
