namespace CodeBrix.Cryptography.Asn1; //was previously: Org.BouncyCastle.Asn1;

public interface Asn1SetParser
    : IAsn1Convertible
{
    IAsn1Convertible ReadObject();
}
