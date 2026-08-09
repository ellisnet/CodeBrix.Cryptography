using System;
using CodeBrix.Cryptography.Utilities.Date;

namespace CodeBrix.Cryptography.Asn1.X509; //was previously: Org.BouncyCastle.Asn1.X509;

internal class Rfc5280Asn1Utilities
{
    internal static DerGeneralizedTime CreateGeneralizedTime(DateTime dateTime) =>
        new DerGeneralizedTime(DateTimeUtilities.WithPrecisionSecond(dateTime));

    internal static DerUtcTime CreateUtcTime(DateTime dateTime) => new DerUtcTime(dateTime, 2049);
}
