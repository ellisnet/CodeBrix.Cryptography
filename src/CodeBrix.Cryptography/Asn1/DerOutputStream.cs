using System;
using System.IO;

namespace CodeBrix.Cryptography.Asn1; //was previously: Org.BouncyCastle.Asn1;

internal class DerOutputStream
    : Asn1OutputStream
{
    internal DerOutputStream(Stream os, bool leaveOpen)
        : base(os, leaveOpen)
    {
    }

    internal override int Encoding
    {
        get { return EncodingDer; }
    }
}
