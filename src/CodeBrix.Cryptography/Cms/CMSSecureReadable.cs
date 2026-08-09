using System;
using CodeBrix.Cryptography.Asn1.X509;
using CodeBrix.Cryptography.Crypto.Parameters;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

internal interface CmsSecureReadable
{
	AlgorithmIdentifier Algorithm { get; }
	object CryptoObject { get; }
	CmsReadable GetReadable(KeyParameter key);
}
