using System;

namespace CodeBrix.Cryptography.Crypto.Modes.Gcm; //was previously: Org.BouncyCastle.Crypto.Modes.Gcm;

[Obsolete("Will be removed")]
public interface IGcmMultiplier
{
	void Init(byte[] H);
	void MultiplyH(byte[] x);
}
