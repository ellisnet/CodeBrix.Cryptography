using System;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp; //was previously: Org.BouncyCastle.Bcpg.OpenPgp;

public interface IStreamGenerator
{
	[Obsolete("Dispose any opened Stream directly")]
	void Close();
}
