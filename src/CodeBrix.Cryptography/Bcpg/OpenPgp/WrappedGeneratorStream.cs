using System;
using System.IO;
using CodeBrix.Cryptography.Utilities.IO;

namespace CodeBrix.Cryptography.Bcpg.OpenPgp; //was previously: Org.BouncyCastle.Bcpg.OpenPgp;

internal sealed class WrappedGeneratorStream
	: FilterStream
{
	private readonly IStreamGenerator m_generator;

	internal WrappedGeneratorStream(IStreamGenerator generator, Stream s)
		: base(s)
	{
		m_generator = generator ?? throw new ArgumentNullException(nameof(generator));
	}

    protected override void Dispose(bool disposing)
    {
		if (disposing)
		{
#pragma warning disable CS0618 // Type or member is obsolete
			m_generator.Close();
#pragma warning restore CS0618 // Type or member is obsolete
		}

		Detach(disposing);
	}
}
