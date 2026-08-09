using System.IO;

namespace CodeBrix.Cryptography.Cms; //was previously: Org.BouncyCastle.Cms;

public interface CmsReadable
{
    Stream GetInputStream();
}
