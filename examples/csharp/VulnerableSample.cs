// A deliberately insecure C# file used to demonstrate C# security_scan.
// It contains NO real secrets — only patterns the Roslyn security analyzers flag.
//
// C# analysis builds the project, so point security_scan at this directory
// (which holds sample.csproj) or at the .csproj itself.

using System.Security.Cryptography;

public class VulnerableSample
{
    // MD5 is a broken cryptographic algorithm. (Roslyn CA5351)
    public byte[] WeakHash(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }
}
