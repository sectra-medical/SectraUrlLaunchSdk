namespace Sectra.UrlLaunch.Pki;
internal record SignedUrlString(byte[] UrlString, byte[] Signature);