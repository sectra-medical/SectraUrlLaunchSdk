using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Sectra.UrlLaunch.SharedSecret;
public class OneTimeSignatureTests {
    private const string Rsa2048Cert =
@"MIIDADCCAeigAwIBAgIQaRtwaRDmlpFEpka5e/Wa+TANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDDAhUZXN0IFJTQTAeFw0yMjA1MzEwODI1NTJaFw0yMzA1MzEwODQ1NTJaMBMxETAPBgNVBAMMCFRlc3QgUlNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxFVQHbI2lHGVUZehtiLKCeII3mKyoGDUUmAOegYKquL2ME6u0k4xEHgDTyorQ/xm+QhCCh23OE5ltzcc3yxczFSQ3rK9Y7goa5ebWeTnArxvZxkrdbMG+I2aPoahPG7kUVPjq/SInzfLf71I+mH0YdOgo87zk4Br9GBzbYu26Xgk5H4ZP+nCdAT/VSPON0nZriEWKhUolaxzoZDoyM6/chzwbMTiO9BBDZB+quXKk7DLHUJAo6LCxdB77N/Hj2J+HKZWMdGlO+qL4+rdp3NL2/C4l93XVijCtKc0cP41Em50HcdhxyP5YZ5OpjcSOaKkX60Fu5SXV2T+t30gBE2/nQIDAQABo1AwTjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBSuyq7GWL55fq0n6sMkvGGa+7YQlzANBgkqhkiG9w0BAQsFAAOCAQEAPU87c5izmKGcjIumH0kNxPZaSwkHrNQ8I+WTPdaCFs+Iz9D+/D/YlQZQTEkudgGz+hNy4VFFqCJTf76nrxpeXzbJIfmlUgsJMsBi3bpuVT40IWTkstKn1pmL81vP3c13gOegZbWzfB5/fkaquyCFqX7MM1v0iMUutnUrRyo4pyuS9uzjlzr72ZL1EwUG8aR1E6WB3usTNY5xXwADNyQ5sFFuVbC6IoqCdqk284x2emOC4Acokjv4EqluRG+RIppl4CB9i/rQBTcMm34Joe3ah69pGQDpHhXDPGkL4mHkRqAzfZyct5G4L4l5f7QAbaGCKddwpkeadxkDpUTI
t94yUg==";

    private const string Rsa2048CertWithPrivateKey =
@"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";

    private const string Rsa4096Cert =
@"MIIFCjCCAvKgAwIBAgIQZo++/UTeo6xLAjh/4aswUzANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA1UZXN0IFJTQSA0MDk2MB4XDTIyMDUzMTA4MjYxN1oXDTIzMDUzMTA4NDYxN1owGDEWMBQGA1UEAwwNVGVzdCBSU0EgNDA5NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOODrDItT4gH2nmjciyNyhhvNDP7KFAiKIjYU+dW4kkuThuwUXq9xyKSYtDYHwituMmp+s+29YK65dPJiEAI0uPuDfNJGiAnbXs6bIi8wHt557dUSWcUN4GzOkoFTHahZNE5YYyh4rLfs5TqatEcktMF3T6FQe8/qqMVlm8uMf5tok7Aqm2qxLe41xyG5tK2qVotoKZ+6DLcZScfHvYsz9U5Za/uAPrfvLiy78Cn/T01glqkUD6t/mlZ+lkzR938nd5FU8LtFnvcjHqN+13/FDqUCXArk4S8VKmfwT7tKQ7m2DVjBBHCk6sTgFfIMLuHjLoRRnBjh+KZqhryHVYYvmEL8BspznNgsKfxMsoP6WoxgteFlE7P3f8or+sb3SLE0epsDnChcHSQcfeQIvwh9td8BJp0hVjmmUWMukZvUlwXrnSaBEycCGP64dYyJ43Jzfp3xVtJqq2KDh3WTZZd1UwQrDSeL1CvT74YGjxxGb7RCrx/Q6+/omB4e6kGehQQRb0O3zlt4xbrqurdmC+fM6SeDiuvD8E92aecJy24z/sM3QUxJ2n+CiBRMlMStkQ0b6mTwWnCDDlPiFewj8x7qNGVnvcdeeL59LCRQvDoFO5Ku+NUFdjNV4uGPGJ+NNnMkKFl6xpaOr22sosOf6QvJ/brJgztX8XDJWokJvsCnBPNAgMBAAGjUDBOMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHQYDVR0OBBYEFPpq2zeEiM/pF+yGA+FyNmSPM2KzMA0GCSqG
SIb3DQEBCwUAA4ICAQBSWziP7xp9uqJCcAS62yp22ghJsfmBOcr8eZQUU2DAjVb8YbhsjMxppgUBjMk6nKKL3BO6WXuGbywSE7RLlrOYuN0GbKYnz4lTNZVs74+nJ0RkD6r7s+1Y/zTIcLkYzVNqct4T2aZKFyIt3lu+C5YlDSw1UUBoIEDVjw0AhZABrDFtsigI+4vPvHLRfF/6KzM08pAp/bTa67xSlsM9tHtxWM0XWmvFw2Qo1uqSgabBDaO+bERDW412QX793YFxSOVdsKAwNqqlDsxKBiP3CoJgIWUBBOMblpFSyInc/0zb3XH6EP/BXZR3ai+Ts8FGNagWHONHbt8+r9D2zrsTgZBIAI2AC5SM0ICcb8nYzyLShC2LCF4RfxKXN+iVMqNYrDJd690K9KoJNPjwFIqL9FqSZy27nRVfTmfG8Bmvrz2GJLZSMEwCQmyJNPRGN8AzSaPDUVPuNramrapt6iBQICdmWkLL2yHE3o1yhGSreUihjw/jY8pQOuFJBlhXB6M4xUGvUw/2TTYM/QKBXIbS4JMlQ+V49BI3JRxSQRN3PcG4AB07cS3kac3Mf3Fy+CTvJMbNVO6ECA1Fj6dVmEiFyVQtBZ9wGjJtQT7oWFWigZj86lXNG8Ne5P/GTyPiAd7SU/c7qMg22v8Sio/DGSbzb2mH/X22NxobwmwMRm2QIeFlKQ==";

    private const string Rsa4096CertWithPrivateKey =
@"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";

    private const string EcdsaP256Cert =
@"MIIBdzCCAR6gAwIBAgIQE8QDmIvTkI5G5HnoEq/+KjAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApUZXN0IEVDRFNBMB4XDTIyMDUzMTA4NDcxN1oXDTIzMDUzMTA5MDcxN1owFTETMBEGA1UEAwwKVGVzdCBFQ0RTQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLPWqz3XqEiOn/KMsgl72vjHpNBzyJMAYS3ZEH/0HK4dfY6G4RwtXsd6MpplBwfaVXq8T2eOGIyruPn3FNSvEXejUDBOMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHQYDVR0OBBYEFOaAxBVSfuOS4kzU8KqCMqxG/zhhMAoGCCqGSM49BAMCA0cAMEQCIDShoNniue6s1S+y/QFM719LkUul0h7YsYmnjTLHSYssAiB3TUYSSf6k0bJ/BgMAjSziXqHGdBjWic7ZiFxAYt3A3A==";

    private const string EcdsaP256CertWithPrivateKey =
@"MIIEPwIBAzCCA/sGCSqGSIb3DQEHAaCCA+wEggPoMIID5DCCAc0GCSqGSIb3DQEHAaCCAb4EggG6MIIBtjCCAbIGCyqGSIb3DQEMCgECoIHMMIHJMBwGCiqGSIb3DQEMAQMwDgQIxNMK5I8RWNUCAgfQBIGozK1sgzdv8N6qusZJYzXSyBwbkEY0MC3qget2id906IF/iXSFfs7+o1B4tJIPRvz0GylLRp7B+3tvFmm8dgUIVNtqf027zzfh0PD4ttTX1VGx4jeQZMp5wQzOYsE9XrEzN8Oseyua9AoS7S0xzZVaPd60yTO0wIG+477FM+4PVHTO6foQTSUiNMEbhiIcfh0jxBjN8Z/UlgErN65xVM9CgJg1+tEWdABrMYHTMBMGCSqGSIb3DQEJFTEGBAQBAAAAMF0GCSqGSIb3DQEJFDFQHk4AdABlAC0ANQA5ADkAZgA3ADkANABmAC0AZgAxAGIAMwAtADQAMwA2ADQALQBiAGUAYQA3AC0AMgBlADkAYgA5AGYAMwAwADIAMgBlADMwXQYJKwYBBAGCNxEBMVAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcjCCAg8GCSqGSIb3DQEHBqCCAgAwggH8AgEAMIIB9QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIX2oVzN/E1kUCAgfQgIIByFDoni6r+x5SPrIR91d0h94hjNXbo2pLFIDBPewbyLmM4qxo1efvc2Tm5/yfLEXaKlxMMX8kTsEtas6uxe4CGgJKroNKfltzJOlHc3LTQz7lMw5DvrLYBPp6g1sql169p9nzoPwwG1CHkIin4ExCPe/r9KNx7F59hhMufO09h4HM+L2zbU6KeAg8WIqRSyE5BHGUFdz4+7vCyC9i2WtbnLkZognwD8Rn3e+e5NncGN+nfyUVOUkUrjllRuU/Ce5A+MBI
vSOxu7gqNsseRYQzQhHMk/nNJ5H0bSh/PkRHX8LoBr0655yX9siYyfpQ7bDzgVl+O6VsAh+m6s+zt3Vt+HKw2tElV9nAOy0EG0afnRfVCoYxWEEp4Bjtmapo1WgIlPU2oEuCwyJA4FAJXCrVFJaL84vWoaXw9bLodWzL+ZGHhjrwFYG1aLm/Z4iN6KPP9sEUtHML8mIT06m3GfAMPhlQQFwlPe5gbZdmqA42uE8rQySw7JdeTic+/gvFNPLcyOB3qAbc1cG/JzlfCX+VfPBKnNZoLz2nH5j3BpPG5hWmnrF2Kqct85q8ngWElOkXqNlubhpbPjTjhBDtu1wEyrfMMYSRD0Kz8TA7MB8wBwYFKw4DAhoEFKdO8oFz/KGD1ihvn8eRwRqglC+tBBRL0bZk+Q6ORAh6pUoG/0iDverCBwICB9A=";

    private const string EcdsaP256CertOther =
@"MIIBeDCCAR6gAwIBAgIQNUAwGbq+Xo1M/GKzRCn2hDAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApUZXN0IEVDRFNBMB4XDTIyMDUzMTEzMzYxMVoXDTIzMDUzMTEzNTYxMVowFTETMBEGA1UEAwwKVGVzdCBFQ0RTQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEQ0nR3XdNGShd6z0ei4daeyW6m/0WGDAtSMLbUKFPujgtWTPsdZEUjYA7YnE59v8AdHm9grCsnnmP8t935YH0SjUDBOMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwHQYDVR0OBBYEFBodnCjDqEv++QIfS+MsuCAV9cKvMAoGCCqGSM49BAMCA0gAMEUCIAVOH+fTchiS0BGe6lq5j9kPjXHlJ4mvC3TJu2iohf55AiEArqkSpbwAHl9sxW5DyFQrLiqAbEgLhLteBovUlqQV4o4=";

    private const string EcdsaP384Cert =
@"MIIBtDCCATugAwIBAgIQHKKPb55RBr1MxSD010/lDjAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApUZXN0IEVDRFNBMB4XDTIyMDUzMTExMzMxM1oXDTIzMDUzMTExNTMxM1owFTETMBEGA1UEAwwKVGVzdCBFQ0RTQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABHX/PtRghvZBSrxyTBz7fy5m8sQQwSUOOypsI8lidATgvrlXNA1VA5K2pYp6d7AfoS3T19FDuixIAIpJAWY4vw4dLL7YxD+T2Bb/ve/afnT+D1CybsUO4xMoVFWTcXVSjaNQME4wDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4EFgQUc690pqNRqXaCbuIKEuc/ciS1/Q0wCgYIKoZIzj0EAwIDZwAwZAIwL+SinB9ZB+6xyuWzeoRoQkbSJsUPhXGM1rid1CDdR5KyteKwUCNmDDo+mLgAbxy7AjBJHWyY/mPvx+RM19IXzJkm8ajOuDttAy63Azik2Uh9jF7FfUwwFg35oP40EhndovY=";

    private const string EcdsaP384CertWithPrivateKey =
@"MIIErwIBAzCCBGsGCSqGSIb3DQEHAaCCBFwEggRYMIIEVDCCAf0GCSqGSIb3DQEHAaCCAe4EggHqMIIB5jCCAeIGCyqGSIb3DQEMCgECoIH8MIH5MBwGCiqGSIb3DQEMAQMwDgQIFPi097bAxZ0CAgfQBIHYp7Wzt+KvYM5IaKkL5inKoz1zrXzgXN6DcdbgXICjkllyBlsQpUl377Iwv8nTdrsY3P+bVt4XjqOo16zG01/NF/iB110HPcEtXZsYnJ9y7zToH0J/4M26scQw+ZW8icYa9kBJQbT5VZVwKZyqHjGloC61cXnomSgY/S3lo9L3h50O2unlqDpwxWxGkFNy6qDFFQvCFNPgTkP5gZKrTV8/szVKaG3uFcVbZXRifeJUAZRnlckjb1n2L9q7CtrzzpHnOrqYxsxNTa+3bcDJJkLnegrIsvngvSq3MYHTMBMGCSqGSIb3DQEJFTEGBAQBAAAAMF0GCSqGSIb3DQEJFDFQHk4AdABlAC0ANQBlAGMAZAA0ADMANABmAC0AYQA1ADYANQAtADQAYgAwAGIALQA5ADIAMwA5AC0AZgAxADMAZQBlADkAYQBiAGEAOQBjADcwXQYJKwYBBAGCNxEBMVAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcjCCAk8GCSqGSIb3DQEHBqCCAkAwggI8AgEAMIICNQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIs9CdQaHVdeICAgfQgIICCA8ECowdVgYVsxCBP5xKNoxK0uA54QGeYuJGQA9GXeLJ0vrfJXi0uoOa1J1/upkcrxlv8MygcfGqP+90QYMOTsAy4y/Rjs1SGevAiUvCGR0dhkkBZorr0UL8ut1VxR0U1fHmcUI8GpENz5MHc11YA3rzAXp3gbJSZ2hyaFQ4c7rcr+16e+bR4Bhr9eukDq7tM4cu
tNKSFvbZP4ACUeqP3bLG8cSLYmFfM9FD/c+zSoEHBEDjq5EXJjaRMkyqGPT03j1HgBAFe0KzBYdjyFH965or5y7R08BHvlaeNffigAr982bYqKP7KbRWYyKXlILzpWaVfd2TnpF3LZKqf7ha3wNDUzgNk6ETu0ofvrbxnZ9zd5kBFfPkJUG7nUX+EyBmYSborhLZog6wDgx4JiLv9UYdJHf0Ls1H6MvT9dwog/IsgvarySmtmqZoP0YLaDn3eRXOuMRpQdUIlf9uGihkgZI9rqlf3J06jmEcJaiz9CRSbUFInh48+ZNIJGkaD5BCF1dZEfCJXmVgvNb0vyWA+YcKS4H55k3tUqezY1UqIOptZaVv+zOtSxVvMFRpm/4LMibbYv7xR+ofHHkpF4gEopKL5iv/TLaWfMzuQ96PRNJXilb2Cn/Z+f7AO60zpZAj9KRFzL+oSdZ3Xo+Ex4O1AMQwsKH4Q5zd4Bxu1BCIRjksZIxVuIOFaU4wOzAfMAcGBSsOAwIaBBQeMrSTtSLMQvT5ewLSTR6Ga+cgAwQUQywRpq/Kxz84zhjkQhCWvb2l3RACAgfQ";

    public class OneTimeSignatureTestData : IEnumerable<object[]> {
        public IEnumerator<object[]> GetEnumerator() {
            yield return new object[] { Rsa2048Cert, Rsa2048CertWithPrivateKey };
            yield return new object[] { Rsa4096Cert, Rsa4096CertWithPrivateKey };
            yield return new object[] { EcdsaP256Cert, EcdsaP256CertWithPrivateKey };
            yield return new object[] { EcdsaP384Cert, EcdsaP384CertWithPrivateKey };
        }
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    private static string plainTextTestData = "The quick brown fox jumps over the lazy dog";

    [Fact]
    public void OneTimeSignature_SignUsingHmacAndVerify_Succeeds() {
        var key = Rng.GetBytes(32);
        var signedData = OneTimeSignature.Sign(
            Encoding.UTF8.GetBytes(plainTextTestData), key);

        var data = OneTimeSignature.Verify(signedData, key);

        Assert.Equal(plainTextTestData, Encoding.UTF8.GetString(data));
    }

    [Fact]
    public void OneTimeSignature_SignUsingHmacInvalidKeyAndVerify_Fails() {
        var signedData = OneTimeSignature.Sign(
            Encoding.UTF8.GetBytes(plainTextTestData), Rng.GetBytes(32));

        Assert.Throws<CryptographicException>(() => OneTimeSignature.Verify(signedData, Rng.GetBytes(32)));
    }

    internal class FileQueue : IConcurrentQueue<OneTimeSignature.NonceAndTimestamp> {

        private static string fileName = Path.GetTempFileName();
        long start = 0;
        int count = 0;

        ~FileQueue() {
            File.Delete(fileName);
        }

        public int Count => count;

        public void Enqueue(OneTimeSignature.NonceAndTimestamp item) {
            string serialized = $"{item.Timestamp.ToFileTimeUtc()}:{Convert.ToBase64String(item.Nonce)}";
            using var sw = new StreamWriter(File.OpenWrite(fileName));
            sw.WriteLine(serialized);
            count++;
        }

        public IEnumerator<OneTimeSignature.NonceAndTimestamp> GetEnumerator() {
            using var sr = new StreamReader(File.OpenRead(fileName));
            var serialized = sr.ReadLine();
            if (serialized == null) {
                yield break;
            }

            yield return Deserialize(serialized);
        }

        private OneTimeSignature.NonceAndTimestamp Deserialize(string serialized) {
            return new OneTimeSignature.NonceAndTimestamp(
                DateTime.FromFileTimeUtc(long.Parse(serialized.Split(':')[0])),
                Convert.FromBase64String(serialized.Split(':')[1]));
        }

        public bool TryDequeue(out OneTimeSignature.NonceAndTimestamp? item) {
            using var sr = new StreamReader(File.OpenRead(fileName));
            sr.BaseStream.Seek(start, SeekOrigin.Begin);
            var serialized = sr.ReadLine();
            if (serialized == null) {
                item = null;
                return false;
            }
            item = Deserialize(serialized);
            start += serialized.Length;
            count--;
            return true;
        }

        public bool TryPeek(out OneTimeSignature.NonceAndTimestamp? item) {
            using var sr = new StreamReader(File.OpenRead(fileName));
            var serialized = sr.ReadLine();
            if (serialized == null) {
                item = null;
                return false;
            }
            item = Deserialize(serialized);
            return true;

        }

        IEnumerator IEnumerable.GetEnumerator() {
            return GetEnumerator();
        }
    }


    [Fact]
    public void OneTimeSignature_VerifyWithCustomBackingStore_Succeeds() {
        var key = Rng.GetBytes(32);
        var signedData = OneTimeSignature.Sign(
            Encoding.UTF8.GetBytes(plainTextTestData), key);
        var myNonceBacking = new FileQueue();

        var data = OneTimeSignature.Verify(signedData, key, myNonceBacking);

        Assert.Equal(plainTextTestData, Encoding.UTF8.GetString(data));
        var ex = Assert.Throws<CryptographicException>(
                    () => OneTimeSignature.Verify(signedData, key, myNonceBacking));
        Assert.Equal("Nonce reused, possible replay attack!", ex.Message);
    }

    [Fact]
    public async Task OneTimeSignature_VerifyConcurrent_Succeeds() {
        var task1 = Task.Run(ThreadRun);
        var task2 = Task.Run(ThreadRun);

        await Task.WhenAll(task1, task2);

        Assert.True(true);
    }

    private static void ThreadRun() {
        for (int i = 0; i < 1000; i++) {
            var key = Rng.GetBytes(32);
            var signedData = OneTimeSignature.Sign(Encoding.UTF8.GetBytes(plainTextTestData), key);
            OneTimeSignature.Verify(signedData.ToArray(), key);
        }
    }
}
