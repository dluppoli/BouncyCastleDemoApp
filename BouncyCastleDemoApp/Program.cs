using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace BouncyCastleDemoApp;


class Program
{
    static void Main(string[] args)
    {
        //HashFormString("123456");
        //BcryptFromString("123456");

        string key = "HelloWorld!!$$!!";

        AES_CBC_Encrypt("8061.bmp", Encoding.ASCII.GetBytes(key));
        //AES_ECB_Decrypt("test2.txt.bin", Encoding.ASCII.GetBytes(key));
    }

    static void AES_CBC_Encrypt(string filePath, byte[] key)
    {
        if (File.Exists(filePath))
        {
            byte[] plaintext = File.ReadAllBytes(filePath);
            byte[] ciphertext = AES_CBC(plaintext, key);

            File.WriteAllBytes(filePath + ".bin", ciphertext);
        }
    }

    static void AES_CBC_Decrypt(string filePath, byte[] key)
    {
        if (File.Exists(filePath))
        {
            byte[] ciphertext = File.ReadAllBytes(filePath);
            byte[] plaintext = AES_CBC(ciphertext, key, false);

            File.WriteAllBytes(filePath.Replace(".bin", ""), plaintext);
        }
    }

    static void AES_ECB_Encrypt(string filePath, byte[]key)
    {
        if( File.Exists(filePath) )
        {
            byte[] plaintext = File.ReadAllBytes(filePath);
            byte[] ciphertext = AES_ECB(plaintext, key);

            File.WriteAllBytes(filePath + ".bin", ciphertext);
        }
    }

    static void AES_ECB_Decrypt(string filePath, byte[] key)
    {
        if (File.Exists(filePath))
        {
            byte[] ciphertext = File.ReadAllBytes(filePath);
            byte[] plaintext = AES_ECB(ciphertext, key, false);

            File.WriteAllBytes(filePath.Replace(".bin",""), plaintext);
        }
    }

    static byte[] AES_ECB(byte[] input, byte[] key, bool encrypt = true)
    {
        AesEngine engine = new AesEngine();
        EcbBlockCipher ecbBlockCipher = new EcbBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(ecbBlockCipher);

        KeyParameter keyParameter = new KeyParameter(key);

        cipher.Init(encrypt, keyParameter);

        byte[] output = new byte[ cipher.GetOutputSize(input.Length) ];

        int l = cipher.ProcessBytes(input, output, 0);
        cipher.DoFinal(output,l);

        return output;
    }

    static byte[] AES_CBC(byte[] input, byte[] key, bool encrypt = true)
    {
        AesEngine engine = new AesEngine();
        CbcBlockCipher cbcBlockCipher = new CbcBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

        KeyParameter keyParameter = new KeyParameter(key);

        byte[] iv = new byte[engine.GetBlockSize()];

        if (encrypt)
        {
            SecureRandom random = new SecureRandom();
            random.NextBytes(iv);
        }
        else
        {
            iv = input.Take(iv.Length).ToArray();
            input = input.Skip(iv.Length).ToArray();
        }

        ParametersWithIV parametersWithIV = new ParametersWithIV(keyParameter, iv);
        cipher.Init(encrypt, parametersWithIV);

        byte[] output = new byte[cipher.GetOutputSize(input.Length)];

        int l = cipher.ProcessBytes(input, output, 0);
        cipher.DoFinal(output, l);

        if(encrypt)  return iv.Concat(output).ToArray();

        return output;
    }










    static void HashFormString(string s)
    {
        Sha256Digest digest = new Sha256Digest();

        byte[] plaintext = Encoding.ASCII.GetBytes(s);
        byte[] ciphertext = new byte[digest.GetDigestSize()];

        digest.BlockUpdate(plaintext, 0, plaintext.Length);
        digest.DoFinal(ciphertext, 0);

        Console.WriteLine(BitConverter.ToString(ciphertext).Replace("-", ""));
    }

    static void BcryptFromString(string password)
    {
        byte[] salt = Encoding.ASCII.GetBytes("sljkbdfah3slod09");
        byte[] passwordBytes = Encoding.ASCII.GetBytes(password);

        byte[] digest = BCrypt.Generate(passwordBytes, salt, 13);

        Console.WriteLine(BitConverter.ToString(digest).Replace("-", ""));
    }
}

