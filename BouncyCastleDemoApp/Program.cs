using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;

namespace BouncyCastleDemoApp;


class Program
{
    static void Main(string[] args)
    {
        //HashFormString("123456");
        BcryptFromString("123456");
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

