using ATBM_PRO.Utils;
using System.Numerics;
using System.Text;
using System.Text.Json;
using ATBM_PRO.Models;
using BE_Project.Models;


namespace ATBM_PRO.Services
{
    public class EncryptionService
    {
        private readonly CustomRSA _rsa;
        private const int BlockSize = 16;

        public static PublicKey publicKeyBE;
        public static PrivateKey privateKeyBE;

        public static void SetKeys()
        {
            CustomRSA rsa = new CustomRSA(128);
            publicKeyBE = new PublicKey
            {
                n = rsa.GetPublicKey().n.ToString(),
                e = rsa.GetPublicKey().e.ToString()
            };
            privateKeyBE = new PrivateKey
            {
                n = rsa.GetPrivateKey().n.ToString(),
                d = rsa.GetPrivateKey().d.ToString()
            };

            Console.WriteLine($"Public Key: n = {publicKeyBE.n}, e = {publicKeyBE.e}");
            Console.WriteLine($"Private Key: n = {privateKeyBE.n}, d = {privateKeyBE.d}");
        }

        public EncryptionService()
        {
            _rsa = new CustomRSA(128);
        }


        public string EncryptResponse(byte[] originalData, BigInteger nFE, BigInteger eFE)
        {
            const int blockSize = 16;
            byte[] dataBytes = originalData;
            byte[] mask = new byte[dataBytes.Length];
            Random.Shared.NextBytes(mask);

            byte[] maskedData = new byte[dataBytes.Length];
            for (int i = 0; i < dataBytes.Length; i++)
                maskedData[i] = (byte)(dataBytes[i] ^ mask[i]);

            BigInteger[] encryptedMask = _rsa.Encrypt(mask, nFE, eFE);
            byte[] encryptedMaskBytes = new byte[encryptedMask.Length * blockSize];
            for (int i = 0; i < encryptedMask.Length; i++)
            {
                byte[] bytes = encryptedMask[i].ToByteArray();
                if (bytes.Length > blockSize)
                {
                    Array.Copy(bytes, 0, encryptedMaskBytes, i * blockSize, blockSize);
                }
                else
                {
                    Array.Copy(bytes, 0, encryptedMaskBytes, i * blockSize, bytes.Length);
                }
            }

            return JsonSerializer.Serialize(new
            {
                Data = Convert.ToBase64String(maskedData),
                Mask = Convert.ToBase64String(encryptedMaskBytes)
            });
        }

        public byte[] DecryptRequest(string aesKeyMaskedBase64, string encryptedMaskBase64)
        {
            byte[] aesKeyMaskedByte = Convert.FromBase64String(aesKeyMaskedBase64);
            byte[] encryptedMaskBytes = Convert.FromBase64String(encryptedMaskBase64);

            BigInteger[] encryptedMask = new BigInteger[aesKeyMaskedByte.Length];
            for (int i = 0; i < aesKeyMaskedByte.Length; i++)
            {
                byte[] block = new byte[BlockSize];
                Array.Copy(encryptedMaskBytes, i * BlockSize, block, 0, BlockSize);
                encryptedMask[i] = new BigInteger(block);
            }
            Console.WriteLine($"nprivateKey: {privateKeyBE.n}, dprivateKey: {privateKeyBE.d}");


            byte[] decryptedMask = _rsa.Decrypt(encryptedMask, BigInteger.Parse(privateKeyBE.n), BigInteger.Parse(privateKeyBE.d));

            if (decryptedMask.Length > aesKeyMaskedByte.Length)
            {
                Array.Resize(ref decryptedMask, aesKeyMaskedByte.Length);
            }

            byte[] originalData = new byte[aesKeyMaskedByte.Length];
            for (int i = 0; i < aesKeyMaskedByte.Length; i++)
                originalData[i] = (byte)(aesKeyMaskedByte[i] ^ decryptedMask[i % decryptedMask.Length]);


            return originalData;
        }
    }
}


