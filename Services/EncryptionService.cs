using ATBM_PRO.Utils;
using System.Numerics;
using System.Text;
using System.Text.Json;

namespace ATBM_PRO.Services
{
    public class EncryptionService
    {
        private readonly CustomRSA _rsa;
        private  readonly (BigInteger n, BigInteger e) _publicKey;
        private  readonly(BigInteger n, BigInteger d) _privateKey;
        private const int BlockSize = 16;

        public EncryptionService()
        {
            _rsa = new CustomRSA(128);
            _publicKey = _rsa.GetPublicKey();
            _privateKey = _rsa.GetPrivateKey();
        }

        public (BigInteger n, BigInteger e) GetPublicKey() => _publicKey;

        public string EncryptResponse(string originalData, BigInteger nFE, BigInteger eFE)
        {
            const int blockSize = 16;
            byte[] dataBytes = Encoding.UTF8.GetBytes(originalData);
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

        public string DecryptRequest(string maskedDataBase64, string encryptedMaskBase64)
        {
            byte[] maskedData = Convert.FromBase64String(maskedDataBase64);
            byte[] encryptedMaskBytes = Convert.FromBase64String(encryptedMaskBase64);

            int numBlocks = encryptedMaskBytes.Length / BlockSize;
            BigInteger[] encryptedMask = new BigInteger[numBlocks];
            for (int i = 0; i < numBlocks; i++)
            {
                
                byte[] block = new byte[BlockSize];  
                Array.Copy(encryptedMaskBytes, i * BlockSize, block, 0, BlockSize);
                encryptedMask[i] = new BigInteger(block);
            }

            byte[] decryptedMask = _rsa.Decrypt(encryptedMask, _privateKey.n, _privateKey.d);

            byte[] originalData = new byte[maskedData.Length];
            for (int i = 0; i < maskedData.Length; i++)
                originalData[i] = (byte)(maskedData[i] ^ decryptedMask[i % decryptedMask.Length]);

            return Encoding.UTF8.GetString(originalData);
        }
    }
}
