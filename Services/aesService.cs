﻿using System.Text;
using System;
using System.Security.Cryptography;
namespace ATBM_PRO.Services
{
    public class aesService
    {
        // [Các bảng SBox, InvSBox, Rcon và các hàm khác giữ nguyên như code trước]
        private static readonly byte[] SBox = new byte[] {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

        private static readonly byte[] InvSBox = new byte[] {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

        private static readonly byte[] Rcon = new byte[] {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

        private const int Nb = 4;
        private const int Nk = 4;
        private const int Nr = 10;

        private static byte[] KeyExpansion(byte[] key)
        {
            byte[] w = new byte[Nb * (Nr + 1) * 4];
            int i = 0;

            while (i < Nk * 4)
            {
                w[i] = key[i];
                i++;
            }

            for (i = Nk; i < Nb * (Nr + 1); i++)
            {
                byte[] temp = new byte[4];
                for (int j = 0; j < 4; j++)
                    temp[j] = w[(i - 1) * 4 + j];

                if (i % Nk == 0)
                {
                    temp = SubWord(RotWord(temp));
                    temp[0] ^= Rcon[i / Nk];
                }

                for (int j = 0; j < 4; j++)
                    w[i * 4 + j] = (byte)(w[(i - Nk) * 4 + j] ^ temp[j]);
            }

            return w;
        }

        private static byte[] SubWord(byte[] word)
        {
            for (int i = 0; i < 4; i++)
                word[i] = SBox[word[i]];
            return word;
        }

        private static byte[] RotWord(byte[] word)
        {
            byte temp = word[0];
            for (int i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = temp;
            return word;
        }

        private static void SubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
                state[i] = SBox[state[i]];
        }

        private static void InvSubBytes(byte[] state)
        {
            for (int i = 0; i < 16; i++)
                state[i] = InvSBox[state[i]];
        }

        private static void ShiftRows(byte[] state)
        {
            byte[] temp = (byte[])state.Clone();

            state[1] = temp[5]; state[5] = temp[9]; state[9] = temp[13]; state[13] = temp[1];
            state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
            state[3] = temp[15]; state[7] = temp[3]; state[11] = temp[7]; state[15] = temp[11];
        }

        private static void InvShiftRows(byte[] state)
        {
            byte[] temp = (byte[])state.Clone();

            state[5] = temp[1]; state[9] = temp[5]; state[13] = temp[9]; state[1] = temp[13];
            state[10] = temp[2]; state[14] = temp[6]; state[2] = temp[10]; state[6] = temp[14];
            state[15] = temp[3]; state[3] = temp[7]; state[7] = temp[11]; state[11] = temp[15];
        }

        private static void MixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                int idx = i * 4;
                byte a0 = state[idx], a1 = state[idx + 1], a2 = state[idx + 2], a3 = state[idx + 3];
                state[idx] = (byte)(Mul2(a0) ^ Mul3(a1) ^ a2 ^ a3);
                state[idx + 1] = (byte)(a0 ^ Mul2(a1) ^ Mul3(a2) ^ a3);
                state[idx + 2] = (byte)(a0 ^ a1 ^ Mul2(a2) ^ Mul3(a3));
                state[idx + 3] = (byte)(Mul3(a0) ^ a1 ^ a2 ^ Mul2(a3));
            }
        }

        private static void InvMixColumns(byte[] state)
        {
            for (int i = 0; i < 4; i++)
            {
                int idx = i * 4;
                byte a0 = state[idx], a1 = state[idx + 1], a2 = state[idx + 2], a3 = state[idx + 3];
                state[idx] = (byte)(Mul14(a0) ^ Mul11(a1) ^ Mul13(a2) ^ Mul9(a3));
                state[idx + 1] = (byte)(Mul9(a0) ^ Mul14(a1) ^ Mul11(a2) ^ Mul13(a3));
                state[idx + 2] = (byte)(Mul13(a0) ^ Mul9(a1) ^ Mul14(a2) ^ Mul11(a3));
                state[idx + 3] = (byte)(Mul11(a0) ^ Mul13(a1) ^ Mul9(a2) ^ Mul14(a3));
            }
        }

        private static byte Mul2(byte a)
        {
            return (byte)((a << 1) ^ (((a >> 7) & 1) * 0x1b));
        }

        private static byte Mul3(byte a)
        {
            return (byte)(Mul2(a) ^ a);
        }

        private static byte Mul9(byte a)
        {
            return (byte)(Mul2(Mul2(Mul2(a))) ^ a);
        }

        private static byte Mul11(byte a)
        {
            return (byte)(Mul2(Mul2(Mul2(a))) ^ Mul2(a) ^ a);
        }

        private static byte Mul13(byte a)
        {
            return (byte)(Mul2(Mul2(Mul2(a))) ^ Mul2(Mul2(a)) ^ a);
        }

        private static byte Mul14(byte a)
        {
            return (byte)(Mul2(Mul2(Mul2(a))) ^ Mul2(Mul2(a)) ^ Mul2(a));
        }

        private static void AddRoundKey(byte[] state, byte[] key, int round)
        {
            for (int i = 0; i < 16; i++)
                state[i] ^= key[round * 16 + i];
        }

        private static byte[] EncryptBlock(byte[] input, byte[] expandedKey)
        {
            byte[] state = (byte[])input.Clone();

            AddRoundKey(state, expandedKey, 0);

            for (int round = 1; round < Nr; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, expandedKey, round);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, expandedKey, Nr);

            return state;
        }

        private static byte[] DecryptBlock(byte[] input, byte[] expandedKey)
        {
            byte[] state = (byte[])input.Clone();

            AddRoundKey(state, expandedKey, Nr);

            for (int round = Nr - 1; round > 0; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, expandedKey, round);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, expandedKey, 0);

            return state;
        }

        private static byte[] AddPadding(byte[] input)
        {
            int paddingLength = 16 - (input.Length % 16);
            byte[] padded = new byte[input.Length + paddingLength];
            Array.Copy(input, padded, input.Length);
            for (int i = input.Length; i < padded.Length; i++)
                padded[i] = (byte)paddingLength;
            return padded;
        }
        public byte[] GenerateAesKey()
        {
            byte[] key = new byte[16]; // AES-128
            RandomNumberGenerator.Fill(key); // Tạo ngẫu nhiên an toàn
            return key;
        }
        private static byte[] RemovePadding(byte[] input)
        {
            int paddingLength = input[input.Length - 1];
            byte[] unpadded = new byte[input.Length - paddingLength];
            Array.Copy(input, unpadded, unpadded.Length);
            return unpadded;
        }

        public  byte[] EncryptString(string plainText, byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("Key must be 16 bytes long.");

            byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] paddedInput = AddPadding(inputBytes);
            byte[] expandedKey = KeyExpansion(key);
            byte[] encrypted = new byte[paddedInput.Length];

            for (int i = 0; i < paddedInput.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(paddedInput, i, block, 0, 16);
                byte[] encryptedBlock = EncryptBlock(block, expandedKey);
                Array.Copy(encryptedBlock, 0, encrypted, i, 16);
            }

            return encrypted;
        }

        public string DecryptString(byte[] cipherText, byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("Key must be 16 bytes long.");
            if (cipherText.Length % 16 != 0)
                throw new ArgumentException("Cipher text length must be a multiple of 16 bytes.");

            byte[] expandedKey = KeyExpansion(key);
            byte[] decrypted = new byte[cipherText.Length];

            for (int i = 0; i < cipherText.Length; i += 16)
            {
                byte[] block = new byte[16];
                Array.Copy(cipherText, i, block, 0, 16);
                byte[] decryptedBlock = DecryptBlock(block, expandedKey);
                Array.Copy(decryptedBlock, 0, decrypted, i, 16);
            }

            byte[] unpadded = RemovePadding(decrypted);
            return Encoding.UTF8.GetString(unpadded);
        }

        //public static void Main()
        //{
        //    Console.OutputEncoding = Encoding.UTF8;
        //    Console.InputEncoding = Encoding.UTF8;

        //    // Khóa ban đầu dưới dạng chuỗi (16 ký tự để đảm bảo 16 byte sau khi mã hóa UTF-8)
        //    string keyString = "ThisIsASecretKey"; // 16 ký tự
        //    byte[] key = Encoding.UTF8.GetBytes(keyString);

        //    // Kiểm tra độ dài khóa
        //    if (key.Length != 16)
        //    {
        //        throw new Exception("Khóa phải dài đúng 16 ký tự để tạo thành 16 byte!");
        //    }

        //    string plainText1 = "nam";
        //    string plainText2 = "nam";


        //    byte[] encrypted1 = EncryptString(plainText1, key);
        //    byte[] encrypted2 = EncryptString(plainText2, key);

        //    Console.WriteLine("Chuỗi mã hóa (hex):");
        //    foreach (byte b in encrypted1)
        //        Console.Write($"{b:x2} ");
        //    Console.WriteLine();
        //    foreach (byte b in encrypted1)
        //        Console.Write($"{b:x2} ");

        //    string decrypted1 = DecryptString(encrypted1, key);
        //    Console.WriteLine("Chuỗi giải mã: " + decrypted1);

        //    string decrypted2 = DecryptString(encrypted2, key);
        //    Console.WriteLine("Chuỗi giải mã: " + decrypted2);
        //    Console.WriteLine("Nhấn Enter để thoát...");
        //    Console.ReadLine();
        //}
    }
}
