// * ************************************************************
// * * START:                                          corc5.cs *
// * ************************************************************

// * ************************************************************
// *                      INFORMATIONS
// * ************************************************************
// * Conquer Online Rivest Cipher 5 for the library.
// * corc5.cs
// * 
// * --
// *
// * Feel free to use this class in your projects, but don't
// * remove the header to keep the paternity of the class.
// * 
// * ************************************************************
// *                      CREDITS
// * ************************************************************
// * Originally created by CptSky (May 10th, 2011)
// * Copyright (C) 2011 CptSky
// * 
// * ************************************************************

using System;

namespace CO2_CORE_DLL.Security.Cryptography
{
    public unsafe class CORC5
    {
        public const int RC5_32 = 32,
                         RC5_12 = 12,
                         RC5_SUB = RC5_12 * 2 + 2,
                         RC5_16 = 16,
                         RC5_KEY = RC5_16 / 4;

        public const uint RC5_PW32 = 0xb7e15163, RC5_QW32 = 0x9e3779b9;

        public static readonly byte[] RC5_PASSWORDKEY = new byte[]
                                                            {
                                                                0x3c, 0xdc, 0xfe, 0xe8, 0xc4, 0x54, 0xd6, 0x7e,
                                                                0x16, 0xa6, 0xf8, 0x1a, 0xe8, 0xd0, 0x38, 0xbe
                                                            };

        private readonly uint[] _bufKey;
        private readonly uint[] _bufSub;

        public static uint RotateLeft(uint data, int count)
        {
            count %= 32;

            var high = data >> (32 - count);
            return (data << count) | high;
        }

        public static uint RotateRight(uint data, int count)
        {
            count %= 32;

            var low = data << (32 - count);
            return (data >> count) | low;
        }
        public CORC5(byte[] key)
        {
            _bufKey = new uint[RC5_KEY];
            _bufSub = new uint[RC5_SUB];

            fixed (byte* pKey = key)
            {
                fixed (uint* pKey2 = _bufKey)
                {
                    Kernel.memcpy(pKey2, pKey, RC5_16);
                }
            }

            _bufSub[0] = RC5_PW32;
            for (var i = 1; i < RC5_SUB; i++)
            {
                _bufSub[i] = _bufSub[i - 1] + RC5_QW32;
            }

            int ii, j;
            uint x, y;
            ii = j = 0;
            x = y = 0;
            for (var k = 0; k < 3 * Math.Max(RC5_KEY, RC5_SUB); k++)
            {
                _bufSub[ii] = RotateLeft(_bufSub[ii] + x + y, 3);
                x = _bufSub[ii];
                ii = (ii + 1) % RC5_SUB;

                _bufKey[j] = RotateLeft(_bufKey[j] + x + y, (int)(x + y));
                y = _bufKey[j];
                j = (j + 1) % RC5_KEY;
            }
        }

        public void Encrypt(void* buffer, int length)
        {
            if (length % 8 != 0) throw new ArgumentException("Length must be a multiple of 8!", "length");

            var length8 = (length / 8) * 8;
            if (length8 <= 0) return;

            var bufData = (uint*)buffer;
            for (var k = 0; k < length8 / 8; k++)
            {
                uint a = bufData[2 * k];
                uint b = bufData[2 * k + 1];

                uint le = a + _bufSub[0];
                uint re = b + _bufSub[1];
                for (var i = 1; i <= RC5_12; i++)
                {
                    le = RotateLeft(le ^ re, (int)re) + _bufSub[2 * i];
                    re = RotateLeft(re ^ le, (int)le) + _bufSub[2 * i + 1];
                }

                bufData[2 * k] = le;
                bufData[2 * k + 1] = re;
            }
        }

        public void Decrypt(void* buffer, int length)
        {
            if (length % 8 != 0) throw new ArgumentException("Length must be a multiple of 8!", "length");

            var length8 = (length / 8) * 8;
            if (length8 <= 0) return;

            var bufData = (uint*)buffer;
            for (var k = 0; k < length8 / 8; k++)
            {
                uint ld = bufData[2 * k];
                uint rd = bufData[2 * k + 1];
                for (var i = RC5_12; i >= 1; i--)
                {
                    rd = RotateRight(rd - _bufSub[2 * i + 1], (int)ld) ^ ld;
                    ld = RotateRight(ld - _bufSub[2 * i], (int)rd) ^ rd;
                }

                uint b = rd - _bufSub[1];
                uint a = ld - _bufSub[0];

                bufData[2 * k] = a;
                bufData[2 * k + 1] = b;
            }
        }
    }
}

// * ************************************************************
// * * END:                                            corc5.cs *
// * ************************************************************