/*
    HChaCha20.NET: A .NET implementation of HChaCha20.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace HChaCha20DotNet;

public static class HChaCha20
{
    public const int OutputSize = 32;
    public const int KeySize = 32;
    public const int NonceSize = 16;
    
    public static void DeriveKey(Span<byte> outputKeyingMaterial, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> nonce)
    {
        if (outputKeyingMaterial.Length != OutputSize) { throw new ArgumentOutOfRangeException(nameof(outputKeyingMaterial), outputKeyingMaterial.Length, $"{nameof(outputKeyingMaterial)} must be {OutputSize} bytes long."); }
        if (inputKeyingMaterial.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(inputKeyingMaterial), inputKeyingMaterial.Length, $"{nameof(inputKeyingMaterial)} must be {KeySize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        
        uint x0 = 0x61707865;
        uint x1 = 0x3320646e;
        uint x2 = 0x79622d32;
        uint x3 = 0x6b206574;
        uint x4 = ReadUInt32LittleEndian(inputKeyingMaterial[..4]);
        uint x5 = ReadUInt32LittleEndian(inputKeyingMaterial[4..8]);
        uint x6 = ReadUInt32LittleEndian(inputKeyingMaterial[8..12]);
        uint x7 = ReadUInt32LittleEndian(inputKeyingMaterial[12..16]);
        uint x8 = ReadUInt32LittleEndian(inputKeyingMaterial[16..20]);
        uint x9 = ReadUInt32LittleEndian(inputKeyingMaterial[20..24]);
        uint x10 = ReadUInt32LittleEndian(inputKeyingMaterial[24..28]);
        uint x11 = ReadUInt32LittleEndian(inputKeyingMaterial[28..32]);
        uint x12 = ReadUInt32LittleEndian(nonce[..4]);
        uint x13 = ReadUInt32LittleEndian(nonce[4..8]);
        uint x14 = ReadUInt32LittleEndian(nonce[8..12]);
        uint x15 = ReadUInt32LittleEndian(nonce[12..16]);
        
        for (int i = 0; i < 10; i++) {
            (x0, x4, x8, x12) = QuarterRound(x0, x4, x8, x12);
            (x1, x5, x9, x13) = QuarterRound(x1, x5, x9, x13);
            (x2, x6, x10, x14) = QuarterRound(x2, x6, x10, x14);
            (x3, x7, x11, x15) = QuarterRound(x3, x7, x11, x15);
            (x0, x5, x10, x15) = QuarterRound(x0, x5, x10, x15);
            (x1, x6, x11, x12) = QuarterRound(x1, x6, x11, x12);
            (x2, x7, x8, x13) = QuarterRound(x2, x7, x8, x13);
            (x3, x4, x9, x14) = QuarterRound(x3, x4, x9, x14);
        }
        
        WriteUInt32LittleEndian(outputKeyingMaterial[..4], x0);
        WriteUInt32LittleEndian(outputKeyingMaterial[4..8], x1);
        WriteUInt32LittleEndian(outputKeyingMaterial[8..12], x2);
        WriteUInt32LittleEndian(outputKeyingMaterial[12..16], x3);
        WriteUInt32LittleEndian(outputKeyingMaterial[16..20], x12);
        WriteUInt32LittleEndian(outputKeyingMaterial[20..24], x13);
        WriteUInt32LittleEndian(outputKeyingMaterial[24..28], x14);
        WriteUInt32LittleEndian(outputKeyingMaterial[28..32], x15);
    }
    
    private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> source)
    {
        return source[0] | (uint) source[1] << 8 | (uint) source[2] << 16 | (uint) source[3] << 24;
    }
    
    private static (uint a, uint b, uint c, uint d) QuarterRound(uint a, uint b, uint c, uint d)
    {
        a += b;
        d ^= a;
        d = RotateLeft(d, 16);
        c += d;
        b ^= c;
        b = RotateLeft(b, 12);
        a += b;
        d ^= a;
        d = RotateLeft(d, 8);
        c += d;
        b ^= c;
        b = RotateLeft(b, 7);
        return (a, b, c, d);
    }
    
    private static uint RotateLeft(uint a, int b)
    {
        return (a << b) ^ (a >> (32 - b));
    }
    
    private static void WriteUInt32LittleEndian(Span<byte> destination, uint value)
    {
        destination[0] = (byte) value;
        destination[1] = (byte) (value >> 8);
        destination[2] = (byte) (value >> 16);
        destination[3] = (byte) (value >> 24);
    }
}