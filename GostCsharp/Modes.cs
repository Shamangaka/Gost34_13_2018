using System.Security.Cryptography;

namespace GostCsharp;

/// <summary>An expanded СТ РК 4009-2025 key for one block length.</summary>
public sealed class QalqanCipher : IDisposable
{
    readonly byte[] rkey;
    readonly int klen;

    /// <param name="key">32..128 bytes in steps of 16.</param>
    /// <param name="blockSize">16, 32 or 64 bytes.</param>
    public unsafe QalqanCipher(ReadOnlySpan<byte> key, int blockSize)
    {
        if (!Qalqan.ValidParams(key.Length, blockSize))
            throw new ArgumentException("key must be 32..128 bytes in steps of 16, block 16, 32 or 64 bytes");
        klen = key.Length;
        BlockSize = blockSize;
        rkey = new byte[Qalqan.RNDS(klen) * blockSize];
        fixed (byte* k = key)
        fixed (byte* rk = rkey)
            Qalqan.Kexp(k, klen, blockSize, rk);
    }

    public int BlockSize { get; }

    /// <summary>Number of round keys N = 16 + (KLen - 256) / 128.</summary>
    public int Rounds => Qalqan.RNDS(klen);

    public unsafe void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        CheckBlock(input, output);
        Span<byte> tmp = stackalloc byte[BlockSize];
        input[..BlockSize].CopyTo(tmp); // allows input and output to overlap
        fixed (byte* i = tmp)
        fixed (byte* o = output)
        fixed (byte* rk = rkey)
            Qalqan.encrypt(i, rk, klen, BlockSize, o);
    }

    public unsafe void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        CheckBlock(input, output);
        Span<byte> tmp = stackalloc byte[BlockSize];
        input[..BlockSize].CopyTo(tmp);
        fixed (byte* i = tmp)
        fixed (byte* o = output)
        fixed (byte* rk = rkey)
            Qalqan.decrypt(i, rk, klen, BlockSize, o);
    }

    void CheckBlock(ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < BlockSize || output.Length < BlockSize)
            throw new ArgumentException("input and output must hold a full block");
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(rkey);
}

/// <summary>
/// Modes of operation of СТ РК ISO/IEC 10116-2019: ECB, CBC (m = 1),
/// CFB (r = n, j = k = n), OFB (j = n), CTR (j = n; the counter is the whole
/// block, incremented modulo 2^n with the last byte least significant).
/// CFB/OFB/CTR accept a final partial block. Input and output may be the same
/// buffer. None of the modes authenticates data.
/// </summary>
public static class Modes
{
    public static void EcbEncrypt(QalqanCipher c, ReadOnlySpan<byte> input, Span<byte> output)
    {
        var buf = Prepare(c, input, output, wholeBlocks: true);
        for (int i = 0; i < buf.Length; i += c.BlockSize)
            c.EncryptBlock(buf.Slice(i, c.BlockSize), buf.Slice(i, c.BlockSize));
    }

    public static void EcbDecrypt(QalqanCipher c, ReadOnlySpan<byte> input, Span<byte> output)
    {
        var buf = Prepare(c, input, output, wholeBlocks: true);
        for (int i = 0; i < buf.Length; i += c.BlockSize)
            c.DecryptBlock(buf.Slice(i, c.BlockSize), buf.Slice(i, c.BlockSize));
    }

    public static void CbcEncrypt(QalqanCipher c, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        CheckIv(c, iv);
        var buf = Prepare(c, input, output, wholeBlocks: true);
        Span<byte> prev = stackalloc byte[c.BlockSize];
        iv.CopyTo(prev);
        for (int i = 0; i < buf.Length; i += c.BlockSize)
        {
            var b = buf.Slice(i, c.BlockSize);
            for (int k = 0; k < b.Length; k++)
                b[k] ^= prev[k];
            c.EncryptBlock(b, b);
            b.CopyTo(prev);
        }
    }

    public static void CbcDecrypt(QalqanCipher c, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        CheckIv(c, iv);
        var buf = Prepare(c, input, output, wholeBlocks: true);
        Span<byte> prev = stackalloc byte[c.BlockSize], cur = stackalloc byte[c.BlockSize];
        iv.CopyTo(prev);
        for (int i = 0; i < buf.Length; i += c.BlockSize)
        {
            var b = buf.Slice(i, c.BlockSize);
            b.CopyTo(cur);
            c.DecryptBlock(b, b);
            for (int k = 0; k < b.Length; k++)
                b[k] ^= prev[k];
            cur.CopyTo(prev);
        }
    }

    public static void CfbEncrypt(QalqanCipher c, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output) =>
        Cfb(c, iv, input, output, decrypt: false);

    public static void CfbDecrypt(QalqanCipher c, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output) =>
        Cfb(c, iv, input, output, decrypt: true);

    static void Cfb(QalqanCipher c, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output, bool decrypt)
    {
        CheckIv(c, iv);
        var buf = Prepare(c, input, output, wholeBlocks: false);
        Span<byte> reg = stackalloc byte[c.BlockSize], ks = stackalloc byte[c.BlockSize];
        iv.CopyTo(reg);
        for (int i = 0; i < buf.Length; i += c.BlockSize)
        {
            c.EncryptBlock(reg, ks);
            int n = Math.Min(c.BlockSize, buf.Length - i);
            for (int k = 0; k < n; k++)
            {
                byte inb = buf[i + k];
                buf[i + k] = (byte)(inb ^ ks[k]);
                reg[k] = decrypt ? inb : buf[i + k]; // the ciphertext is fed back
            }
        }
    }

    /// <summary>OFB; encryption and decryption are the same operation.</summary>
    public static void Ofb(QalqanCipher c, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        CheckIv(c, iv);
        var buf = Prepare(c, input, output, wholeBlocks: false);
        Span<byte> reg = stackalloc byte[c.BlockSize];
        iv.CopyTo(reg);
        for (int i = 0; i < buf.Length; i += c.BlockSize)
        {
            c.EncryptBlock(reg, reg); // Y_i = e_K(Y_{i-1})
            int n = Math.Min(c.BlockSize, buf.Length - i);
            for (int k = 0; k < n; k++)
                buf[i + k] ^= reg[k];
        }
    }

    /// <summary>CTR; encryption and decryption are the same operation.</summary>
    public static void Ctr(QalqanCipher c, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, Span<byte> output)
    {
        CheckIv(c, iv);
        var buf = Prepare(c, input, output, wholeBlocks: false);
        Span<byte> ctr = stackalloc byte[c.BlockSize], ks = stackalloc byte[c.BlockSize];
        iv.CopyTo(ctr);
        for (int i = 0; i < buf.Length; i += c.BlockSize)
        {
            c.EncryptBlock(ctr, ks);
            for (int k = ctr.Length - 1; k >= 0; k--) // CTR_{i+1} = CTR_i + 1 mod 2^n
                if (++ctr[k] != 0)
                    break;
            int n = Math.Min(c.BlockSize, buf.Length - i);
            for (int k = 0; k < n; k++)
                buf[i + k] ^= ks[k];
        }
    }

    /// <summary>ISO/IEC 9797-1 padding method 2 (0x80, then zeros to a whole block).</summary>
    public static byte[] PadMethod2(ReadOnlySpan<byte> data, int blockSize)
    {
        var output = new byte[(data.Length / blockSize + 1) * blockSize];
        data.CopyTo(output);
        output[data.Length] = 0x80;
        return output;
    }

    /// <summary>Removes method-2 padding; null if it is invalid.</summary>
    public static byte[]? UnpadMethod2(ReadOnlySpan<byte> data, int blockSize)
    {
        if (data.Length == 0 || data.Length % blockSize != 0)
            return null;
        int stop = data.Length - blockSize, i = data.Length;
        while (i > stop && data[i - 1] == 0)
            i--;
        if (i == stop || data[i - 1] != 0x80)
            return null;
        return data[..(i - 1)].ToArray();
    }

    static void CheckIv(QalqanCipher c, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != c.BlockSize)
            throw new ArgumentException("IV length must equal the block size");
    }

    static Span<byte> Prepare(QalqanCipher c, ReadOnlySpan<byte> input, Span<byte> output, bool wholeBlocks)
    {
        if (wholeBlocks && input.Length % c.BlockSize != 0)
            throw new ArgumentException("input is not a whole number of blocks");
        if (output.Length < input.Length)
            throw new ArgumentException("output is shorter than input");
        input.CopyTo(output); // handles input == output and overlaps
        return output[..input.Length];
    }
}
