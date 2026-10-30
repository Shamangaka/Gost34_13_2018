#include "Modes.h"
#include <cstring>
#include <stdexcept>

QalqanCipher::QalqanCipher(const uint8_t* key, size_t keyLen, size_t blockLen)
    : klen_((int)keyLen), blen_((int)blockLen)
{
    if (keyLen > MAXKEYLEN || blockLen > MAXBLOCKLEN || !Kexp(key, klen_, blen_, rkey_))
        throw std::invalid_argument("qalqan: key must be 32..128 bytes (step 16), block 16, 32 or 64 bytes");
}

QalqanCipher::~QalqanCipher()
{
    volatile uint8_t* p = rkey_;
    for (size_t i = 0; i < sizeof rkey_; i++)
        p[i] = 0;
}

void QalqanCipher::EncryptBlock(const uint8_t* in, uint8_t* out) const
{
    encrypt(in, rkey_, klen_, blen_, out);
}

void QalqanCipher::DecryptBlock(const uint8_t* in, uint8_t* out) const
{
    decrypt(in, rkey_, klen_, blen_, out);
}

static void requireBlocks(const QalqanCipher& c, size_t len)
{
    if (len % c.BlockSize() != 0)
        throw std::invalid_argument("qalqan: input is not a whole number of blocks");
}

void EcbEncrypt(const QalqanCipher& c, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    for (size_t i = 0; i < len; i += c.BlockSize())
        c.EncryptBlock(in + i, out + i);
}

void EcbDecrypt(const QalqanCipher& c, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    for (size_t i = 0; i < len; i += c.BlockSize())
        c.DecryptBlock(in + i, out + i);
}

void CbcEncrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    const size_t bs = c.BlockSize();
    uint8_t x[MAXBLOCKLEN], prev[MAXBLOCKLEN];
    memcpy(prev, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        for (size_t k = 0; k < bs; k++)
            x[k] = in[i + k] ^ prev[k];
        c.EncryptBlock(x, out + i);
        memcpy(prev, out + i, bs);
    }
}

void CbcDecrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    const size_t bs = c.BlockSize();
    uint8_t prev[MAXBLOCKLEN], cur[MAXBLOCKLEN], x[MAXBLOCKLEN];
    memcpy(prev, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        memcpy(cur, in + i, bs); // in may be out
        c.DecryptBlock(cur, x);
        for (size_t k = 0; k < bs; k++)
            out[i + k] = x[k] ^ prev[k];
        memcpy(prev, cur, bs);
    }
}

static void cfb(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len, bool dec)
{
    const size_t bs = c.BlockSize();
    uint8_t reg[MAXBLOCKLEN], ks[MAXBLOCKLEN];
    memcpy(reg, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        const size_t n = len - i < bs ? len - i : bs;
        c.EncryptBlock(reg, ks);
        for (size_t k = 0; k < n; k++)
        {
            const uint8_t inb = in[i + k];
            out[i + k] = inb ^ ks[k];
            reg[k] = dec ? inb : out[i + k]; // the ciphertext is fed back
        }
    }
}

void CfbEncrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    cfb(c, iv, in, out, len, false);
}

void CfbDecrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    cfb(c, iv, in, out, len, true);
}

void OfbCrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    const size_t bs = c.BlockSize();
    uint8_t reg[MAXBLOCKLEN], next[MAXBLOCKLEN];
    memcpy(reg, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        c.EncryptBlock(reg, next); // Y_i = e_K(Y_{i-1})
        memcpy(reg, next, bs);
        const size_t n = len - i < bs ? len - i : bs;
        for (size_t k = 0; k < n; k++)
            out[i + k] = in[i + k] ^ reg[k];
    }
}

void CtrCrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    const size_t bs = c.BlockSize();
    uint8_t ctr[MAXBLOCKLEN], ks[MAXBLOCKLEN];
    memcpy(ctr, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        c.EncryptBlock(ctr, ks);
        for (size_t k = bs; k-- > 0;) // CTR_{i+1} = CTR_i + 1 mod 2^n
            if (++ctr[k] != 0)
                break;
        const size_t n = len - i < bs ? len - i : bs;
        for (size_t k = 0; k < n; k++)
            out[i + k] = in[i + k] ^ ks[k];
    }
}

std::vector<uint8_t> PadMethod2(const uint8_t* data, size_t len, size_t blockLen)
{
    std::vector<uint8_t> out(data, data + len);
    out.push_back(0x80);
    while (out.size() % blockLen != 0)
        out.push_back(0);
    return out;
}

bool UnpadMethod2(std::vector<uint8_t>& data, size_t blockLen)
{
    if (data.empty() || data.size() % blockLen != 0)
        return false;
    size_t i = data.size();
    const size_t stop = data.size() - blockLen;
    while (i > stop && data[i - 1] == 0)
        i--;
    if (i == stop || data[i - 1] != 0x80)
        return false;
    data.resize(i - 1);
    return true;
}
