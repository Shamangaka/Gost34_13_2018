#include "QalqanInternal.h"
#include "Modes.h"
#include <cstring>
#include <stdexcept>
#include <cstdint>
#include <span>

QalqanCipher::QalqanCipher(std::span<const uint8_t> key, size_t blockLen)
    : klen_(0), blen_(0), rkey_{}
{
    if (key.size() > MAXKEYLEN || blockLen > MAXBLOCKLEN ||
        !ValidParams(static_cast<int>(key.size()), static_cast<int>(blockLen)))
        throw std::invalid_argument("qalqan: key must be 32..128 bytes (step 16), block 16, 32 or 64 bytes");
    klen_ = static_cast<int>(key.size());
    blen_ = static_cast<int>(blockLen);
    if (!Kexp(key.data(), klen_, blen_, rkey_))
        throw std::invalid_argument("qalqan: key expansion rejected inputs");
}

QalqanCipher::~QalqanCipher()
{
    volatile uint8_t* p = rkey_;
    for (size_t i = 0; i < sizeof rkey_; i++)
        p[i] = 0;
}

static void requireBlockSpans(size_t bs, std::span<const uint8_t> in,
                              std::span<uint8_t> out)
{
    if (in.size() != bs || out.size() != bs)
        throw std::invalid_argument("qalqan: input and output must each be one full block");
    // A partially overlapping pair is unsupported by the low-level round
    // functions. uintptr_t comparison is valid for our supported flat-memory
    // C++ targets; check subtraction (no address addition/wraparound).
    const auto a = reinterpret_cast<std::uintptr_t>(in.data());
    const auto b = reinterpret_cast<std::uintptr_t>(out.data());
    if (a != b && (a < b ? b - a < bs : a - b < bs))
        throw std::invalid_argument("qalqan: partial buffer overlap");
}

void QalqanCipher::EncryptBlock(std::span<const uint8_t> in,
                                std::span<uint8_t> out) const
{
    requireBlockSpans(BlockSize(), in, out);
    if (!encrypt(in.data(), rkey_, klen_, blen_, out.data()))
        throw std::logic_error("qalqan: internal encrypt failure");
}

void QalqanCipher::DecryptBlock(std::span<const uint8_t> in,
                                std::span<uint8_t> out) const
{
    requireBlockSpans(BlockSize(), in, out);
    if (!decrypt(in.data(), rkey_, klen_, blen_, out.data()))
        throw std::logic_error("qalqan: internal decrypt failure");
}

static void requireBlocks(const QalqanCipher& c, size_t len)
{
    if (len % c.BlockSize() != 0)
        throw std::invalid_argument("qalqan: input is not a whole number of blocks");
}

static void EcbEncryptRaw(const QalqanCipher& c, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    for (size_t i = 0; i < len; i += c.BlockSize())
        c.EncryptBlock({in + i, c.BlockSize()}, {out + i, c.BlockSize()});
}

static void EcbDecryptRaw(const QalqanCipher& c, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    for (size_t i = 0; i < len; i += c.BlockSize())
        c.DecryptBlock({in + i, c.BlockSize()}, {out + i, c.BlockSize()});
}

static void CbcEncryptRaw(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    const size_t bs = c.BlockSize();
    uint8_t x[MAXBLOCKLEN], prev[MAXBLOCKLEN];
    memcpy(prev, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        for (size_t k = 0; k < bs; k++)
            x[k] = in[i + k] ^ prev[k];
        c.EncryptBlock({x, bs}, {out + i, bs});
        memcpy(prev, out + i, bs);
    }
}

static void CbcDecryptRaw(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    requireBlocks(c, len);
    const size_t bs = c.BlockSize();
    uint8_t prev[MAXBLOCKLEN], cur[MAXBLOCKLEN], x[MAXBLOCKLEN];
    memcpy(prev, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        memcpy(cur, in + i, bs); // in may be out
        c.DecryptBlock({cur, bs}, {x, bs});
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
        c.EncryptBlock({reg, bs}, {ks, bs});
        for (size_t k = 0; k < n; k++)
        {
            const uint8_t inb = in[i + k];
            out[i + k] = inb ^ ks[k];
            reg[k] = dec ? inb : out[i + k]; // the ciphertext is fed back
        }
    }
}

static void CfbEncryptRaw(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    cfb(c, iv, in, out, len, false);
}

static void CfbDecryptRaw(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    cfb(c, iv, in, out, len, true);
}

static void OfbCryptRaw(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    const size_t bs = c.BlockSize();
    uint8_t reg[MAXBLOCKLEN], next[MAXBLOCKLEN];
    memcpy(reg, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        c.EncryptBlock({reg, bs}, {next, bs}); // Y_i = e_K(Y_{i-1})
        memcpy(reg, next, bs);
        const size_t n = len - i < bs ? len - i : bs;
        for (size_t k = 0; k < n; k++)
            out[i + k] = in[i + k] ^ reg[k];
    }
}

static void CtrCryptRaw(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len)
{
    const size_t bs = c.BlockSize();
    uint8_t ctr[MAXBLOCKLEN], ks[MAXBLOCKLEN];
    memcpy(ctr, iv, bs);
    for (size_t i = 0; i < len; i += bs)
    {
        c.EncryptBlock({ctr, bs}, {ks, bs});
        for (size_t k = bs; k-- > 0;) // CTR_{i+1} = CTR_i + 1 mod 2^n
            if (++ctr[k] != 0)
                break;
        const size_t n = len - i < bs ? len - i : bs;
        for (size_t k = 0; k < n; k++)
            out[i + k] = in[i + k] ^ ks[k];
    }
}

static void requirePaddingBlockSize(size_t blockLen)
{
    if (blockLen != 16 && blockLen != 32 && blockLen != 64)
        throw std::invalid_argument("qalqan: padding block size must be 16, 32 or 64");
}

std::vector<uint8_t> PadMethod2(std::span<const uint8_t> data, size_t blockLen)
{
    requirePaddingBlockSize(blockLen);
    std::vector<uint8_t> out(data.begin(), data.end());
    out.push_back(0x80);
    while (out.size() % blockLen != 0)
        out.push_back(0);
    return out;
}

bool UnpadMethod2(std::vector<uint8_t>& data, size_t blockLen)
{
    requirePaddingBlockSize(blockLen);
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

// Public size-aware API. The raw implementation functions above are internal
// only; they must NEVER be declared in a public installed header.
static void requireModeSpans(const QalqanCipher& c,
                             std::span<const uint8_t> in, std::span<uint8_t> out,
                             bool wholeBlocks)
{
    if (in.size() != out.size())
        throw std::invalid_argument("qalqan: mode input/output length mismatch");
    if (wholeBlocks && in.size() % c.BlockSize() != 0)
        throw std::invalid_argument("qalqan: mode requires full blocks");
    if (!in.empty())
    {
        const auto a = reinterpret_cast<std::uintptr_t>(in.data());
        const auto b = reinterpret_cast<std::uintptr_t>(out.data());
        if (a != b && (a < b ? b - a < in.size() : a - b < in.size()))
            throw std::invalid_argument("qalqan: partial mode buffer overlap");
    }
}
static void requireIV(const QalqanCipher& c, std::span<const uint8_t> iv)
{
    if (iv.size() != c.BlockSize())
        throw std::invalid_argument("qalqan: IV must be exactly one block");
}
void EcbEncrypt(const QalqanCipher& c, std::span<const uint8_t> in,
                std::span<uint8_t> out)
{
    requireModeSpans(c,in,out,true);
    EcbEncryptRaw(c,in.data(),out.data(),in.size());
}
void EcbDecrypt(const QalqanCipher& c, std::span<const uint8_t> in,
                std::span<uint8_t> out)
{
    requireModeSpans(c,in,out,true);
    EcbDecryptRaw(c,in.data(),out.data(),in.size());
}
void CbcEncrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out)
{
    requireIV(c,iv); requireModeSpans(c,in,out,true);
    CbcEncryptRaw(c,iv.data(),in.data(),out.data(),in.size());
}
void CbcDecrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out)
{
    requireIV(c,iv); requireModeSpans(c,in,out,true);
    CbcDecryptRaw(c,iv.data(),in.data(),out.data(),in.size());
}
void CfbEncrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out)
{
    requireIV(c,iv); requireModeSpans(c,in,out,false);
    CfbEncryptRaw(c,iv.data(),in.data(),out.data(),in.size());
}
void CfbDecrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out)
{
    requireIV(c,iv); requireModeSpans(c,in,out,false);
    CfbDecryptRaw(c,iv.data(),in.data(),out.data(),in.size());
}
void OfbCrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
              std::span<const uint8_t> in, std::span<uint8_t> out)
{
    requireIV(c,iv); requireModeSpans(c,in,out,false);
    OfbCryptRaw(c,iv.data(),in.data(),out.data(),in.size());
}
void CtrCrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
              std::span<const uint8_t> in, std::span<uint8_t> out)
{
    requireIV(c,iv); requireModeSpans(c,in,out,false);
    CtrCryptRaw(c,iv.data(),in.data(),out.data(),in.size());
}
